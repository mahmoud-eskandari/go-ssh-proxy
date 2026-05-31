package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ListenAndServe starts the SSH server and accepts connections.
func (s *Server) ListenAndServe() error {
	// Initialize stats map
	s.stats = make(map[string]*UserStats)

	// Initialize SOCKS5 proxy pool
	if len(s.SocksList) > 0 {
		s.proxyPool = NewSocksProxyPool(s.SocksList)
		logger.Info("[*] Initialized SOCKS5 proxy pool with %d proxies", len(s.SocksList))
	} else if s.Socks5Address != "" {
		// Backward compatibility: convert single proxy to list
		s.SocksList = []SocksProxy{{Address: s.Socks5Address}}
		s.proxyPool = NewSocksProxyPool(s.SocksList)
		logger.Info("[*] Using legacy single SOCKS5 proxy: %s", s.Socks5Address)
	}

	config, err := s.buildSSHConfig()
	if err != nil {
		return fmt.Errorf("build ssh config: %w", err)
	}

	listener, err := net.Listen("tcp", ":"+s.ListenPort)
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", s.ListenPort, err)
	}
	defer listener.Close()

	// Start statistics printer goroutine
	go s.printStatsPeriodically()

	logger.Info("[*] Server ready — waiting for SSH clients...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("[!] Accept error: %v", err)
			continue
		}
		go s.handleConn(conn, config)
	}
}

// buildSSHConfig creates the SSH server configuration with a host key from config or generates one.
func (s *Server) buildSSHConfig() (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			username := c.User()
			password := string(pass)

			// Check against users list first
			if len(s.Users) > 0 {
				for _, user := range s.Users {
					if user.Username == username && user.Password == password {
						logger.Info("[+] Auth OK  — user=%q from %s", username, c.RemoteAddr())

						// Initialize stats for this user if not exists
						s.statsLock.Lock()
						if _, exists := s.stats[username]; !exists {
							s.stats[username] = &UserStats{}
						}
						s.statsLock.Unlock()

						// Store username in permissions for later use
						return &ssh.Permissions{
							Extensions: map[string]string{
								"username": username,
							},
						}, nil
					}
				}
			}

			// Fallback to single user config (for backward compatibility)
			if s.Username != "" && username == s.Username && password == s.Password {
				logger.Info("[+] Auth OK  — user=%q from %s", username, c.RemoteAddr())

				s.statsLock.Lock()
				if _, exists := s.stats[username]; !exists {
					s.stats[username] = &UserStats{}
				}
				s.statsLock.Unlock()

				return &ssh.Permissions{
					Extensions: map[string]string{
						"username": username,
					},
				}, nil
			}

			logger.Warn("[-] Auth FAIL — user=%q from %s", username, c.RemoteAddr())
			return nil, fmt.Errorf("invalid credentials")
		},
		// Reject public-key auth so only password is accepted
		PublicKeyCallback: nil,
	}

	var privateKey *ecdsa.PrivateKey
	var err error

	if s.HostKey != "" {
		// Load host key from config
		privateKey, err = loadHostKeyFromBase64(s.HostKey)
		if err != nil {
			return nil, fmt.Errorf("load host key from config: %w", err)
		}
		logger.Info("[*] Loaded host key from config")
	} else {
		// Generate a new ECDSA host key
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}

		// Encode to base64 and print to stdout
		encoded, err := encodeHostKeyToBase64(privateKey)
		if err != nil {
			return nil, fmt.Errorf("encode host key: %w", err)
		}
		fmt.Printf("new ECDSA host key is:\n%s\n\n", encoded)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	config.AddHostKey(signer)

	return config, nil
}

// loadHostKeyFromBase64 decodes a base64-encoded ECDSA private key.
func loadHostKeyFromBase64(encoded string) (*ecdsa.PrivateKey, error) {
	derBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	privateKey, err := x509.ParseECPrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA key: %w", err)
	}

	return privateKey, nil
}

// encodeHostKeyToBase64 encodes an ECDSA private key to base64.
func encodeHostKeyToBase64(privateKey *ecdsa.PrivateKey) (string, error) {
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal ECDSA key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derBytes), nil
}

// handleConn performs the SSH handshake and routes channel requests.
func (s *Server) handleConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	defer tcpConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		logger.Debug("[!] SSH handshake failed from %s: %v", tcpConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()
	logger.Info("[+] New SSH session — user=%q addr=%s", sshConn.User(), sshConn.RemoteAddr())

	// Discard global requests (keepalive, etc.)
	go ssh.DiscardRequests(reqs)

	// Get username from SSH connection
	username := sshConn.User()

	// Handle each channel opened by the client
	for newChan := range chans {
		switch newChan.ChannelType() {

		case "direct-tcpip":
			// Standard SSH -L / -D dynamic forward channel
			go s.handleDirectTCPIP(newChan, username)

		case "session":
			// Some SSH clients open a session channel during -D; accept and do nothing
			ch, reqs2, err := newChan.Accept()
			if err != nil {
				logger.Error("[!] Accept session channel: %v", err)
				continue
			}
			go func() {
				defer ch.Close()
				// Handle session requests — accept pty-req and shell to prevent client errors
				for req := range reqs2 {
					switch req.Type {
					case "pty-req", "shell":
						// Accept PTY and shell requests silently (prevents client errors)
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					default:
						// Reject other requests (exec, subsystem, etc.)
						if req.WantReply {
							_ = req.Reply(false, nil)
						}
					}
				}
			}()

		default:
			logger.Debug("[~] Rejecting unknown channel type: %s", newChan.ChannelType())
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}

	logger.Info("[*] SSH session closed — addr=%s", sshConn.RemoteAddr())
}

// isInternalAddress checks if the given address is internal/private/localhost.
func isInternalAddress(addr string) bool {
	// Check for localhost names
	if addr == "localhost" || addr == "127.0.0.1" || addr == "::1" {
		return true
	}

	// Parse IP address
	ip := net.ParseIP(addr)
	if ip == nil {
		// If it's not a valid IP, try resolving it as hostname
		// Check for localhost variants
		if addr == "ip6-localhost" || addr == "ip6-loopback" {
			return true
		}
		// For hostnames, we'll be conservative and allow them
		// (we can't easily determine if a hostname resolves to internal IP)
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for private IP ranges
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local addresses
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// handleDirectTCPIP handles a direct-tcpip channel (used by SSH -D SOCKS proxy).
// Instead of connecting to the original destination, we route through the upstream SOCKS5 proxy.
func (s *Server) handleDirectTCPIP(newChan ssh.NewChannel, username string) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		logger.Error("[!] Parse direct-tcpip payload: %v", err)
		_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}

	target := fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort)

	// Prevent connections to internal/private IPs and localhost
	// Accept the channel but don't relay - just keep it open with empty ACK
	if isInternalAddress(payload.DestAddr) {
		logger.Warn("[!] Blocked internal address request: user=%s target=%s", username, target)

		// Accept the channel to send OK response
		ch, reqs, err := newChan.Accept()
		if err != nil {
			logger.Error("[!] Accept channel for internal address block: %v", err)
			return
		}
		defer ch.Close()

		// Discard any requests and data - don't relay anything
		go ssh.DiscardRequests(reqs)

		// Keep channel open but discard all data from client
		io.Copy(io.Discard, ch)
		return
	}

	// Get next available proxy from pool
	proxy, proxyIndex, err := s.proxyPool.GetNextProxy()
	if err != nil {
		logger.Error("[!] No available SOCKS5 proxy: %v", err)
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	logger.Debug("[>] Forwarding  %s → SOCKS5(%s) → %s", newChan.ChannelType(), proxy.Address, target)

	// Connect to the upstream SOCKS5 proxy and ask it to reach the real target
	upstreamConn, err := dialViaSocks5(proxy, payload.DestAddr, uint16(payload.DestPort))
	if err != nil {
		logger.Error("[!] SOCKS5 connect to %s via %s failed: %v", target, proxy.Address, err)

		// Mark this proxy as failed (activate circuit breaker)
		s.proxyPool.MarkProxyFailed(proxyIndex)

		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer upstreamConn.Close()

	// Accept the SSH channel now that we have the upstream connection
	ch, reqs, err := newChan.Accept()
	if err != nil {
		logger.Error("[!] Accept direct-tcpip channel: %v", err)
		return
	}
	defer ch.Close()

	go ssh.DiscardRequests(reqs)

	// Get user stats for tracking
	s.statsLock.RLock()
	userStats := s.stats[username]
	s.statsLock.RUnlock()

	// Bidirectional copy between SSH channel and SOCKS5 upstream with bandwidth tracking
	done := make(chan struct{}, 2)

	// RX: client → upstream (data received from client)
	go func() {
		n, _ := io.Copy(upstreamConn, ch)
		atomic.AddUint64(&userStats.RxBytes, uint64(n))
		done <- struct{}{}
	}()

	// TX: upstream → client (data sent to client)
	go func() {
		n, _ := io.Copy(ch, upstreamConn)
		atomic.AddUint64(&userStats.TxBytes, uint64(n))
		done <- struct{}{}
	}()

	<-done
}

// printStatsPeriodically prints bandwidth statistics for each user every 5 minutes.
func (s *Server) printStatsPeriodically() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.statsLock.RLock()

		if len(s.stats) == 0 {
			s.statsLock.RUnlock()
			continue
		}

		logger.Info("========== Bandwidth Statistics ==========")
		for username, stats := range s.stats {
			tx := atomic.LoadUint64(&stats.TxBytes)
			rx := atomic.LoadUint64(&stats.RxBytes)

			logger.Info("User: %s | TX: %s | RX: %s",
				username,
				formatBytes(tx),
				formatBytes(rx))
		}
		logger.Info("==========================================")

		s.statsLock.RUnlock()
	}
}

// formatBytes converts bytes to human-readable format.
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
