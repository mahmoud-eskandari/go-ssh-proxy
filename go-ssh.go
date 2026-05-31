package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// User represents a single user configuration.
type User struct {
	Username string `yaml:"user"`
	Password string `yaml:"password"`
}

// UserStats tracks bandwidth statistics for a user.
type UserStats struct {
	TxBytes uint64 // transmitted bytes (sent to client)
	RxBytes uint64 // received bytes (received from client)
}

// Server holds configuration for the SSH server.
type Server struct {
	ListenPort    string `yaml:"listen_port"`
	Socks5Address string `yaml:"socks5_address"`
	Username      string `yaml:"username"` // Deprecated: use Users instead
	Password      string `yaml:"password"` // Deprecated: use Users instead
	Users         []User `yaml:"users"`    // Multiple user configurations
	HostKey       string `yaml:"host_key"` // Base64-encoded ECDSA private key (DER format)

	// Bandwidth tracking
	statsLock sync.RWMutex
	stats     map[string]*UserStats
}

// ListenAndServe starts the SSH server and accepts connections.
func (s *Server) ListenAndServe() error {
	// Initialize stats map
	s.stats = make(map[string]*UserStats)

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

	log.Printf("[*] Server ready — waiting for SSH clients...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[!] Accept error: %v", err)
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
						log.Printf("[+] Auth OK  — user=%q from %s", username, c.RemoteAddr())

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

			// Fallback to legacy single user config (for backward compatibility)
			if s.Username != "" && username == s.Username && password == s.Password {
				log.Printf("[+] Auth OK  — user=%q from %s", username, c.RemoteAddr())

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

			log.Printf("[-] Auth FAIL — user=%q from %s", username, c.RemoteAddr())
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
		log.Printf("[*] Loaded host key from config")
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
		fmt.Printf("%s\n", encoded)
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
		log.Printf("[!] SSH handshake failed from %s: %v", tcpConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()
	log.Printf("[+] New SSH session — user=%q addr=%s", sshConn.User(), sshConn.RemoteAddr())

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
				log.Printf("[!] Accept session channel: %v", err)
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
			log.Printf("[~] Rejecting unknown channel type: %s", newChan.ChannelType())
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}

	log.Printf("[*] SSH session closed — addr=%s", sshConn.RemoteAddr())
}

// directTCPIPPayload matches the RFC 4254 §7.2 direct-tcpip payload.
type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// handleDirectTCPIP handles a direct-tcpip channel (used by SSH -D SOCKS proxy).
// Instead of connecting to the original destination, we route through the upstream SOCKS5 proxy.
func (s *Server) handleDirectTCPIP(newChan ssh.NewChannel, username string) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		log.Printf("[!] Parse direct-tcpip payload: %v", err)
		_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}

	target := fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort)
	//log.Printf("[>] Forwarding  %s → SOCKS5(%s) → %s", newChan.ChannelType(), s.Socks5Address, target)

	// Connect to the upstream SOCKS5 proxy and ask it to reach the real target
	upstreamConn, err := dialViaSocks5(s.Socks5Address, payload.DestAddr, uint16(payload.DestPort))
	if err != nil {
		log.Printf("[!] SOCKS5 connect to %s failed: %v", target, err)
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer upstreamConn.Close()

	// Accept the SSH channel now that we have the upstream connection
	ch, reqs, err := newChan.Accept()
	if err != nil {
		log.Printf("[!] Accept direct-tcpip channel: %v", err)
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

// printStatsPeriodically prints bandwidth statistics for each user every minute.
func (s *Server) printStatsPeriodically() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.statsLock.RLock()

		if len(s.stats) == 0 {
			s.statsLock.RUnlock()
			continue
		}

		log.Printf("========== Bandwidth Statistics ==========")
		for username, stats := range s.stats {
			tx := atomic.LoadUint64(&stats.TxBytes)
			rx := atomic.LoadUint64(&stats.RxBytes)

			log.Printf("User: %s | TX: %s | RX: %s",
				username,
				formatBytes(tx),
				formatBytes(rx))
		}
		log.Printf("==========================================")

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

// -----------------------------------------------------------------------
// Minimal SOCKS5 client (RFC 1928) — no external dependencies
// -----------------------------------------------------------------------

// dialViaSocks5 connects to a SOCKS5 proxy and requests a TCP stream to dest:port.
func dialViaSocks5(proxyAddr, destHost string, destPort uint16) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	if err := socks5Handshake(conn, destHost, destPort); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5Handshake performs the SOCKS5 greeting + CONNECT request (no auth).
func socks5Handshake(conn net.Conn, host string, port uint16) error {
	// ── Greeting ──────────────────────────────────────────────────────────
	// VER=5, NMETHODS=1, METHOD=0x00 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting write: %w", err)
	}

	// Server choice: VER, METHOD
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 greeting read: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: server is not SOCKS5 (got version %d)", resp[0])
	}
	if resp[1] == 0xFF {
		return fmt.Errorf("socks5: no acceptable auth method")
	}

	// ── CONNECT request ───────────────────────────────────────────────────
	// VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3), ADDR, PORT
	hostBytes := []byte(host)
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00)     // VER, CMD, RSV
	req = append(req, 0x03)                 // ATYP: domain name
	req = append(req, byte(len(hostBytes))) // domain length
	req = append(req, hostBytes...)         // domain
	req = append(req, 0, 0)                 // port placeholder
	binary.BigEndian.PutUint16(req[len(req)-2:], port)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect write: %w", err)
	}

	// ── Response ──────────────────────────────────────────────────────────
	// VER, REP, RSV, ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("socks5 response read: %w", err)
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT failed, REP=0x%02x", header[1])
	}

	// Skip the BND.ADDR / BND.PORT fields
	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, buf)
	case 0x04: // IPv6
		buf := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, buf)
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		buf := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, buf)
	default:
		return fmt.Errorf("socks5: unknown ATYP in response: 0x%02x", header[3])
	}

	return nil
}
