package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// NewSocksProxyPool creates a new SOCKS5 proxy pool.
func NewSocksProxyPool(proxies []SocksProxy, circuitBreakerEnabled bool) *SocksProxyPool {
	return &SocksProxyPool{
		proxies:               proxies,
		currentIndex:          0,
		circuitBreaker:        make(map[int]*CircuitBreakerState),
		circuitBreakerEnabled: circuitBreakerEnabled,
	}
}

// GetNextProxy returns the next available proxy using round-robin with circuit breaker.
// Returns the proxy and its index, or error if no proxies are available.
func (p *SocksProxyPool) GetNextProxy() (*SocksProxy, int, error) {
	if len(p.proxies) == 0 {
		return nil, -1, fmt.Errorf("no SOCKS5 proxies configured")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	failureWindow := time.Minute
	errorThreshold := 3

	// Try all proxies starting from the current index
	for i := 0; i < len(p.proxies); i++ {
		idx := int(atomic.AddUint32(&p.currentIndex, 1)-1) % len(p.proxies)

		// Check if this proxy is in circuit breaker (only if circuit breaker is enabled)
		if p.circuitBreakerEnabled {
			if state, exists := p.circuitBreaker[idx]; exists {
				// Clean up old failures
				validFailures := make([]time.Time, 0)
				for _, failTime := range state.failures {
					if now.Sub(failTime) < failureWindow {
						validFailures = append(validFailures, failTime)
					}
				}
				state.failures = validFailures

				// Check if we should reset the circuit breaker
				if state.isBroken {
					if len(state.failures) < errorThreshold {
						// Not enough recent failures, reset circuit breaker
						state.isBroken = false
						logger.Info("[*] Circuit breaker reset for proxy %s (errors dropped below threshold)", p.proxies[idx].Address)
					} else {
						// Still too many recent failures, skip this proxy
						continue
					}
				}
			}
		}

		return &p.proxies[idx], idx, nil
	}

	return nil, -1, fmt.Errorf("all SOCKS5 proxies are currently unavailable (circuit breaker)")
}

// MarkProxyFailed marks a proxy as failed and activates the circuit breaker after 3 errors within 1 minute.
func (p *SocksProxyPool) MarkProxyFailed(proxyIndex int) {
	if proxyIndex < 0 || proxyIndex >= len(p.proxies) {
		return
	}

	// If circuit breaker is disabled, just log the error and return
	if !p.circuitBreakerEnabled {
		logger.Warn("[!] Proxy %s connection error (circuit breaker disabled)", p.proxies[proxyIndex].Address)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	failureWindow := time.Minute
	errorThreshold := 3

	// Get or create circuit breaker state for this proxy
	state, exists := p.circuitBreaker[proxyIndex]
	if !exists {
		state = &CircuitBreakerState{
			failures: make([]time.Time, 0),
			isBroken: false,
		}
		p.circuitBreaker[proxyIndex] = state
	}

	// Add the new failure timestamp
	state.failures = append(state.failures, now)

	// Remove failures older than the failure window (1 minute)
	validFailures := make([]time.Time, 0)
	for _, failTime := range state.failures {
		if now.Sub(failTime) < failureWindow {
			validFailures = append(validFailures, failTime)
		}
	}
	state.failures = validFailures

	// Activate circuit breaker if we have 3 or more errors in the last minute
	if len(state.failures) >= errorThreshold {
		if !state.isBroken {
			state.isBroken = true
			logger.Warn("[!] Proxy %s marked as failed — circuit breaker activated (%d errors in last minute)",
				p.proxies[proxyIndex].Address, len(state.failures))
		}
	} else {
		logger.Warn("[!] Proxy %s connection error (%d/%d errors in last minute)",
			p.proxies[proxyIndex].Address, len(state.failures), errorThreshold)
	}
}

// -----------------------------------------------------------------------
// Minimal SOCKS5 client (RFC 1928 + RFC 1929) — no external dependencies
// -----------------------------------------------------------------------

// dialViaSocks5 connects to a SOCKS5 proxy and requests a TCP stream to dest:port.
func dialViaSocks5(proxy *SocksProxy, destHost string, destPort uint16) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy.Address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	if err := socks5Handshake(conn, proxy.Username, proxy.Password, destHost, destPort); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5Handshake performs the SOCKS5 greeting + authentication + CONNECT request.
func socks5Handshake(conn net.Conn, username, password, host string, port uint16) error {
	// ── Greeting ──────────────────────────────────────────────────────────
	// Determine which authentication methods to offer
	var greeting []byte
	if username != "" || password != "" {
		// Offer both no-auth (0x00) and username/password (0x02)
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		// Offer only no-auth (0x00)
		greeting = []byte{0x05, 0x01, 0x00}
	}

	if _, err := conn.Write(greeting); err != nil {
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

	// Handle authentication based on server's choice
	authMethod := resp[1]
	switch authMethod {
	case 0x00:
		// No authentication required
		break
	case 0x02:
		// Username/password authentication (RFC 1929)
		if err := socks5UsernamePasswordAuth(conn, username, password); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5: unsupported auth method 0x%02x", authMethod)
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

// socks5UsernamePasswordAuth performs username/password authentication (RFC 1929).
func socks5UsernamePasswordAuth(conn net.Conn, username, password string) error {
	// Username and password must be 1-255 bytes
	if len(username) == 0 || len(username) > 255 {
		return fmt.Errorf("socks5: invalid username length")
	}
	if len(password) > 255 {
		return fmt.Errorf("socks5: invalid password length")
	}

	// Build authentication request
	// VER=1, ULEN, UNAME, PLEN, PASSWD
	authReq := make([]byte, 0, 3+len(username)+len(password))
	authReq = append(authReq, 0x01)                // VER (username/password auth version)
	authReq = append(authReq, byte(len(username))) // ULEN
	authReq = append(authReq, []byte(username)...) // UNAME
	authReq = append(authReq, byte(len(password))) // PLEN
	authReq = append(authReq, []byte(password)...) // PASSWD

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("socks5 auth write: %w", err)
	}

	// Read authentication response
	// VER, STATUS
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return fmt.Errorf("socks5 auth read: %w", err)
	}

	if authResp[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed (status=0x%02x)", authResp[1])
	}

	return nil
}
