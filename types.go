package main

import (
	"sync"
	"time"
)

var initTime time.Time

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

// SocksProxy represents a SOCKS5 proxy configuration.
type SocksProxy struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Server holds configuration for the SSH server.
type Server struct {
	ListenPort    string       `yaml:"listen_port"`
	Socks5Address string       `yaml:"socks5_address"` // Deprecated: use SocksList instead
	SocksList     []SocksProxy `yaml:"socks_list"`     // Multiple SOCKS5 proxy configurations
	Username      string       `yaml:"username"`       // Deprecated: use Users instead
	Password      string       `yaml:"password"`       // Deprecated: use Users instead
	Users         []User       `yaml:"users"`          // Multiple user configurations
	HostKey       string       `yaml:"host_key"`       // Base64-encoded ECDSA private key (DER format)
	LogLevel      string       `yaml:"log_level"`      // Log level: debug, info, warn, error, silent

	// Bandwidth tracking
	statsLock sync.RWMutex
	stats     map[string]*UserStats

	// SOCKS5 proxy pool
	proxyPool *SocksProxyPool
}

// SocksProxyPool manages a pool of SOCKS5 proxies with round-robin and circuit breaker.
type SocksProxyPool struct {
	proxies        []SocksProxy
	currentIndex   uint32
	circuitBreaker map[int]*CircuitBreakerState
	mu             sync.RWMutex
}

// CircuitBreakerState tracks the state of a single proxy in the circuit breaker.
type CircuitBreakerState struct {
	failedAt time.Time
	isBroken bool
}

// directTCPIPPayload matches the RFC 4254 §7.2 direct-tcpip payload.
type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}
