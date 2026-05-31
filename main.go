package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"go.yaml.in/yaml/v2"
)

// version is set via ldflags at build time
var version = "v1.2.0"

func main() {
	// Server flags
	port := flag.String("port", "", "SSH server listen port")
	proxy := flag.String("proxy", "", "Upstream SOCKS5 proxy address (host:port)")
	user := flag.String("user", "", "SSH username")
	password := flag.String("password", "", "SSH password")
	hostKey := flag.String("host-key", "", "SSH ECDSA host key")
	config := flag.String("config", "", "Config Path (./config.yaml) you can use yaml file instead of config args")
	showVersion := flag.Bool("version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SSH-to-SOCKS5 Tunnel Server

Usage:
  %s -port <port> -proxy <socks5_host:port> -user <username> -password <password>

Example:
  %s -port 2222 -proxy 192.168.10.10:1080 -user myuser -password secret

Client usage (dynamic SOCKS5 via SSH -D):
  ssh <user>@<server> -N -p <port> -D 8080

Flags:
`, os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("go-ssh-proxy version %s\n", version)
		os.Exit(0)
	}

	if *config == "" && (*port == "" || *proxy == "" || *user == "" || *password == "") {
		flag.Usage()
		os.Exit(1)
	}

	srv := &Server{
		ListenPort:    *port,
		Socks5Address: *proxy,
		Username:      *user,
		Password:      *password,
		HostKey:       *hostKey,
	}

	if *config != "" {
		data, err := os.ReadFile(*config)
		if err != nil {
			log.Fatalf("error reading file: %w", err)
		}

		err = yaml.Unmarshal(data, &srv)
		if err != nil {
			log.Fatalf("error decoding config file: %w", err)
		}
	}

	// Validate configuration
	if srv.ListenPort == "" {
		log.Fatal("listen_port is required")
	}

	// Check SOCKS5 proxy configuration
	hasSocksList := len(srv.SocksList) > 0
	hasLegacySocks := srv.Socks5Address != ""

	if !hasSocksList && !hasLegacySocks {
		log.Fatal("at least one SOCKS5 proxy must be configured (either 'socks_list' or legacy 'socks5_address')")
	}

	// Check if we have at least one user configured (either legacy single user or users list)
	hasUsers := len(srv.Users) > 0
	hasLegacyUser := srv.Username != "" && srv.Password != ""

	if !hasUsers && !hasLegacyUser {
		log.Fatal("at least one user must be configured (either 'users' list or legacy 'username'/'password')")
	}

	log.Printf("[*] Starting SSH-to-SOCKS5 tunnel server (version: %s)", version)
	log.Printf("[*] Listening on port      : %s", srv.ListenPort)

	// Log SOCKS5 proxy configuration
	if len(srv.SocksList) > 0 {
		log.Printf("[*] SOCKS5 proxy pool      : %d proxies", len(srv.SocksList))
		for i, proxy := range srv.SocksList {
			authStatus := "no auth"
			if proxy.Username != "" {
				authStatus = fmt.Sprintf("auth: %s", proxy.Username)
			}
			log.Printf("[*]   %d. %s (%s)", i+1, proxy.Address, authStatus)
		}
	} else {
		log.Printf("[*] Upstream SOCKS5 proxy  : %s (legacy mode)", srv.Socks5Address)
	}

	// Log configured users
	if len(srv.Users) > 0 {
		log.Printf("[*] Configured users       : %d", len(srv.Users))
		for i, user := range srv.Users {
			log.Printf("[*]   %d. %s", i+1, user.Username)
		}
	} else {
		log.Printf("[*] Allowed user           : %s", srv.Username)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[!] Server error: %v", err)
	}
}
