package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"go.yaml.in/yaml/v2"
)

func main() {
	// Server flags
	port := flag.String("port", "", "SSH server listen port")
	proxy := flag.String("proxy", "", "Upstream SOCKS5 proxy address (host:port)")
	user := flag.String("user", "", "SSH username")
	password := flag.String("password", "", "SSH password")
	hostKey := flag.String("host-key", "", "SSH ECDSA host key")
	config := flag.String("config", "", "Config Path (./config.yaml) you can use yaml file instead of config args")

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
	if srv.ListenPort == "" || srv.Socks5Address == "" {
		log.Fatal("listen_port and socks5_address are required")
	}
	
	// Check if we have at least one user configured (either legacy single user or users list)
	hasUsers := len(srv.Users) > 0
	hasLegacyUser := srv.Username != "" && srv.Password != ""
	
	if !hasUsers && !hasLegacyUser {
		log.Fatal("at least one user must be configured (either 'users' list or legacy 'username'/'password')")
	}

	log.Printf("[*] Starting SSH-to-SOCKS5 tunnel server")
	log.Printf("[*] Listening on port      : %s", srv.ListenPort)
	log.Printf("[*] Upstream SOCKS5 proxy  : %s", srv.Socks5Address)
	
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
