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
	}

	if *config != "" {
		data, err := os.ReadFile(*config)
		if err != nil {
			log.Fatalf("error reading file: %w", err)
		}

		err = yaml.Unmarshal(data, srv)
		if err != nil {
			log.Fatalf("error decoding config file: %w", err)
		}
	}
	if srv.ListenPort == "" || srv.Socks5Address == "" || srv.Username == "" || srv.Password == "" {
		log.Fatal("some config parameters is empty")
	}

	log.Printf("[*] Starting SSH-to-SOCKS5 tunnel server")
	log.Printf("[*] Listening on port      : %s", *port)
	log.Printf("[*] Upstream SOCKS5 proxy  : %s", *proxy)
	log.Printf("[*] Allowed user           : %s", *user)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[!] Server error: %v", err)
	}
}
