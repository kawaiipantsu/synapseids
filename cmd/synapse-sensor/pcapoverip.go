package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// runPCAPOverIP serves the SYNPOIP protocol over TLS, replaying a capture file
// to connecting clients. It returns a process exit code.
func runPCAPOverIP(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runPCAPOverIPCtx(ctx, args, nil)
}

// runPCAPOverIPCtx is the testable core: it stops when ctx is cancelled and
// invokes ready (if non-nil) with the bound listener address once serving.
func runPCAPOverIPCtx(ctx context.Context, args []string, ready func(net.Addr)) int {
	log.SetFlags(log.LstdFlags | log.LUTC)
	fs := flag.NewFlagSet("synapse-sensor pcap-over-ip", flag.ContinueOnError)
	var (
		listen    = fs.String("listen", ":4789", "TLS listen address (host:port)")
		from      = fs.String("from", "", "classic .pcap file to replay over the wire (required)")
		certFile  = fs.String("cert", "", "server certificate PEM; if empty a self-signed cert is generated")
		keyFile   = fs.String("key", "", "server private key PEM (required with --cert)")
		tokenFile = fs.String("token-file", "", "file holding the bearer token clients must present")
		token     = fs.String("token", "", "bearer token literal (prefer --token-file); empty accepts any client")
		clientCA  = fs.String("client-ca", "", "PEM bundle: require and verify a client certificate (mutual TLS)")
		speedStr  = fs.String("speed", "1", "replay speed: 0.5, 1, 2, 10, or max")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Serve a capture file to synapsed over the framed, authenticated SYNPOIP transport.")
		fmt.Fprintln(os.Stderr, "\nUsage:\n  synapse-sensor pcap-over-ip --listen :4789 --from capture.pcap --token-file tok [flags]\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *from == "" {
		fmt.Fprintln(os.Stderr, "pcap-over-ip: --from <capture.pcap> is required")
		return 2
	}
	if (*certFile == "") != (*keyFile == "") {
		fmt.Fprintln(os.Stderr, "pcap-over-ip: --cert and --key must be given together")
		return 2
	}

	speed, err := parseSpeed(*speedStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 2
	}

	tok := strings.TrimSpace(*token)
	if *tokenFile != "" {
		b, rerr := os.ReadFile(*tokenFile)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "pcap-over-ip: --token-file:", rerr)
			return 1
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		log.Printf("pcap-over-ip: WARNING no token configured — every client that completes TLS is accepted")
	}

	stream, link, err := pcapoverip.PcapFileStream(*from, speed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 1
	}

	tlsCfg, err := serverTLSConfig(*listen, *certFile, *keyFile, *clientCA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 1
	}

	ln, err := tls.Listen("tcp", *listen, tlsCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip: listen:", err)
		return 1
	}
	log.Printf("pcap-over-ip: serving %s (link %d) on %s at speed %s", *from, link, ln.Addr(), *speedStr)
	if ready != nil {
		ready(ln.Addr())
	}

	serr := pcapoverip.Serve(ctx, ln, pcapoverip.ServerConfig{
		Token:    tok,
		LinkType: link,
		Filter:   "", // whole capture; a real sensor would advertise its BPF here
		Logf:     log.Printf,
	}, stream)
	if serr != nil && !errors.Is(serr, context.Canceled) {
		log.Printf("pcap-over-ip: %v", serr)
		return 1
	}
	log.Printf("pcap-over-ip: stopped")
	return 0
}

func serverTLSConfig(listen, certFile, keyFile, clientCA string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	} else {
		host := "127.0.0.1"
		if h, _, err := splitHostPort(listen); err == nil && h != "" {
			host = h
		}
		pair, certPEM, _, err := pcapoverip.SelfSignedCert(host, "127.0.0.1", "::1", "localhost")
		if err != nil {
			return nil, fmt.Errorf("generating self-signed certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
		sum := sha256.Sum256(certPEM)
		log.Printf("pcap-over-ip: using a generated self-signed certificate for %q", host)
		log.Printf("pcap-over-ip: cert SHA-256 %s", hex.EncodeToString(sum[:]))
		log.Printf("pcap-over-ip: point synapsed at it with insecure_tls + authorized, or pin this PEM as ca_file")
	}

	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, fmt.Errorf("client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client-ca %q holds no PEM certificate", clientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("pcap-over-ip: mutual TLS required — clients must present a certificate signed by %s", clientCA)
	}
	return cfg, nil
}

func splitHostPort(hostport string) (string, string, error) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return "", "", errors.New("no port")
	}
	return strings.Trim(hostport[:i], "[]"), hostport[i+1:], nil
}

// parseSpeed maps the CLI speed token to the float PcapFileStream expects.
func parseSpeed(s string) (float64, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "1", "1x":
		return 1, nil
	case "max", "0":
		return 0, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToLower(s), "x"), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid replay speed %q", s)
	}
	return f, nil
}
