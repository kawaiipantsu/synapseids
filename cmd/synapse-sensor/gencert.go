package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// runGenCert writes a self-signed ECDSA P-256 certificate + key pair for the
// daemon's SYNPOIP collector (or a sensor's --listen socket). It exists so an
// operator can get a testing collector on the air without an openssl incantation
// or a real PKI; production deployments provision their own certificates.
//
// The generated certificate is marked as its own CA, so the .crt doubles as the
// ca_file / --ca the peer verifies against.
func runGenCert(args []string) int {
	fs := flag.NewFlagSet("synapse-sensor gen-cert", flag.ContinueOnError)
	var hosts multiString
	fs.Var(&hosts, "host", "DNS name or IP the certificate is valid for (repeatable; default 127.0.0.1, ::1, localhost)")
	certOut := fs.String("cert", "collector.crt", "certificate PEM output path")
	keyOut := fs.String("key", "collector.key", "private key PEM output path")
	force := fs.Bool("force", false, "overwrite existing output files")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Generate a self-signed certificate for the SYNPOIP collector (testing only).")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  synapse-sensor gen-cert --host ids.example --cert collector.crt --key collector.key")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if !*force {
		for _, p := range []string{*certOut, *keyOut} {
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(os.Stderr, "gen-cert: %s already exists (use --force to overwrite)\n", p)
				return 1
			}
		}
	}

	_, certPEM, keyPEM, err := pcapoverip.SelfSignedCert(hosts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-cert:", err)
		return 1
	}
	if err := os.WriteFile(*certOut, certPEM, 0o644); err != nil { //nolint:gosec // a public certificate
		fmt.Fprintln(os.Stderr, "gen-cert:", err)
		return 1
	}
	if err := os.WriteFile(*keyOut, keyPEM, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "gen-cert:", err)
		return 1
	}

	sum := sha256.Sum256(certPEM)
	names := hosts
	if len(names) == 0 {
		names = multiString{"127.0.0.1", "::1", "localhost"}
	}
	fmt.Printf("wrote %s (0644) and %s (0600)\n", *certOut, *keyOut)
	fmt.Printf("valid for: %s\n", strings.Join(names, ", "))
	fmt.Printf("cert SHA-256: %s\n", hex.EncodeToString(sum[:]))
	fmt.Println("point the daemon collector at it with cert_file / key_file;")
	fmt.Println("the sensor verifies it with --ca " + *certOut + " (or --insecure-tls --authorized for a throwaway).")
	return 0
}

// multiString is a repeatable string flag.
type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }

func (m *multiString) Set(v string) error {
	*m = append(*m, v)
	return nil
}
