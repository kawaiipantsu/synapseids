// Package capturewire turns a validated config.CaptureSource into a live
// capture.Source. It is the one place that maps the declarative per-kind config
// onto the capture constructors, shared by the daemon's startup loop
// (cmd/synapsed) and the runtime POST /api/v1/captures handler (internal/api) so
// the two paths build sources identically (issue #32).
//
// It sits above both internal/capture (a leaf that must not import config — see
// docs/architecture.md) and internal/config, importing both; nothing in the
// capture/flow/features data plane imports it back, so the import graph stays a
// DAG.
package capturewire

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/config"
)

// Meta is the descriptive metadata the Manager keeps beside a source for the
// capture-sources view. The filter label mirrors what cmd/synapsed logged:
// an empty per-kind filter shows as "(all)". Origin defaults to "config" (the
// startup loader); the runtime POST handler overrides it to "api".
func Meta(cs config.CaptureSource) capture.SourceMeta {
	label := cs.Filter
	if label == "" {
		label = "(all)"
	}
	return capture.SourceMeta{Kind: cs.Kind, Filter: label, Origin: "config"}
}

// Build constructs the capture.Source for one configured entry and returns a
// short human label for logs. config.ValidateCaptureSource must have passed
// first; the constructors here do the real environment checks (interface
// exists, capability present, binary on PATH, TLS material readable) and a
// failure is returned so the caller can degrade gracefully rather than crash
// (PROJECT.md §21). logf receives one-line lifecycle/warning messages from the
// pcap-over-ip client; pass log.Printf.
func Build(cs config.CaptureSource, logf func(string, ...any)) (capture.Source, string, error) {
	switch cs.Kind {
	case "nic":
		src, err := capture.NewAFPacket(capture.AFPacketConfig{
			Interface:   cs.Interface,
			Promiscuous: cs.Promiscuous,
			Snaplen:     cs.Snaplen,
			Filter:      cs.Filter,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Interface, nil
	case "tcpdump":
		src, err := capture.NewTcpdumpStream(capture.TcpdumpConfig{
			Binary:    cs.Binary,
			Interface: cs.Interface,
			Filter:    cs.Filter,
			Snaplen:   cs.Snaplen,
			ExtraArgs: cs.ExtraArgs,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Interface, nil
	case "ssh":
		src, err := capture.NewSSHTcpdump(capture.SSHConfig{
			SSHBinary:      cs.Binary,
			Destination:    cs.Destination,
			Port:           cs.Port,
			IdentityFile:   cs.IdentityFile,
			RemoteBinary:   cs.RemoteBinary,
			Interface:      cs.Interface,
			Filter:         cs.Filter,
			Snaplen:        cs.Snaplen,
			ExtraSSHArgs:   cs.ExtraSSHArgs,
			KnownHostsMode: cs.KnownHosts,
			Authorized:     cs.Authorized,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Destination + " " + cs.Interface, nil
	case "pcap-over-ip":
		tok, err := ResolvePOIPToken(cs)
		if err != nil {
			return nil, "", err
		}
		src, err := capture.NewPCAPOverIP(capture.POIPConfig{
			Addr:               cs.Addr,
			Token:              tok,
			ServerName:         cs.ServerName,
			CAFile:             cs.CAFile,
			ClientCertFile:     cs.ClientCertFile,
			ClientKeyFile:      cs.ClientKeyFile,
			InsecureSkipVerify: cs.InsecureTLS,
			Authorized:         cs.Authorized,
			SensorID:           cs.Name,
			Logf:               logf,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Addr, nil
	default:
		return nil, "", fmt.Errorf("unknown kind %q", cs.Kind)
	}
}

// ResolvePOIPToken loads the bearer token for a pcap-over-ip source from its
// token_file, else from SYNAPSE_POIP_TOKEN. An empty result is only valid when
// the source set authorized:true (config validation has already enforced that).
func ResolvePOIPToken(cs config.CaptureSource) (string, error) {
	if cs.TokenFile != "" {
		b, err := os.ReadFile(cs.TokenFile)
		if err != nil {
			return "", fmt.Errorf("token_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv("SYNAPSE_POIP_TOKEN")), nil
}

// ResolveCollectorToken loads the collector's bearer token from its token_file,
// else from SYNAPSE_COLLECTOR_TOKEN. The daemon presents this token in the
// ClientHello it sends to every accepted sensor; the sensor verifies it. An
// empty result is allowed (the collector already required authorized:true) but
// means any sensor that completes TLS is accepted, so mTLS should be configured.
func ResolveCollectorToken(c config.Collector) (string, error) {
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return "", fmt.Errorf("token_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv("SYNAPSE_COLLECTOR_TOKEN")), nil
}

// BuildCollector turns a validated config.Collector into a live
// capture.Collector: it loads the daemon's server certificate, an optional
// client-CA pool for mutual TLS, and the bearer token. config.ValidateCollector
// must have passed first; a missing or malformed PEM is returned so the daemon
// can log it and keep serving the API without the collector (PROJECT.md §21).
func BuildCollector(c config.Collector, records chan<- pcapoverip.SensorRecord, logf func(string, ...any)) (*capture.Collector, error) {
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("collector certificate: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}
	if c.ClientCAFile != "" {
		pem, rerr := os.ReadFile(c.ClientCAFile)
		if rerr != nil {
			return nil, fmt.Errorf("collector client_ca_file: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("collector client_ca_file %q holds no PEM certificate", c.ClientCAFile)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	tok, err := ResolveCollectorToken(c)
	if err != nil {
		return nil, err
	}

	return capture.NewCollector(capture.CollectorConfig{
		Listen:            c.Listen,
		TLSConfig:         tlsCfg,
		Token:             tok,
		RequireClientCert: c.ClientCAFile != "",
		MaxSensors:        c.MaxSensors,
		Records:           records,
		Logf:              logf,
	})
}
