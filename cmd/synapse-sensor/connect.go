package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// Reverse-connect ("phone home") mode.
//
// The default SYNPOIP posture is that the daemon dials the sensor. A firewall
// sensor is usually the wrong side of NAT for that, and punching an inbound
// hole in the box you are trying to monitor is exactly the wrong instinct — so
// --connect inverts the *transport* direction: the sensor dials out.
//
// The SYNPOIP roles do NOT invert with it. On the established TLS connection
// the daemon (the accepting side) still sends the ClientHello and the sensor
// still answers with a ServerAccept and streams packet frames. That is why this
// needs no wire change, no version bump and no role byte: pcapoverip.ServeConn
// runs the identical handler Serve runs per accepted connection. See
// internal/capture/pcapoverip/PROTOCOL.md §6 and docs/adr/0014.
//
// The TLS roles do invert: dialling out makes the sensor the TLS client, so it
// verifies the daemon's certificate (--ca / --server-name) and may present its
// own for mutual TLS (--cert / --key). Combined with the bearer token the
// daemon presents in its ClientHello, both ends authenticate each other.
//
// The daemon-side collector this dials is `capture.Collector`, enabled by a
// `capture.collector` block in synapsed's config (ADR 0018, docs/api.md).

const connectDialTimeout = 15 * time.Second

// runConnect dials the collector and serves the sensor side of SYNPOIP on the
// resulting connection, reconnecting with capped exponential backoff until ctx
// is cancelled. A sensor is a long-running service on a box nobody logs into,
// so a dropped link must heal itself (PROJECT.md §5.3 "sensors can reconnect").
func runConnect(ctx context.Context, o *sensorOpts, cfg pcapoverip.ServerConfig, stream pcapoverip.StreamFunc) int {
	tlsCfg, err := connectTLSConfig(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 1
	}

	retryMin, retryMax := o.retryMin, o.retryMax
	if retryMin <= 0 {
		retryMin = 2 * time.Second
	}
	if retryMax < retryMin {
		retryMax = retryMin
	}

	logInfof("pcap-over-ip: connecting out to collector %s (link %d, sensor %q, location %q)",
		o.connect, cfg.LinkType, o.sensorID, o.location)

	delay := retryMin
	for ctx.Err() == nil {
		conn, derr := dialCollector(ctx, o.connect, tlsCfg)
		if derr != nil {
			logErrorf("pcap-over-ip: dial %s: %v — retrying in %s", o.connect, derr, delay.Round(time.Millisecond))
			if !sleepCtx(ctx, jitter(delay)) {
				break
			}
			delay = nextDelay(delay, retryMax)
			continue
		}

		logVerbosef("pcap-over-ip: connected to %s; waiting for the collector handshake", conn.RemoteAddr())
		delay = retryMin // a successful dial resets the backoff

		// ServeConn owns the connection and closes it when the session ends.
		pcapoverip.ServeConn(ctx, conn, cfg, stream)

		if ctx.Err() != nil {
			break
		}
		logInfof("pcap-over-ip: session with %s ended — reconnecting in %s",
			o.connect, delay.Round(time.Millisecond))
		if !sleepCtx(ctx, jitter(delay)) {
			break
		}
		delay = nextDelay(delay, retryMax)
	}

	logInfof("pcap-over-ip: stopped")
	return 0
}

// dialCollector opens the TLS connection to the daemon's collector.
func dialCollector(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, connectDialTimeout)
	defer cancel()

	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// connectTLSConfig builds the sensor's *client* TLS configuration: how it
// verifies the collector, and the certificate it offers for mutual TLS.
func connectTLSConfig(o *sensorOpts) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         o.serverName,
		InsecureSkipVerify: o.insecureTLS, //nolint:gosec // gated on --authorized in validateSensorOpts
	}
	if cfg.ServerName == "" {
		if host, err := hostOf(o.connect); err == nil {
			cfg.ServerName = host
		}
	}

	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile) //nolint:gosec // the operator names the CA bundle
		if err != nil {
			return nil, fmt.Errorf("ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca %q holds no PEM certificate", o.caFile)
		}
		cfg.RootCAs = pool
		logVerbosef("pcap-over-ip: verifying the collector against %s", o.caFile)
	}

	if o.certFile != "" {
		pair, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
		logVerbosef("pcap-over-ip: presenting the client certificate %s for mutual TLS", o.certFile)
	}

	if o.insecureTLS {
		logErrorf("pcap-over-ip: WARNING --insecure-tls is set — the collector's certificate is NOT verified")
	}
	return cfg, nil
}

// nextDelay doubles the backoff up to the ceiling.
func nextDelay(d, max time.Duration) time.Duration {
	if d >= max {
		return max
	}
	if d *= 2; d > max {
		return max
	}
	return d
}

// jitter spreads reconnects over [d/2, d) so a fleet of sensors that lost the
// same collector does not stampede it when it comes back.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := int64(d / 2)
	if half <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(half))
	if err != nil {
		return d
	}
	return time.Duration(half + n.Int64())
}

// sleepCtx waits for d, reporting false when ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
