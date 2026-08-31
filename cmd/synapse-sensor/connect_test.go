package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// TestConnectModeStreamsToACollector proves the reverse-connect posture end to
// end: the sensor dials out, and on that connection the SYNPOIP roles are
// unchanged — the *accepting* side sends the ClientHello and the sensor answers
// with a ServerAccept and streams packet frames. Nothing about the wire format
// differs from --listen mode, which is the whole point of the design.
//
// The collector here is a stand-in. synapsed does not yet ship one; see
// errConnectNotWired and docs/adr/0014.
func TestConnectModeStreamsToACollector(t *testing.T) {
	pair, _, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCh := make(chan int, 1)
	go func() {
		exitCh <- runPCAPOverIPCtx(ctx, []string{
			"--connect", ln.Addr().String(),
			"--from", filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"),
			"--token", "demo-token",
			"--sensor-id", "opnsense-wan",
			"--location", "edge",
			"--insecure-tls",
			"--authorized",
			"--speed", "max",
		}, nil)
	}()

	conn, err := acceptWithin(ln, 5*time.Second)
	if err != nil {
		t.Fatalf("collector never saw the sensor dial in: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The collector drives the handshake exactly as synapsed does today.
	sess, err := pcapoverip.ClientHandshake(conn, pcapoverip.ClientHello{
		Version: pcapoverip.Version1,
		Token:   "demo-token",
	}, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if sess.NegotiatedVersion() != pcapoverip.Version1 {
		t.Errorf("negotiated version %d, want %d", sess.NegotiatedVersion(), pcapoverip.Version1)
	}
	// The sensor identifies itself through the session id, since in this
	// direction it is the one answering rather than sending metadata.
	if sid := sess.SessionID(); len(sid) < len("opnsense-wan-") || sid[:len("opnsense-wan-")] != "opnsense-wan-" {
		t.Errorf("session id %q does not carry the sensor id prefix", sid)
	}

	packets := 0
	for {
		ft, _, rerr := sess.ReadFrame(5 * time.Second)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("read: %v", rerr)
		}
		if ft == pcapoverip.FramePacket {
			packets++
		}
		if ft == pcapoverip.FrameGoodbye {
			break
		}
	}
	_ = sess.Close()
	cancel()

	if packets == 0 {
		t.Fatal("received no packets over the reverse connection")
	}
	select {
	case code := <-exitCh:
		if code != 0 {
			t.Fatalf("subcommand exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subcommand did not exit after cancel")
	}
	t.Logf("drained %d packets over a sensor-initiated TLS connection", packets)
}

// TestConnectModeRetriesAFailedDial checks the reconnect loop: the sensor must
// survive a collector that is not up yet rather than exiting.
func TestConnectModeRetriesAFailedDial(t *testing.T) {
	// Bind and immediately release a port so the dial reliably fails.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	dead := probe.Addr().String()
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- runPCAPOverIPCtx(ctx, []string{
			"--connect", dead,
			"--from", filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"),
			"--token", "demo-token",
			"--insecure-tls",
			"--authorized",
			"--retry-min", "20ms",
			"--retry-max", "40ms",
		}, nil)
	}()

	// Give the loop time to fail and retry several times, then stop it.
	time.Sleep(250 * time.Millisecond)
	cancel()

	select {
	case code := <-exitCh:
		if code != 0 {
			t.Fatalf("a sensor whose collector is down should keep retrying and exit 0 on signal, got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reconnect loop did not stop on context cancellation")
	}
}

func TestBackoffAndJitter(t *testing.T) {
	if got := nextDelay(2*time.Second, 60*time.Second); got != 4*time.Second {
		t.Errorf("nextDelay doubled to %v, want 4s", got)
	}
	if got := nextDelay(40*time.Second, 60*time.Second); got != 60*time.Second {
		t.Errorf("nextDelay clamped to %v, want 60s", got)
	}
	if got := nextDelay(90*time.Second, 60*time.Second); got != 60*time.Second {
		t.Errorf("nextDelay above the ceiling gave %v, want 60s", got)
	}
	for range 50 {
		d := jitter(10 * time.Second)
		if d < 5*time.Second || d >= 10*time.Second {
			t.Fatalf("jitter(10s) = %v, want [5s, 10s)", d)
		}
	}
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v, want 0", got)
	}
}

func acceptWithin(ln net.Listener, d time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(d):
		return nil, errors.New("timed out waiting for a connection")
	}
}
