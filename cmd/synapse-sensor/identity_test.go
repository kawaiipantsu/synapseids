package main

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// TestConnectHelloIdentity: the identity the sensor announces in --connect mode
// carries the id, location, agent version and os/arch the daemon collector
// surfaces on /api/v1/sensors.
func TestConnectHelloIdentity(t *testing.T) {
	pair, _, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exit := make(chan int, 1)
	go func() {
		exit <- runPCAPOverIPCtx(ctx, []string{
			"--connect", ln.Addr().String(),
			"--from", filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"),
			"--token", "t", "--sensor-id", "edge-7", "--location", "dc-west",
			"--insecure-tls", "--authorized", "--speed", "max",
		}, nil)
	}()

	conn, err := acceptWithin(ln, 5*time.Second)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = conn.Close() }()

	sess, err := pcapoverip.ClientHandshake(conn, pcapoverip.ClientHello{Version: pcapoverip.Version1, Token: "t"}, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	got := pcapoverip.ParseSensorIdentity(sess.SessionID())
	if got.SensorID != "edge-7" || got.Location != "dc-west" {
		t.Fatalf("identity id/location wrong: %+v (session %q)", got, sess.SessionID())
	}
	if got.OSArch != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("identity os/arch = %q, want %q", got.OSArch, runtime.GOOS+"/"+runtime.GOARCH)
	}
	if got.AgentVersion == "" {
		t.Fatal("identity carries no agent version")
	}
	_ = sess.Close()
	cancel()
	select {
	case <-exit:
	case <-time.After(5 * time.Second):
		t.Fatal("subcommand did not exit after cancel")
	}
}

// TestConnectNoGoroutineLeak: a --connect session that is cancelled must not
// leak goroutines or fds (issue #98's leak check, applied to the real path).
func TestConnectNoGoroutineLeak(t *testing.T) {
	// Bind then release a port so the dial fails and the reconnect loop spins.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	before := runtime.NumGoroutine()

	for range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		exit := make(chan int, 1)
		go func() {
			exit <- runPCAPOverIPCtx(ctx, []string{
				"--connect", addr,
				"--from", filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"),
				"--token", "t", "--insecure-tls", "--authorized",
				"--retry-min", "10ms", "--retry-max", "20ms",
			}, nil)
		}()
		time.Sleep(120 * time.Millisecond)
		cancel()
		select {
		case code := <-exit:
			if code != 0 {
				t.Fatalf("exit code %d", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reconnect loop did not stop on cancel")
		}
	}

	// Let the runtime settle, then check the delta.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine()-before <= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: before=%d after=%d", before, runtime.NumGoroutine())
}
