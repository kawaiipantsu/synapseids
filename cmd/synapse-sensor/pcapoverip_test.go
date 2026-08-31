package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// TestPCAPOverIPSubcommandEndToEnd starts the reference server with a generated
// self-signed cert and drains the SYNPOIP stream over real TLS on loopback.
func TestPCAPOverIPSubcommandEndToEnd(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokFile, []byte("demo-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap")

	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan net.Addr, 1)
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- runPCAPOverIPCtx(ctx, []string{
			"--listen", "127.0.0.1:0",
			"--from", capPath,
			"--token-file", tokFile,
			"--speed", "max",
		}, func(a net.Addr) { addrCh <- a })
	}()

	var addr net.Addr
	select {
	case addr = <-addrCh:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("server never became ready")
	}

	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test dials the generated self-signed cert
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	sess, err := pcapoverip.ClientHandshake(conn, pcapoverip.ClientHello{
		Version: pcapoverip.Version1, Token: "demo-token", SensorID: "test",
	}, time.Now().Add(3*time.Second))
	if err != nil {
		cancel()
		t.Fatalf("handshake: %v", err)
	}

	packets := 0
	for {
		ft, _, rerr := sess.ReadFrame(3 * time.Second)
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
		t.Fatal("received no packets from the pcap-over-ip subcommand")
	}
	select {
	case code := <-exitCh:
		if code != 0 {
			t.Fatalf("subcommand exit code %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("subcommand did not exit after cancel")
	}
	t.Logf("drained %d packets from portscan.pcap over TLS", packets)
}

func TestParseSpeed(t *testing.T) {
	for in, want := range map[string]float64{"": 1, "1": 1, "2x": 2, "0.5": 0.5, "max": 0} {
		got, err := parseSpeed(in)
		if err != nil || got != want {
			t.Errorf("parseSpeed(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseSpeed("fast"); err == nil {
		t.Error("parseSpeed(\"fast\") should error")
	}
}
