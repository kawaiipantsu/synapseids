package capture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

const testPCAP = "../../testdata/pcap/http.pcap"

type poipServerOpts struct {
	token         string
	speed         float64
	filter        string
	keepalive     time.Duration
	requireClient bool // mutual TLS
	stream        pcapoverip.StreamFunc
}

// startPOIPServer brings up a TLS pcap-over-ip reference server on loopback and
// returns its address plus the PEM files a client needs (server CA, and — for
// mTLS — a client cert/key it can present).
func startPOIPServer(t *testing.T, o poipServerOpts) (addr, caFile, clientCert, clientKey string) {
	t.Helper()

	srvCert, srvCAPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert}}

	dir := t.TempDir()
	caFile = filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(caFile, srvCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if o.requireClient {
		cliCert, cliCertPEM, cliKeyPEM, cerr := pcapoverip.SelfSignedCert("synapsed-client")
		if cerr != nil {
			t.Fatalf("client cert: %v", cerr)
		}
		_ = cliCert
		clientCert = filepath.Join(dir, "client.pem")
		clientKey = filepath.Join(dir, "client-key.pem")
		if err := os.WriteFile(clientCert, cliCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(clientKey, cliKeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cliCertPEM)
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	stream := o.stream
	link := uint32(packet.LinkEthernet)
	if stream == nil {
		s, l, serr := pcapoverip.PcapFileStream(testPCAP, o.speed)
		if serr != nil {
			t.Fatalf("PcapFileStream: %v", serr)
		}
		stream, link = s, l
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = pcapoverip.Serve(ctx, ln, pcapoverip.ServerConfig{
			Token:             o.token,
			LinkType:          link,
			Filter:            o.filter,
			KeepaliveInterval: o.keepalive,
		}, stream)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("pcap-over-ip server did not stop")
		}
	})
	return ln.Addr().String(), caFile, clientCert, clientKey
}

func drain(t *testing.T, src *PCAPOverIP, limit time.Duration) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	pkts, errc := src.Packets(ctx)
	n := 0
	for {
		select {
		case _, ok := <-pkts:
			if !ok {
				select {
				case err := <-errc:
					return n, err
				default:
					return n, nil
				}
			}
			n++
		case <-ctx.Done():
			return n, ctx.Err()
		}
	}
}

func refDecodedCount(t *testing.T) int {
	t.Helper()
	f, err := OpenPCAPFile(testPCAP)
	if err != nil {
		t.Fatalf("OpenPCAPFile: %v", err)
	}
	pkts, errc := f.Packets(context.Background())
	n := 0
	for range pkts {
		n++
	}
	if err := <-errc; err != nil {
		t.Fatalf("reference read: %v", err)
	}
	return n
}

func TestPCAPOverIPRoundTrip(t *testing.T) {
	addr, caFile, _, _ := startPOIPServer(t, poipServerOpts{token: "s3cret", speed: 0, filter: "ip"})

	src, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "s3cret", ServerName: "127.0.0.1", CAFile: caFile})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	got, termErr := drain(t, src, 10*time.Second)
	if termErr != nil {
		t.Fatalf("terminal error: %v", termErr)
	}
	if want := refDecodedCount(t); got != want {
		t.Fatalf("received %d packets, want %d", got, want)
	}
	st := src.Stats()
	if st.Decoded == 0 || st.Bytes == 0 || st.LastTS.IsZero() {
		t.Fatalf("stats not populated: %+v", st)
	}
	if src.ConnLatencyMS() < 0 {
		t.Fatalf("negative conn latency %d", src.ConnLatencyMS())
	}
	if f, ok := src.DynamicFilter(); !ok || f != "ip" {
		t.Fatalf("DynamicFilter = %q,%v want \"ip\",true", f, ok)
	}
}

func TestPCAPOverIPBadToken(t *testing.T) {
	addr, caFile, _, _ := startPOIPServer(t, poipServerOpts{token: "right", speed: 0})
	src, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "wrong", ServerName: "127.0.0.1", CAFile: caFile})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	_, termErr := drain(t, src, 5*time.Second)
	if termErr == nil || !strings.Contains(termErr.Error(), "unauthorized") {
		t.Fatalf("want an unauthorized reject, got %v", termErr)
	}
}

func TestPCAPOverIPServerGoodbyeCleanEOF(t *testing.T) {
	addr, caFile, _, _ := startPOIPServer(t, poipServerOpts{token: "t", speed: 0})
	src, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "t", ServerName: "127.0.0.1", CAFile: caFile})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	got, termErr := drain(t, src, 10*time.Second)
	if termErr != nil {
		t.Fatalf("end of capture should be a clean EOF, got %v", termErr)
	}
	if got == 0 {
		t.Fatal("no packets before goodbye")
	}
}

func TestPCAPOverIPIdleTimeout(t *testing.T) {
	// A stream that never yields a record, and a long server keepalive so the
	// client's short read-idle window is what fires.
	blocking := func(ctx context.Context) (<-chan pcapoverip.Record, <-chan error) {
		recs := make(chan pcapoverip.Record)
		errc := make(chan error, 1)
		go func() { <-ctx.Done(); close(recs); close(errc) }()
		return recs, errc
	}
	addr, caFile, _, _ := startPOIPServer(t, poipServerOpts{token: "t", keepalive: 30 * time.Second, stream: blocking})

	src, err := NewPCAPOverIP(POIPConfig{
		Addr: addr, Token: "t", ServerName: "127.0.0.1", CAFile: caFile,
		ReadIdleTimeout: 250 * time.Millisecond, KeepaliveInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	_, termErr := drain(t, src, 5*time.Second)
	if termErr == nil || !strings.Contains(termErr.Error(), "idle") {
		t.Fatalf("want a read-idle timeout, got %v", termErr)
	}
}

func TestPCAPOverIPContextCancelNoLeak(t *testing.T) {
	blocking := func(ctx context.Context) (<-chan pcapoverip.Record, <-chan error) {
		recs := make(chan pcapoverip.Record)
		errc := make(chan error, 1)
		go func() { <-ctx.Done(); close(recs); close(errc) }()
		return recs, errc
	}
	addr, caFile, _, _ := startPOIPServer(t, poipServerOpts{token: "t", keepalive: 30 * time.Second, stream: blocking})

	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	src, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "t", ServerName: "127.0.0.1", CAFile: caFile})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pkts, errc := src.Packets(ctx)
	time.Sleep(200 * time.Millisecond) // let it connect and settle
	cancel()

	for range pkts { //nolint:revive // drain until closed
	}
	if err := <-errc; err != nil {
		t.Fatalf("cancel should be a clean stop, got %v", err)
	}
	_ = src.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: before=%d after=%d", before, runtime.NumGoroutine())
}

func TestPCAPOverIPInsecureNeedsAuthorized(t *testing.T) {
	if _, err := NewPCAPOverIP(POIPConfig{Addr: "127.0.0.1:4789", Token: "t", InsecureSkipVerify: true}); err == nil {
		t.Fatal("insecure_tls without authorized must be rejected")
	}
	if _, err := NewPCAPOverIP(POIPConfig{Addr: "10.9.9.9:4789", Token: "t"}); err == nil {
		t.Fatal("a non-loopback addr without authorized must be rejected")
	}
	if _, err := NewPCAPOverIP(POIPConfig{Addr: "127.0.0.1:4789"}); err == nil {
		t.Fatal("a missing token without authorized must be rejected")
	}
	if _, err := NewPCAPOverIP(POIPConfig{Addr: "10.9.9.9:4789", Token: "t", Authorized: true}); err != nil {
		t.Fatalf("authorized remote should build: %v", err)
	}
}

func TestPCAPOverIPTLSVerifyFailsWithoutCA(t *testing.T) {
	addr, _, _, _ := startPOIPServer(t, poipServerOpts{token: "t", speed: 0})
	// No CAFile, verification on: the self-signed sensor cert must not verify.
	src, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "t", ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	_, termErr := drain(t, src, 5*time.Second)
	if termErr == nil || !strings.Contains(termErr.Error(), "certificate") {
		t.Fatalf("want a TLS certificate verification error, got %v", termErr)
	}
}

func TestPCAPOverIPInsecureSkipVerifyConnects(t *testing.T) {
	addr, _, _, _ := startPOIPServer(t, poipServerOpts{token: "t", speed: 0})
	src, err := NewPCAPOverIP(POIPConfig{
		Addr: addr, Token: "t", ServerName: "127.0.0.1",
		InsecureSkipVerify: true, Authorized: true,
	})
	if err != nil {
		t.Fatalf("NewPCAPOverIP: %v", err)
	}
	got, termErr := drain(t, src, 10*time.Second)
	if termErr != nil {
		t.Fatalf("insecure connect terminal error: %v", termErr)
	}
	if got == 0 {
		t.Fatal("no packets over insecure-skip-verify connection")
	}
}

func TestPCAPOverIPMutualTLS(t *testing.T) {
	addr, caFile, clientCert, clientKey := startPOIPServer(t, poipServerOpts{token: "t", speed: 0, requireClient: true})

	// Happy path: client presents its certificate.
	src, err := NewPCAPOverIP(POIPConfig{
		Addr: addr, Token: "t", ServerName: "127.0.0.1", CAFile: caFile,
		ClientCertFile: clientCert, ClientKeyFile: clientKey,
	})
	if err != nil {
		t.Fatalf("NewPCAPOverIP (mTLS): %v", err)
	}
	got, termErr := drain(t, src, 10*time.Second)
	if termErr != nil {
		t.Fatalf("mTLS happy path terminal error: %v", termErr)
	}
	if got == 0 {
		t.Fatal("mTLS happy path received no packets")
	}

	// No client certificate: the TLS handshake must fail.
	bare, err := NewPCAPOverIP(POIPConfig{Addr: addr, Token: "t", ServerName: "127.0.0.1", CAFile: caFile})
	if err != nil {
		t.Fatalf("NewPCAPOverIP (bare): %v", err)
	}
	_, termErr = drain(t, bare, 5*time.Second)
	if termErr == nil {
		t.Fatal("a client with no certificate must be rejected by the mTLS server")
	}
}

func TestPCAPOverIPClientCertFilesMustPair(t *testing.T) {
	if _, err := NewPCAPOverIP(POIPConfig{Addr: "127.0.0.1:1", Token: "t", ClientCertFile: "x"}); err == nil {
		t.Fatal("client_cert_file without client_key_file must be rejected")
	}
}
