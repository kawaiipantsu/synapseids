package pcapoverip

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientHelloRoundTrip(t *testing.T) {
	in := ClientHello{
		Version:  Version1,
		LinkType: 1,
		Token:    "s3cr3t-token",
		SensorID: "hq-01",
		Filter:   "ip",
		Location: "copenhagen",
	}
	raw, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ReadClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestReadClientHelloRejectsBadMagic(t *testing.T) {
	raw := append([]byte("NOTSYNPO"), make([]byte, 20)...)
	if _, err := ReadClientHello(bytes.NewReader(raw)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("want ErrProtocol, got %v", err)
	}
}

func TestReadClientHelloRejectsOversizedToken(t *testing.T) {
	// magic + version + linktype + tokenLen(=60000) then EOF.
	var b bytes.Buffer
	b.WriteString(Magic)
	b.Write([]byte{0, 1}) // version
	b.Write([]byte{0, 0, 0, 1})
	b.Write([]byte{0xea, 0x60}) // 60000
	if _, err := ReadClientHello(&b); !errors.Is(err, ErrProtocol) {
		t.Fatalf("want ErrProtocol for oversized token, got %v", err)
	}
}

func TestServerResponseRoundTrip(t *testing.T) {
	acc := ServerAccept{Version: Version1, LinkType: 101, Filter: "not-arp", SessionID: "abc123"}
	raw, err := acc.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal accept: %v", err)
	}
	got, err := ReadServerResponse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read accept: %v", err)
	}
	if got == nil || *got != acc {
		t.Fatalf("accept round trip: got %+v want %+v", got, acc)
	}

	rj := ServerReject{Code: RejectUnauthorized, Reason: "bad bearer token"}
	raw, err = rj.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal reject: %v", err)
	}
	_, err = ReadServerResponse(bytes.NewReader(raw))
	var re *RejectError
	if !errors.As(err, &re) || re.Code != RejectUnauthorized || re.Reason != "bad bearer token" {
		t.Fatalf("reject round trip: got %v", err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	payload := PacketFramePayload(time.Unix(1, 2).UnixNano(), []byte{0xde, 0xad, 0xbe, 0xef})
	if err := WriteFrame(&b, FramePacket, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteFrame(&b, FrameKeepalive, nil); err != nil {
		t.Fatalf("write keepalive: %v", err)
	}

	fr := NewFrameReader(&b)
	ft, got, err := fr.ReadFrame()
	if err != nil || ft != FramePacket {
		t.Fatalf("read packet frame: ft=%v err=%v", ft, err)
	}
	ts, raw, err := ParsePacketFrame(got)
	if err != nil || ts != time.Unix(1, 2).UnixNano() || !bytes.Equal(raw, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("parse packet frame: ts=%d raw=%x err=%v", ts, raw, err)
	}
	ft, got, err = fr.ReadFrame()
	if err != nil || ft != FrameKeepalive || len(got) != 0 {
		t.Fatalf("read keepalive: ft=%v got=%x err=%v", ft, got, err)
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	var b bytes.Buffer
	b.WriteByte(byte(FramePacket))
	b.Write([]byte{0x00, 0x10, 0x00, 0x00}) // 1 MiB, well over MaxFramePayload
	fr := NewFrameReader(&b)
	if _, _, err := fr.ReadFrame(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("want ErrProtocol for oversized frame, got %v", err)
	}
}

func TestPcapFileStream(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "pcap", "http.pcap")
	stream, link, err := PcapFileStream(path, 0)
	if err != nil {
		t.Fatalf("PcapFileStream: %v", err)
	}
	if link != linkEN10MB {
		t.Fatalf("http.pcap link type = %d, want %d", link, linkEN10MB)
	}
	recs, errc := stream(context.Background())
	var n int
	for r := range recs {
		if len(r.Raw) == 0 {
			t.Fatal("empty record")
		}
		n++
	}
	if err := <-errc; err != nil {
		t.Fatalf("stream terminal error: %v", err)
	}
	if n == 0 {
		t.Fatal("no records streamed from http.pcap")
	}
	t.Logf("http.pcap streamed %d records (link %d)", n, link)
}

func TestPcapFileStreamRejectsNonPCAP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := writeTemp(p, []byte("this is not a pcap file, just some bytes")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PcapFileStream(p, 0); !errors.Is(err, ErrNotClassicPCAP) {
		t.Fatalf("want ErrNotClassicPCAP, got %v", err)
	}
}

// --- server + Session integration over real TLS on loopback ---

func testTLSServer(t *testing.T, cfg ServerConfig, stream StreamFunc) (addr string, caPEM []byte) {
	t.Helper()
	srvCert, certPEM, _, err := SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = Serve(ctx, ln, cfg, stream)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("server did not stop within 2s")
		}
	})
	return ln.Addr().String(), certPEM
}

func dialSession(t *testing.T, addr string, caPEM []byte, hello ClientHello) (*Session, error) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca PEM did not parse")
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "127.0.0.1",
		RootCAs:    pool,
	})
	if err != nil {
		return nil, err
	}
	return ClientHandshake(conn, hello, time.Now().Add(3*time.Second))
}

func TestServeSessionRoundTrip(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "pcap", "http.pcap")
	stream, link, err := PcapFileStream(path, 0)
	if err != nil {
		t.Fatalf("PcapFileStream: %v", err)
	}
	addr, ca := testTLSServer(t, ServerConfig{Token: "tok", LinkType: link, Filter: "ip"}, stream)

	sess, err := dialSession(t, addr, ca, ClientHello{Version: Version1, Token: "tok"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if sess.LinkType() != link || sess.Filter() != "ip" || sess.NegotiatedVersion() != Version1 {
		t.Fatalf("accept fields: link=%d filter=%q v=%d", sess.LinkType(), sess.Filter(), sess.NegotiatedVersion())
	}

	var packets int
	sawGoodbye := false
	for {
		ft, payload, rerr := sess.ReadFrame(3 * time.Second)
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("read frame: %v", rerr)
		}
		switch ft {
		case FramePacket:
			if _, _, perr := ParsePacketFrame(payload); perr != nil {
				t.Fatalf("bad packet frame: %v", perr)
			}
			packets++
		case FrameGoodbye:
			sawGoodbye = true
		}
		if sawGoodbye {
			break
		}
	}
	if packets == 0 || !sawGoodbye {
		t.Fatalf("packets=%d sawGoodbye=%v", packets, sawGoodbye)
	}
}

func TestServeRejectsBadToken(t *testing.T) {
	addr, ca := testTLSServer(t, ServerConfig{Token: "right", LinkType: 1}, blockingStream)
	_, err := dialSession(t, addr, ca, ClientHello{Version: Version1, Token: "wrong"})
	var re *RejectError
	if !errors.As(err, &re) || re.Code != RejectUnauthorized {
		t.Fatalf("want RejectUnauthorized, got %v", err)
	}
}

func TestServeRejectsHigherVersion(t *testing.T) {
	addr, ca := testTLSServer(t, ServerConfig{Token: "tok", LinkType: 1}, blockingStream)
	_, err := dialSession(t, addr, ca, ClientHello{Version: VersionMax + 1, Token: "tok"})
	var re *RejectError
	if !errors.As(err, &re) || re.Code != RejectVersion {
		t.Fatalf("want RejectVersion for a version above VersionMax, got %v", err)
	}
}

func TestServeRejectsLinkTypeMismatch(t *testing.T) {
	addr, ca := testTLSServer(t, ServerConfig{Token: "tok", LinkType: 1}, blockingStream)
	_, err := dialSession(t, addr, ca, ClientHello{Version: Version1, Token: "tok", LinkType: 101})
	var re *RejectError
	if !errors.As(err, &re) || re.Code != RejectLinkType {
		t.Fatalf("want RejectLinkType, got %v", err)
	}
}

// blockingStream yields no records and never errors until ctx is cancelled.
func blockingStream(ctx context.Context) (<-chan Record, <-chan error) {
	recs := make(chan Record)
	errc := make(chan error, 1)
	go func() {
		<-ctx.Done()
		close(recs)
		close(errc)
	}()
	return recs, errc
}

func writeTemp(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }
