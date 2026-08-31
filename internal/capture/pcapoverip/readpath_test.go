package pcapoverip

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"
)

type countingReader struct {
	r     io.Reader
	reads int
	bytes int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.reads++
	c.bytes += n
	return n, err
}

func benchStream(frames, size int) []byte {
	var buf bytes.Buffer
	raw := make([]byte, size)
	for i := 0; i < frames; i++ {
		_ = WriteFrame(&buf, FramePacket, PacketFramePayload(int64(i), raw))
	}
	return buf.Bytes()
}

// The collector's read side was checked for the same per-frame overhead the
// sensor's write side had, and deliberately left unbuffered. These measurements
// are why — keep them, so the next person asking "why is there no bufio.Reader
// in FrameReader?" gets the numbers instead of the intuition.
//
// FrameReader does issue two Read calls per frame (header, payload), and on a
// bare socket that would indeed be two syscalls. But every SYNPOIP connection is
// a *tls.Conn, and crypto/tls reads a whole TLS record — up to 16 KiB — into its
// own buffer, then serves subsequent Reads out of it without a syscall. The
// read path is therefore already batched by the layer underneath it, which is
// exactly what the write path was not: crypto/tls emits a record per Write, but
// does not consume one per Read.
//
// Measured here on loopback TLS, 10k 1514-byte frames per op:
//
//	BenchmarkCollectorReadsUnbuffered   6.94 ms/op   2198 MB/s
//	BenchmarkCollectorReadsBuffered     7.69 ms/op   1985 MB/s
//
// A 64 KiB bufio.Reader cuts the Read *calls* from 20000 to 234 (see
// TestReadSideCallCount) and buys nothing in wall clock, because those calls
// were never syscalls — while adding one more copy of every packet byte. So it
// is not the same shape of bug and it does not get the same fix.
func TestReadSideCallCount(t *testing.T) {
	const frames, size = 10000, 1514
	wire := benchStream(frames, size)

	plain := &countingReader{r: bytes.NewReader(wire)}
	fr := NewFrameReader(plain)
	for i := 0; i < frames; i++ {
		if _, _, err := fr.ReadFrame(); err != nil {
			t.Fatalf("plain %d: %v", i, err)
		}
	}

	buffered := &countingReader{r: bytes.NewReader(wire)}
	fr = NewFrameReader(bufio.NewReaderSize(buffered, 64<<10))
	for i := 0; i < frames; i++ {
		if _, _, err := fr.ReadFrame(); err != nil {
			t.Fatalf("buffered %d: %v", i, err)
		}
	}
	t.Logf("read side, %d frames: unbuffered %d Read calls / %d bytes, bufio %d Read calls / %d bytes",
		frames, plain.reads, plain.bytes, buffered.reads, buffered.bytes)
}

func benchmarkTLSReads(b *testing.B, buffered bool) {
	const frames, size = 10000, 1514
	wire := benchStream(frames, size)

	cert, certPEM, _, err := SelfSignedCert("127.0.0.1", "localhost")
	if err != nil {
		b.Fatalf("cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					if _, werr := c.Write(wire); werr != nil {
						return
					}
				}
			}()
		}
	}()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		b.Fatal("ca PEM did not parse")
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", RootCAs: pool,
	})
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var src io.Reader = conn
	if buffered {
		src = bufio.NewReaderSize(conn, 64<<10)
	}
	fr := NewFrameReader(src)

	b.ReportAllocs()
	b.SetBytes(int64(frames * (5 + 8 + size)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < frames; j++ {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, _, rerr := fr.ReadFrame(); rerr != nil {
				b.Fatalf("read: %v", rerr)
			}
		}
	}
}

func BenchmarkCollectorReadsUnbuffered(b *testing.B) { benchmarkTLSReads(b, false) }
func BenchmarkCollectorReadsBuffered(b *testing.B)   { benchmarkTLSReads(b, true) }
