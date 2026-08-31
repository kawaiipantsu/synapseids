package pcapoverip

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

// countingConn is a writeDeadliner that discards everything but records how many
// Write calls it saw, how many bytes those calls carried, and how many times a
// write deadline was armed. It is the instrument for the claim this change
// makes: same bytes, far fewer calls.
type countingConn struct {
	buf       bytes.Buffer
	writes    int
	bytes     int
	deadlines int
	keep      bool
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	c.bytes += len(p)
	if c.keep {
		c.buf.Write(p)
	}
	return len(p), nil
}

func (c *countingConn) SetWriteDeadline(time.Time) error { c.deadlines++; return nil }

// benchFrames builds n realistic raw records: MTU-sized Ethernet frames, which
// is what a saturated WAN sensor actually ships.
func benchFrames(n, size int) []Record {
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(i)
	}
	out := make([]Record, n)
	base := time.Unix(1700000000, 0)
	for i := range out {
		out[i] = Record{TS: base.Add(time.Duration(i) * time.Microsecond), Raw: raw}
	}
	return out
}

// writeUnbatched is the pre-fix sensor write path, kept here as the benchmark's
// baseline: one write deadline and one WriteFrame — itself two Writes — per
// captured frame.
func writeUnbatched(c writeDeadliner, recs []Record, timeout time.Duration) error {
	for _, rec := range recs {
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		if err := WriteFrame(c, FramePacket, PacketFramePayload(rec.TS.UnixNano(), rec.Raw)); err != nil {
			return err
		}
	}
	return nil
}

// writeBatched is the post-fix path: frames coalesce into the buffer while the
// source is backlogged and one flush ends the batch.
func writeBatched(c writeDeadliner, recs []Record, bufSize int, timeout time.Duration) error {
	w := newFrameWriter(c, bufSize, timeout)
	for i, rec := range recs {
		if err := w.writePacketFrame(rec.TS.UnixNano(), rec.Raw); err != nil {
			return err
		}
		// The server loop returns to its select every maxBatchFrames frames.
		if w.full() || i == len(recs)-1 {
			if err := w.flush(); err != nil {
				return err
			}
		}
	}
	return w.flush()
}

// TestBatchedWritesAreByteIdentical is the whole safety argument for the
// batching: the bytes on the wire do not move, only the Write boundaries do.
func TestBatchedWritesAreByteIdentical(t *testing.T) {
	recs := benchFrames(500, 1514)

	plain := &countingConn{keep: true}
	if err := writeUnbatched(plain, recs, time.Second); err != nil {
		t.Fatalf("unbatched: %v", err)
	}
	batched := &countingConn{keep: true}
	if err := writeBatched(batched, recs, DefaultWriteBufferSize, time.Second); err != nil {
		t.Fatalf("batched: %v", err)
	}

	if !bytes.Equal(plain.buf.Bytes(), batched.buf.Bytes()) {
		t.Fatalf("batching changed the bytes on the wire: %d vs %d bytes",
			plain.buf.Len(), batched.buf.Len())
	}
	if batched.writes >= plain.writes {
		t.Fatalf("batching did not reduce Write calls: %d vs %d", batched.writes, plain.writes)
	}
	t.Logf("500 frames: unbatched %d writes / %d deadlines, batched %d writes / %d deadlines, %d bytes both",
		plain.writes, plain.deadlines, batched.writes, batched.deadlines, plain.buf.Len())
}

// TestWritePacketFrameMatchesWriteFrame pins the allocation-free packet encoder
// to the generic one it replaces on the hot path.
func TestWritePacketFrameMatchesWriteFrame(t *testing.T) {
	cases := [][]byte{nil, {}, {0x01}, bytes.Repeat([]byte{0xab}, 1514)}
	for i, raw := range cases {
		ts := -1_000_000_000 * int64(i+1) // also exercise a pre-epoch timestamp

		var want bytes.Buffer
		if err := WriteFrame(&want, FramePacket, PacketFramePayload(ts, raw)); err != nil {
			t.Fatalf("case %d: WriteFrame: %v", i, err)
		}

		got := &countingConn{keep: true}
		w := newFrameWriter(got, DefaultWriteBufferSize, time.Second)
		if err := w.writePacketFrame(ts, raw); err != nil {
			t.Fatalf("case %d: writePacketFrame: %v", i, err)
		}
		if err := w.flush(); err != nil {
			t.Fatalf("case %d: flush: %v", i, err)
		}
		if !bytes.Equal(want.Bytes(), got.buf.Bytes()) {
			t.Fatalf("case %d: encoding differs:\n want %x\n  got %x", i, want.Bytes(), got.buf.Bytes())
		}
	}
}

// TestFrameWriterRejectsOverCapPayloads keeps the pre-existing refusal: an
// over-cap frame must never reach the buffer, batched or not.
func TestFrameWriterRejectsOverCapPayloads(t *testing.T) {
	c := &countingConn{}
	w := newFrameWriter(c, DefaultWriteBufferSize, time.Second)
	if err := w.writeFrame(FramePacket, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("writeFrame: want ErrProtocol, got %v", err)
	}
	if err := w.writePacketFrame(0, make([]byte, MaxFramePayload)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("writePacketFrame: want ErrProtocol, got %v", err)
	}
	if c.writes != 0 {
		t.Fatalf("an over-cap frame reached the connection (%d writes)", c.writes)
	}
}

// TestControlFrameFlushesQueuedData covers the correctness half of requirement
// 4: a goodbye or keepalive must not leave earlier frames stranded in the
// buffer, and must itself be on the wire when the call returns.
func TestControlFrameFlushesQueuedData(t *testing.T) {
	c := &countingConn{keep: true}
	w := newFrameWriter(c, DefaultWriteBufferSize, time.Second)
	if err := w.writePacketFrame(42, []byte{0xde, 0xad}); err != nil {
		t.Fatalf("packet: %v", err)
	}
	if c.writes != 0 {
		t.Fatalf("a queued packet reached the wire before any flush (%d writes)", c.writes)
	}
	if err := w.writeControl(FrameGoodbye, []byte("end of capture")); err != nil {
		t.Fatalf("goodbye: %v", err)
	}
	if c.writes == 0 {
		t.Fatal("a control frame did not flush")
	}

	fr := NewFrameReader(bytes.NewReader(c.buf.Bytes()))
	ft, payload, err := fr.ReadFrame()
	if err != nil || ft != FramePacket {
		t.Fatalf("frame 1: type=%v err=%v", ft, err)
	}
	if _, raw, perr := ParsePacketFrame(payload); perr != nil || !bytes.Equal(raw, []byte{0xde, 0xad}) {
		t.Fatalf("frame 1 payload: raw=%x err=%v", raw, perr)
	}
	ft, payload, err = fr.ReadFrame()
	if err != nil || ft != FrameGoodbye || string(payload) != "end of capture" {
		t.Fatalf("frame 2: type=%v payload=%q err=%v", ft, payload, err)
	}
	if _, _, err = fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF after the goodbye, got %v", err)
	}
}

// TestFrameWriterAgesOutALongBatch is requirement 5: even a source that always
// has one more frame ready cannot hold bytes indefinitely. The batch is aged out
// on its own, before the single write deadline armed at batch start could
// expire.
func TestFrameWriterAgesOutALongBatch(t *testing.T) {
	c := &countingConn{}
	w := newFrameWriter(c, 1<<20, 20*time.Millisecond) // maxAge = 10ms
	if err := w.writePacketFrame(1, []byte{0x01}); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	time.Sleep(40 * time.Millisecond)

	// Tiny frames into a 1 MiB buffer: nothing can reach the connection because
	// the buffer filled, only because the batch aged out.
	for i := 0; i < 4*ageCheckInterval; i++ {
		if err := w.writePacketFrame(int64(i), []byte{0x02}); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if c.writes == 0 {
		t.Fatal("a batch older than maxAge was never flushed")
	}
	if c.deadlines < 2 {
		t.Fatalf("the aged-out batch did not re-arm its write deadline (%d deadlines)", c.deadlines)
	}
}

// --- benchmarks: the measured justification for the change ---

func benchmarkWrites(b *testing.B, batched bool) {
	const (
		frames = 10000
		size   = 1514
	)
	recs := benchFrames(frames, size)
	b.ReportAllocs()
	b.SetBytes(int64(frames * (5 + 8 + size)))

	var writes, deadlines, wire int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := &countingConn{}
		var err error
		if batched {
			err = writeBatched(c, recs, DefaultWriteBufferSize, DefaultWriteTimeout)
		} else {
			err = writeUnbatched(c, recs, DefaultWriteTimeout)
		}
		if err != nil {
			b.Fatalf("write: %v", err)
		}
		writes, deadlines, wire = c.writes, c.deadlines, c.bytes
	}
	b.StopTimer()

	if want := frames * (5 + 8 + size); wire != want {
		b.Fatalf("wire bytes %d, want %d", wire, want)
	}
	b.ReportMetric(float64(writes), "writes/op")
	b.ReportMetric(float64(deadlines), "deadlines/op")
	b.ReportMetric(float64(wire), "wirebytes/op")
}

// BenchmarkSensorWritesUnbatched is the pre-fix path: 2 Writes and 1
// SetWriteDeadline per captured frame.
func BenchmarkSensorWritesUnbatched(b *testing.B) { benchmarkWrites(b, false) }

// BenchmarkSensorWritesBatched is the same 10k frames through the batching
// writer. The wire bytes are asserted identical; the Write and deadline counts
// are the win.
func BenchmarkSensorWritesBatched(b *testing.B) { benchmarkWrites(b, true) }

// benchmarkTLSWrites is the same 10k frames through a real *tls.Conn on
// loopback, which is where the cost actually lives: without batching each Write
// is its own TLS record and its own syscall.
func benchmarkTLSWrites(b *testing.B, batched bool) {
	const (
		frames = 10000
		size   = 1514
	)
	recs := benchFrames(frames, size)

	cert, certPEM, _, err := SelfSignedCert("127.0.0.1", "localhost")
	if err != nil {
		b.Fatalf("self-signed cert: %v", err)
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
				_, _ = io.Copy(io.Discard, c)
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

	b.ReportAllocs()
	b.SetBytes(int64(frames * (5 + 8 + size)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if batched {
			err = writeBatched(conn, recs, DefaultWriteBufferSize, DefaultWriteTimeout)
		} else {
			err = writeUnbatched(conn, recs, DefaultWriteTimeout)
		}
		if err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

// BenchmarkSensorWritesOverTLSUnbatched is the pre-fix path on a real TLS
// connection.
func BenchmarkSensorWritesOverTLSUnbatched(b *testing.B) { benchmarkTLSWrites(b, false) }

// BenchmarkSensorWritesOverTLSBatched is the post-fix path on the same
// connection: identical bytes, one TLS record per 16 KiB instead of two per
// frame.
func BenchmarkSensorWritesOverTLSBatched(b *testing.B) { benchmarkTLSWrites(b, true) }

// --- the latency property, end to end over real TLS ---

// trickleStream emits n records, one every gap, on an unbuffered channel: the
// idle link this change must not regress. It reports the wall-clock instant each
// record was handed to the server.
func trickleStream(n int, gap time.Duration, sentAt chan<- time.Time) StreamFunc {
	return func(ctx context.Context) (<-chan Record, <-chan error) {
		recs := make(chan Record)
		errc := make(chan error, 1)
		go func() {
			defer close(recs)
			defer close(errc)
			for i := 0; i < n; i++ {
				select {
				case <-time.After(gap):
				case <-ctx.Done():
					return
				}
				rec := Record{TS: time.Now(), Raw: []byte{0x01, 0x02, 0x03, 0x04, byte(i)}}
				now := time.Now()
				select {
				case recs <- rec:
					select {
					case sentAt <- now:
					default:
					}
				case <-ctx.Done():
					return
				}
			}
			<-ctx.Done()
		}()
		return recs, errc
	}
}

// TestIdleLinkFlushesEveryFrame is requirement 2, and the property most likely
// to regress: on a link with one packet now and then, each frame must reach the
// daemon immediately, not when a buffer eventually fills or a keepalive fires.
//
// The proof is that no other mechanism can deliver it. The keepalive interval
// and the write timeout — and with it the batch age-out at half the timeout —
// are both set far beyond the client's read deadline, so a frame that arrives
// within that deadline can only have been flushed because the source had
// nothing else ready.
func TestIdleLinkFlushesEveryFrame(t *testing.T) {
	const (
		frames  = 3
		gap     = 50 * time.Millisecond
		readTO  = 2 * time.Second
		nothing = 10 * time.Minute // keepalive + write timeout: cannot be the cause
	)
	sentAt := make(chan time.Time, frames)
	addr, ca := testTLSServer(t, ServerConfig{
		Token: "tok", LinkType: 1,
		KeepaliveInterval: nothing,
		WriteTimeout:      nothing,
	}, trickleStream(frames, gap, sentAt))

	sess, err := dialSession(t, addr, ca, ClientHello{Version: Version1, Token: "tok"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = sess.Close() }()

	for i := 0; i < frames; i++ {
		ft, payload, rerr := sess.ReadFrame(readTO)
		if rerr != nil {
			t.Fatalf("frame %d: %v (a buffered frame that was never flushed reads as a timeout)", i, rerr)
		}
		if ft != FramePacket {
			t.Fatalf("frame %d: type %v, want a packet", i, ft)
		}
		_, raw, perr := ParsePacketFrame(payload)
		if perr != nil || len(raw) != 5 || raw[4] != byte(i) {
			t.Fatalf("frame %d: raw=%x err=%v", i, raw, perr)
		}
		var latency time.Duration
		select {
		case at := <-sentAt:
			latency = time.Since(at)
		default:
		}
		if latency >= readTO {
			t.Fatalf("frame %d took %s to cross an idle link", i, latency)
		}
		t.Logf("frame %d delivered %s after the sensor produced it", i, latency.Round(time.Microsecond))
	}
}

// TestBackloggedSourceStillEndsCleanly checks the batching path end to end: a
// source that is always ready is coalesced, and the final frames plus the
// goodbye still arrive — a truncated tail would be a correctness bug.
func TestBackloggedSourceStillEndsCleanly(t *testing.T) {
	const frames = 5000
	burst := func(ctx context.Context) (<-chan Record, <-chan error) {
		recs := make(chan Record, 512)
		errc := make(chan error, 1)
		go func() {
			defer close(recs)
			defer close(errc)
			for i := 0; i < frames; i++ {
				rec := Record{TS: time.Unix(0, int64(i)), Raw: fmt.Appendf(nil, "frame-%06d", i)}
				select {
				case recs <- rec:
				case <-ctx.Done():
					return
				}
			}
		}()
		return recs, errc
	}
	addr, ca := testTLSServer(t, ServerConfig{Token: "tok", LinkType: 1}, burst)

	sess, err := dialSession(t, addr, ca, ClientHello{Version: Version1, Token: "tok"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = sess.Close() }()

	got, sawGoodbye := 0, false
	for !sawGoodbye {
		ft, payload, rerr := sess.ReadFrame(5 * time.Second)
		if rerr != nil {
			t.Fatalf("after %d frames: %v", got, rerr)
		}
		switch ft {
		case FramePacket:
			_, raw, perr := ParsePacketFrame(payload)
			if perr != nil {
				t.Fatalf("frame %d: %v", got, perr)
			}
			if want := fmt.Sprintf("frame-%06d", got); string(raw) != want {
				t.Fatalf("frame %d out of order: got %q want %q", got, raw, want)
			}
			got++
		case FrameGoodbye:
			sawGoodbye = true
		}
	}
	if got != frames {
		t.Fatalf("received %d frames, sent %d — the tail of a batch was lost", got, frames)
	}
}
