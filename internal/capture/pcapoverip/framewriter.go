package pcapoverip

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

// Outbound batching limits. They exist because the sensor writes one frame per
// captured packet, and on a *tls.Conn every io.Writer.Write is its own TLS
// record and its own syscall. WriteFrame issues two writes (header, payload), so
// an unbuffered raw-mode sensor turns N packets into 2N TLS records, 2N syscalls
// and N SetWriteDeadline calls. Measured on an OPNsense WAN sensor that was
// enough to lose 63% of frames to BPF kernel drops at 81% CPU while both BPF
// buffers sat full — the kernel was batching correctly and the consumer could
// not drain. See ADR 0029.
const (
	// DefaultWriteBufferSize is the outbound batching buffer for one SYNPOIP
	// connection. 64 KiB is four times the 16 KiB TLS record ceiling, so a full
	// buffer still amortises into a handful of maximum-size records; it holds
	// ~42 maximum-size Ethernet frames or ~1000 small ones, which is the burst
	// depth a saturated NIC actually produces between drains. Bigger buys
	// nothing — crypto/tls caps a record at 16 KiB regardless — and costs
	// latency headroom and per-client memory.
	DefaultWriteBufferSize = 64 << 10

	// maxBatchFrames bounds how many frames one batch may absorb before the
	// server loop returns to its select. Without it a permanently backlogged
	// source could starve the keepalive ticker and the cancellation check.
	maxBatchFrames = 1024

	// ageCheckInterval is how many buffered frames pass between clock reads. The
	// age bound below only has to be approximate, and time.Now() per frame is
	// exactly the kind of per-packet cost this file exists to remove.
	ageCheckInterval = 64
)

// writeDeadliner is the slice of net.Conn a frameWriter needs: the bytes out and
// the one deadline it arms per batch. Naming it keeps the benchmark honest — the
// same code is measured against a counting writer and against a real *tls.Conn.
type writeDeadliner interface {
	io.Writer
	SetWriteDeadline(t time.Time) error
}

// frameWriter batches SYNPOIP frames for one connection and flushes them as a
// unit. It is single-goroutine, like the server loop that owns it.
//
// The wire bytes are unchanged: this only moves where the TLS record and syscall
// boundaries fall. Two properties keep the batching honest:
//
//   - the caller flushes as soon as the source has nothing else ready, so a
//     quiet link never sits on a packet (PROJECT.md §17, §22);
//   - a batch is aged out after maxAge regardless, so even a pathological
//     trickle that always has one more frame ready cannot hold bytes
//     indefinitely — and the batch can never outlive the single write deadline
//     armed when it opened.
type frameWriter struct {
	conn    writeDeadliner
	bw      *bufio.Writer
	timeout time.Duration
	maxAge  time.Duration

	// open reports whether a batch is in progress: a write deadline is armed and
	// bytes may be sitting in bw.
	open       bool
	batchStart time.Time
	sinceCheck int

	frames int // frames written into the current batch, for maxBatchFrames

	// head is the reusable frame header scratch for writePacketFrame. It lives on
	// the struct rather than the stack because a local array handed to
	// bufio.Write escapes, which is one heap allocation per captured packet — the
	// kind of per-packet cost PROJECT.md §22 asks the packet path not to pay.
	head [5 + 8]byte
}

// newFrameWriter wraps conn. bufSize <= 0 uses DefaultWriteBufferSize; timeout
// <= 0 uses DefaultWriteTimeout.
func newFrameWriter(conn writeDeadliner, bufSize int, timeout time.Duration) *frameWriter {
	if bufSize <= 0 {
		bufSize = DefaultWriteBufferSize
	}
	if timeout <= 0 {
		timeout = DefaultWriteTimeout
	}
	return &frameWriter{
		conn:    conn,
		bw:      bufio.NewWriterSize(conn, bufSize),
		timeout: timeout,
		// Half the write timeout: a batch is force-flushed and its deadline
		// re-armed well before the deadline armed at batch start could expire, so
		// batching can never turn a healthy peer into a write timeout.
		maxAge: timeout / 2,
	}
}

// full reports whether the current batch has absorbed as much as one batch may.
func (w *frameWriter) full() bool { return w.frames >= maxBatchFrames }

// begin opens a batch if none is open, arming this batch's single write
// deadline, and ages out a batch that has been open too long.
func (w *frameWriter) begin() error {
	if w.open {
		w.sinceCheck++
		if w.sinceCheck >= ageCheckInterval {
			w.sinceCheck = 0
			if time.Since(w.batchStart) >= w.maxAge {
				if err := w.flush(); err != nil {
					return err
				}
			}
		}
	}
	if !w.open {
		w.open = true
		w.batchStart = time.Now()
		w.sinceCheck = 0
		// One deadline per batch, not per frame. It covers every write the batch
		// makes, including the implicit flushes bufio performs when the buffer
		// fills; maxAge guarantees the batch ends before it can expire.
		_ = w.conn.SetWriteDeadline(w.batchStart.Add(w.timeout))
	}
	return nil
}

// writeFrame buffers one frame. Nothing is guaranteed to reach the peer until
// flush (or the buffer filling) sends it.
func (w *frameWriter) writeFrame(t FrameType, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return protoErr("frame payload %d exceeds %d", len(payload), MaxFramePayload)
	}
	if err := w.begin(); err != nil {
		return err
	}
	w.frames++
	return WriteFrame(w.bw, t, payload)
}

// writePacketFrame buffers a FramePacket without building the payload first. It
// emits exactly the bytes WriteFrame(w, FramePacket, PacketFramePayload(ts, raw))
// emits, minus the per-packet allocation and copy of that intermediate payload.
func (w *frameWriter) writePacketFrame(tsUnixNano int64, raw []byte) error {
	if len(raw)+8 > MaxFramePayload {
		return protoErr("frame payload %d exceeds %d", len(raw)+8, MaxFramePayload)
	}
	if err := w.begin(); err != nil {
		return err
	}
	w.frames++

	w.head[0] = byte(FramePacket)
	binary.BigEndian.PutUint32(w.head[1:], uint32(len(raw)+8)) //nolint:gosec // bounded by MaxFramePayload above
	binary.BigEndian.PutUint64(w.head[5:], uint64(tsUnixNano)) //nolint:gosec // wire field is the raw two's-complement nanoseconds
	if _, err := w.bw.Write(w.head[:]); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	_, err := w.bw.Write(raw)
	return err
}

// writeControl buffers a control frame (keepalive, goodbye) and flushes
// immediately, so everything queued behind it leaves with it. A control frame
// left in a buffer is a correctness bug, not a latency one: the peer's whole
// read of the session's end depends on it.
func (w *frameWriter) writeControl(t FrameType, payload []byte) error {
	if err := w.writeFrame(t, payload); err != nil {
		// Still try to push out whatever was already queued.
		_ = w.flush()
		return err
	}
	return w.flush()
}

// flush ends the current batch and pushes it to the connection. It is a no-op
// when no batch is open, so it is safe on every return path.
func (w *frameWriter) flush() error {
	if !w.open {
		return nil
	}
	w.open = false
	w.frames = 0
	if w.bw.Buffered() == 0 {
		return nil
	}
	return w.bw.Flush()
}
