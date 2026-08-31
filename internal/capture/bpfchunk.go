package capture

import (
	"encoding/binary"
	"fmt"
	"time"
)

// This file is the pure, syscall-free half of the FreeBSD /dev/bpf source: it
// splits one read(2) chunk into the individual capture records the kernel
// packed into it. It carries no build tag on purpose, so the fiddly part is
// table-tested on the Linux development and CI machines (see bpfchunk_test.go)
// even though the code that feeds it only compiles on FreeBSD.
//
// A single read from a BPF device returns *many* packets back to back. Each is
// prefixed by a struct bpf_hdr (default BPF_T_MICROTIME timestamps) or a
// struct bpf_xhdr (BPF_T_NANOTIME), and each record starts on a
// BPF_WORDALIGN boundary:
//
//	struct bpf_hdr {              struct bpf_xhdr {
//	    struct timeval bh_tstamp;     struct bpf_ts bh_tstamp;   /* {int64,uint64} */
//	    bpf_u_int32 bh_caplen;        bpf_u_int32 bh_caplen;
//	    bpf_u_int32 bh_datalen;       bpf_u_int32 bh_datalen;
//	    u_short     bh_hdrlen;        u_short     bh_hdrlen;
//	};                            };
//
//	#define BPF_ALIGNMENT    sizeof(long)
//	#define BPF_WORDALIGN(x) (((x) + (BPF_ALIGNMENT-1)) & ~(BPF_ALIGNMENT-1))
//
// bh_hdrlen is authoritative for where the frame starts — it already includes
// the alignment padding the kernel inserted after the header — so the parser
// never assumes a header size. That is also what libpcap does.

// bpfHdrLayout describes where the fields of a BPF record header sit and how to
// read them. bpf_freebsd.go builds the host layout from unsafe.Offsetof on
// syscall.BpfHdr, so it is correct on every FreeBSD GOARCH; the tests build it
// literally.
type bpfHdrLayout struct {
	// order is the byte order of the header fields. BPF headers are written by
	// the kernel in host byte order.
	order binary.ByteOrder

	// tsSecOff / tsSecWidth locate bh_tstamp's seconds field (time_t, 8 bytes
	// on FreeBSD 12+ everywhere; 4 is accepted for older/other BSD layouts).
	tsSecOff   int
	tsSecWidth int
	// tsFracOff / tsFracWidth locate the sub-second field: suseconds_t for
	// struct timeval, bpf_u_int64 bt_frac for struct bpf_ts.
	tsFracOff   int
	tsFracWidth int
	// fracPerSec is how many sub-second units make a second (1e6 for
	// microtime, 1e9 for nanotime). It bounds the value read from the header
	// so a corrupt timestamp cannot overflow the nanosecond arithmetic.
	fracPerSec uint64
	// fracNanos converts one sub-second unit to nanoseconds (1000 for
	// microtime, 1 for nanotime).
	fracNanos int64

	// capLenOff, dataLenOff and hdrLenOff locate bh_caplen (uint32),
	// bh_datalen (uint32) and bh_hdrlen (uint16).
	capLenOff  int
	dataLenOff int
	hdrLenOff  int

	// minHdrLen is the smallest bh_hdrlen that can be valid: enough bytes to
	// hold every field above. A record claiming less is malformed.
	minHdrLen int

	// align is BPF_ALIGNMENT — sizeof(long) on the capturing host.
	align int
}

// bpfRecord is one capture record lifted out of a read(2) chunk. Frame aliases
// the chunk buffer and is only valid until that buffer is reused, so callers
// must decode or copy it before the next read.
type bpfRecord struct {
	// TS is the kernel capture timestamp.
	TS time.Time
	// Frame is the captured link-layer bytes (bh_caplen of them).
	Frame []byte
	// OrigLen is bh_datalen: the frame's length on the wire before the snaplen
	// truncated it. It equals len(Frame) when nothing was cut.
	OrigLen uint32
}

// errBPFChunk is the class of every malformed-chunk error. The read loop counts
// one decode error and keeps going rather than tearing the capture down: a
// short or garbled chunk is untrusted input, not a fatal condition
// (PROJECT.md §28.11).
type errBPFChunk struct{ msg string }

func (e *errBPFChunk) Error() string { return "capture: bpf chunk: " + e.msg }

func chunkErr(format string, a ...any) error {
	return &errBPFChunk{msg: fmt.Sprintf(format, a...)}
}

// bpfWordAlign rounds n up to the next align boundary, mirroring FreeBSD's
// BPF_WORDALIGN. A non-positive or non-power-of-two align degrades to no
// alignment rather than producing a bogus (possibly zero) stride.
func bpfWordAlign(n, align int) int {
	if align <= 1 || align&(align-1) != 0 {
		return n
	}
	return (n + align - 1) &^ (align - 1)
}

// parseBPFChunk splits one read(2) chunk from a BPF device into records,
// appending them to dst (pass a reused slice to keep the packet path
// allocation-free — PROJECT.md §22) and returning the extended slice.
//
// Every record parsed before a problem is still returned, so a chunk whose tail
// is garbage still yields its good packets. A non-nil error means the remainder
// of the chunk could not be trusted and was discarded; it is always an
// *errBPFChunk and is never fatal to the capture.
func parseBPFChunk(dst []bpfRecord, chunk []byte, l bpfHdrLayout) ([]bpfRecord, error) {
	if l.minHdrLen <= 0 || l.order == nil {
		return dst, chunkErr("invalid header layout")
	}

	for off := 0; off < len(chunk); {
		avail := len(chunk) - off
		if avail < l.minHdrLen {
			return dst, chunkErr("trailing %d bytes cannot hold a %d-byte record header", avail, l.minHdrLen)
		}
		hdr := chunk[off:]

		capLen := l.order.Uint32(hdr[l.capLenOff:])
		dataLen := l.order.Uint32(hdr[l.dataLenOff:])
		hdrLen := int(l.order.Uint16(hdr[l.hdrLenOff:]))

		switch {
		case hdrLen < l.minHdrLen:
			return dst, chunkErr("bh_hdrlen %d below the %d-byte minimum at offset %d", hdrLen, l.minHdrLen, off)
		case capLen > maxSnapLen:
			return dst, chunkErr("bh_caplen %d exceeds the %d snaplen ceiling at offset %d", capLen, maxSnapLen, off)
		case hdrLen > avail || int(capLen) > avail-hdrLen:
			return dst, chunkErr("record at offset %d claims %d+%d bytes but only %d remain", off, hdrLen, capLen, avail)
		}

		frameStart := off + hdrLen
		dst = append(dst, bpfRecord{
			TS:      bpfRecordTime(hdr, l),
			Frame:   chunk[frameStart : frameStart+int(capLen)],
			OrigLen: dataLen,
		})

		// The kernel aligns the *start* of every record, so the stride is the
		// aligned header+payload size. It elides the trailing pad after the
		// last record, which simply ends the loop.
		off += bpfWordAlign(hdrLen+int(capLen), l.align)
	}
	return dst, nil
}

// bpfRecordTime decodes bh_tstamp. The sub-second field is reduced modulo
// fracPerSec first so a corrupt header cannot overflow the nanosecond
// multiply (PROJECT.md §28.11).
func bpfRecordTime(hdr []byte, l bpfHdrLayout) time.Time {
	sec := int64(readUintField(hdr, l.order, l.tsSecOff, l.tsSecWidth))
	frac := readUintField(hdr, l.order, l.tsFracOff, l.tsFracWidth)
	if l.fracPerSec > 0 {
		frac %= l.fracPerSec
	}
	return time.Unix(sec, int64(frac)*l.fracNanos).UTC()
}

// readUintField reads a 4- or 8-byte unsigned field; any other width reads 0.
func readUintField(b []byte, order binary.ByteOrder, off, width int) uint64 {
	switch width {
	case 8:
		return order.Uint64(b[off:])
	case 4:
		return uint64(order.Uint32(b[off:]))
	default:
		return 0
	}
}
