package capture

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

// lp64MicroLayout is the record header a FreeBSD amd64/arm64 kernel writes with
// the default BPF_T_MICROTIME timestamp format: struct timeval {int64, int64},
// then bh_caplen, bh_datalen, bh_hdrlen, on an 8-byte alignment.
func lp64MicroLayout() bpfHdrLayout {
	return bpfHdrLayout{
		order:       binary.LittleEndian,
		tsSecOff:    0,
		tsSecWidth:  8,
		tsFracOff:   8,
		tsFracWidth: 8,
		fracPerSec:  1e6,
		fracNanos:   1000,
		capLenOff:   16,
		dataLenOff:  20,
		hdrLenOff:   24,
		minHdrLen:   26,
		align:       8,
	}
}

// lp64NanoLayout is the struct bpf_xhdr form (BPF_T_NANOTIME). The field
// offsets are identical under LP64 — struct bpf_ts is also 16 bytes — only the
// sub-second unit differs.
func lp64NanoLayout() bpfHdrLayout {
	l := lp64MicroLayout()
	l.fracPerSec = 1e9
	l.fracNanos = 1
	return l
}

// ilp32Layout models a 32-bit BSD: 4-byte BPF_ALIGNMENT and a 32-bit
// sub-second field. It exists to prove the parser is not hard-wired to LP64.
func ilp32Layout() bpfHdrLayout {
	return bpfHdrLayout{
		order:       binary.LittleEndian,
		tsSecOff:    0,
		tsSecWidth:  8,
		tsFracOff:   8,
		tsFracWidth: 4,
		fracPerSec:  1e6,
		fracNanos:   1000,
		capLenOff:   12,
		dataLenOff:  16,
		hdrLenOff:   20,
		minHdrLen:   22,
		align:       4,
	}
}

// recOpt tweaks a synthesised record so a test can make it malformed.
type recOpt struct {
	hdrLen  int  // 0 = the aligned natural header length
	capLen  int  // -1 = len(frame)
	dataLen int  // -1 = len(frame)
	noPad   bool // omit the trailing alignment padding (as the kernel does for the last record)
	order   binary.ByteOrder
}

// buildRecord synthesises one BPF record exactly as the kernel lays it out.
func buildRecord(l bpfHdrLayout, sec int64, frac uint64, frame []byte, opt recOpt) []byte {
	order := opt.order
	if order == nil {
		order = l.order
	}
	hdrLen := opt.hdrLen
	if hdrLen == 0 {
		hdrLen = bpfWordAlign(l.minHdrLen, l.align)
	}
	capLen := opt.capLen
	if capLen < 0 {
		capLen = len(frame)
	}
	dataLen := opt.dataLen
	if dataLen < 0 {
		dataLen = len(frame)
	}

	size := hdrLen + len(frame)
	total := size
	if !opt.noPad {
		total = bpfWordAlign(size, l.align)
	}
	// A deliberately short bh_hdrlen still needs a buffer big enough to hold
	// the fields the parser reads.
	if n := l.minHdrLen; total < n {
		total = n
	}
	buf := make([]byte, total)

	putUint(buf, order, l.tsSecOff, l.tsSecWidth, uint64(sec))
	putUint(buf, order, l.tsFracOff, l.tsFracWidth, frac)
	order.PutUint32(buf[l.capLenOff:], uint32(capLen))
	order.PutUint32(buf[l.dataLenOff:], uint32(dataLen))
	order.PutUint16(buf[l.hdrLenOff:], uint16(hdrLen))
	if hdrLen <= len(buf) {
		copy(buf[hdrLen:], frame)
	}
	return buf
}

func putUint(b []byte, order binary.ByteOrder, off, width int, v uint64) {
	switch width {
	case 8:
		order.PutUint64(b[off:], v)
	case 4:
		order.PutUint32(b[off:], uint32(v))
	}
}

func TestParseBPFChunkSingleRecord(t *testing.T) {
	l := lp64MicroLayout()
	frame := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}
	chunk := buildRecord(l, 1_700_000_000, 123_456, frame, recOpt{capLen: -1, dataLen: -1})

	recs, err := parseBPFChunk(nil, chunk, l)
	if err != nil {
		t.Fatalf("parseBPFChunk: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	want := time.Unix(1_700_000_000, 123_456_000).UTC()
	if !recs[0].TS.Equal(want) {
		t.Errorf("TS = %v, want %v", recs[0].TS, want)
	}
	if !bytes.Equal(recs[0].Frame, frame) {
		t.Errorf("Frame = % x, want % x", recs[0].Frame, frame)
	}
	if recs[0].OrigLen != uint32(len(frame)) {
		t.Errorf("OrigLen = %d, want %d", recs[0].OrigLen, len(frame))
	}
}

// The whole point of the parser: one read(2) returns many packets, each padded
// up to BPF_WORDALIGN, and the kernel elides the pad after the final one.
func TestParseBPFChunkSplitsManyRecords(t *testing.T) {
	l := lp64MicroLayout()
	frames := [][]byte{
		bytes.Repeat([]byte{0xaa}, 60),
		bytes.Repeat([]byte{0xbb}, 1),   // forces 7 bytes of padding
		bytes.Repeat([]byte{0xcc}, 64),  // already aligned: no padding
		bytes.Repeat([]byte{0xdd}, 129), // odd length again
	}
	var chunk []byte
	for i, f := range frames {
		last := i == len(frames)-1
		chunk = append(chunk, buildRecord(l, int64(1000+i), uint64(i), f, recOpt{
			capLen: -1, dataLen: -1, noPad: last,
		})...)
	}

	recs, err := parseBPFChunk(nil, chunk, l)
	if err != nil {
		t.Fatalf("parseBPFChunk: %v", err)
	}
	if len(recs) != len(frames) {
		t.Fatalf("got %d records, want %d", len(recs), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(recs[i].Frame, f) {
			t.Errorf("record %d frame = % x…, want % x…", i, recs[i].Frame[:4], f[:4])
		}
		if want := time.Unix(int64(1000+i), int64(i)*1000).UTC(); !recs[i].TS.Equal(want) {
			t.Errorf("record %d TS = %v, want %v", i, recs[i].TS, want)
		}
	}
}

// A snaplen-truncated record reports the on-wire length in bh_datalen while
// only carrying bh_caplen bytes.
func TestParseBPFChunkTruncatedBySnaplen(t *testing.T) {
	l := lp64MicroLayout()
	frame := bytes.Repeat([]byte{0x5a}, 96)
	chunk := buildRecord(l, 5, 0, frame, recOpt{capLen: -1, dataLen: 1514})

	recs, err := parseBPFChunk(nil, chunk, l)
	if err != nil {
		t.Fatalf("parseBPFChunk: %v", err)
	}
	if len(recs) != 1 || len(recs[0].Frame) != 96 || recs[0].OrigLen != 1514 {
		t.Fatalf("got %d records, frame %d bytes, OrigLen %d; want 1 record, 96 bytes, OrigLen 1514",
			len(recs), len(recs[0].Frame), recs[0].OrigLen)
	}
}

func TestParseBPFChunkMalformed(t *testing.T) {
	l := lp64MicroLayout()
	good := buildRecord(l, 7, 7, bytes.Repeat([]byte{0x11}, 32), recOpt{capLen: -1, dataLen: -1})

	tests := []struct {
		name      string
		chunk     []byte
		wantRecs  int
		wantError bool
	}{
		{
			name:      "empty chunk",
			chunk:     nil,
			wantRecs:  0,
			wantError: false,
		},
		{
			name:      "trailing bytes too short for a header",
			chunk:     append(append([]byte{}, good...), 1, 2, 3, 4, 5),
			wantRecs:  1,
			wantError: true,
		},
		{
			name:      "header shorter than the fields it must contain",
			chunk:     buildRecord(l, 1, 1, []byte{0xff}, recOpt{hdrLen: 8, capLen: -1, dataLen: -1}),
			wantRecs:  0,
			wantError: true,
		},
		{
			name:      "bh_caplen beyond the snaplen ceiling",
			chunk:     buildRecord(l, 1, 1, []byte{0xff}, recOpt{capLen: maxSnapLen + 1, dataLen: -1}),
			wantRecs:  0,
			wantError: true,
		},
		{
			name:      "bh_caplen runs past the end of the chunk",
			chunk:     buildRecord(l, 1, 1, []byte{0xff}, recOpt{capLen: 4096, dataLen: -1}),
			wantRecs:  0,
			wantError: true,
		},
		{
			name:      "bh_hdrlen runs past the end of the chunk",
			chunk:     buildRecord(l, 1, 1, []byte{0xff}, recOpt{hdrLen: 4096, capLen: 0, dataLen: 0})[:64],
			wantRecs:  0,
			wantError: true,
		},
		{
			name:      "good record followed by a garbage one",
			chunk:     append(append([]byte{}, good...), buildRecord(l, 1, 1, []byte{0xff}, recOpt{capLen: 9999, dataLen: -1})...),
			wantRecs:  1,
			wantError: true,
		},
		{
			// The stride is the *aligned* header+payload size, so bytes that
			// fall inside a record's alignment padding are padding, not a
			// truncated next record. libpcap advances the same way.
			name:      "stray bytes inside the alignment pad are ignored",
			chunk:     append(buildRecord(l, 1, 1, []byte{0xff, 0xfe, 0xfd}, recOpt{capLen: -1, dataLen: -1, noPad: true}), 0x00, 0x00),
			wantRecs:  1,
			wantError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := parseBPFChunk(nil, tc.chunk, l)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError = %v", err, tc.wantError)
			}
			if len(recs) != tc.wantRecs {
				t.Fatalf("got %d records, want %d", len(recs), tc.wantRecs)
			}
			// Whatever came back must be self-consistent, never a slice that
			// escapes the chunk.
			for _, r := range recs {
				if len(r.Frame) > len(tc.chunk) {
					t.Fatalf("record frame of %d bytes exceeds the %d-byte chunk", len(r.Frame), len(tc.chunk))
				}
			}
		})
	}
}

func TestParseBPFChunkRejectsBadLayout(t *testing.T) {
	l := lp64MicroLayout()
	chunk := buildRecord(l, 1, 1, []byte{0xff}, recOpt{capLen: -1, dataLen: -1})

	if _, err := parseBPFChunk(nil, chunk, bpfHdrLayout{order: binary.LittleEndian}); err == nil {
		t.Error("a layout with minHdrLen 0 must be rejected")
	}
	bad := l
	bad.order = nil
	if _, err := parseBPFChunk(nil, chunk, bad); err == nil {
		t.Error("a layout without a byte order must be rejected")
	}
}

// A corrupt sub-second field must not overflow the nanosecond multiply.
func TestParseBPFChunkClampsSubSecond(t *testing.T) {
	l := lp64MicroLayout()
	chunk := buildRecord(l, 100, ^uint64(0), []byte{0x01}, recOpt{capLen: -1, dataLen: -1})

	recs, err := parseBPFChunk(nil, chunk, l)
	if err != nil {
		t.Fatalf("parseBPFChunk: %v", err)
	}
	got := recs[0].TS
	// ^uint64(0) % 1e6 = 615 (2^64-1 mod 10^6), so the timestamp stays inside
	// the second it claims rather than wrapping into 1754.
	if got.Unix() != 100 {
		t.Fatalf("TS = %v, want a timestamp inside second 100", got)
	}
	if got.Nanosecond() >= int(time.Second/time.Nanosecond) {
		t.Fatalf("nanosecond field %d is out of range", got.Nanosecond())
	}
}

func TestParseBPFChunkAlternateLayouts(t *testing.T) {
	t.Run("nanotime", func(t *testing.T) {
		l := lp64NanoLayout()
		chunk := buildRecord(l, 42, 999_999_999, []byte{0xab, 0xcd}, recOpt{capLen: -1, dataLen: -1})
		recs, err := parseBPFChunk(nil, chunk, l)
		if err != nil {
			t.Fatalf("parseBPFChunk: %v", err)
		}
		if want := time.Unix(42, 999_999_999).UTC(); !recs[0].TS.Equal(want) {
			t.Fatalf("TS = %v, want %v", recs[0].TS, want)
		}
	})

	t.Run("ilp32", func(t *testing.T) {
		l := ilp32Layout()
		a := buildRecord(l, 1, 500_000, bytes.Repeat([]byte{0x01}, 3), recOpt{capLen: -1, dataLen: -1})
		b := buildRecord(l, 2, 0, bytes.Repeat([]byte{0x02}, 5), recOpt{capLen: -1, dataLen: -1, noPad: true})
		recs, err := parseBPFChunk(nil, append(a, b...), l)
		if err != nil {
			t.Fatalf("parseBPFChunk: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("got %d records, want 2", len(recs))
		}
		if want := time.Unix(1, 500_000_000).UTC(); !recs[0].TS.Equal(want) {
			t.Errorf("TS = %v, want %v", recs[0].TS, want)
		}
	})

	t.Run("big endian", func(t *testing.T) {
		l := lp64MicroLayout()
		l.order = binary.BigEndian
		chunk := buildRecord(l, 9, 1, []byte{0x77}, recOpt{capLen: -1, dataLen: -1})
		recs, err := parseBPFChunk(nil, chunk, l)
		if err != nil {
			t.Fatalf("parseBPFChunk: %v", err)
		}
		if len(recs) != 1 || recs[0].Frame[0] != 0x77 {
			t.Fatalf("big-endian header did not round-trip: %+v", recs)
		}
	})
}

// The read loop reuses one record slice per read to stay off the allocator
// (PROJECT.md §22), so appending into a non-empty slice must work.
func TestParseBPFChunkAppendsToDst(t *testing.T) {
	l := lp64MicroLayout()
	chunk := buildRecord(l, 1, 1, []byte{0x01, 0x02}, recOpt{capLen: -1, dataLen: -1})

	dst := make([]bpfRecord, 0, 8)
	dst, err := parseBPFChunk(dst, chunk, l)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	dst, err = parseBPFChunk(dst, chunk, l)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(dst) != 2 {
		t.Fatalf("got %d records after two parses, want 2", len(dst))
	}
	if cap(dst) != 8 {
		t.Errorf("dst reallocated (cap %d); the read loop should reuse its buffer", cap(dst))
	}
}

func TestBPFWordAlign(t *testing.T) {
	for _, tc := range []struct{ n, align, want int }{
		{0, 8, 0},
		{1, 8, 8},
		{8, 8, 8},
		{9, 8, 16},
		{26, 8, 32}, // SIZEOF_BPF_HDR under LP64 -> the real bh_hdrlen
		{22, 4, 24},
		{5, 1, 5},  // no alignment
		{5, 0, 5},  // degenerate align
		{5, 3, 5},  // not a power of two
		{5, -8, 5}, // negative
	} {
		if got := bpfWordAlign(tc.n, tc.align); got != tc.want {
			t.Errorf("bpfWordAlign(%d, %d) = %d, want %d", tc.n, tc.align, got, tc.want)
		}
	}
}

// Packet-derived bytes are untrusted (PROJECT.md §28.11): random and mutated
// input must be rejected or parsed, never panic.
func TestParseBPFChunkNeverPanicsOnRandomInput(t *testing.T) {
	l := lp64MicroLayout()
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test input, not crypto

	base := buildRecord(l, 1, 1, bytes.Repeat([]byte{0x42}, 48), recOpt{capLen: -1, dataLen: -1})
	for i := range 2000 {
		chunk := make([]byte, len(base))
		copy(chunk, base)
		// Half random noise, half single-byte mutations of a valid record.
		if i%2 == 0 {
			chunk = make([]byte, rng.Intn(200))
			rng.Read(chunk)
		} else {
			chunk[rng.Intn(len(chunk))] = byte(rng.Intn(256))
		}
		recs, _ := parseBPFChunk(nil, chunk, l)
		for _, r := range recs {
			_ = r.TS
			_ = len(r.Frame)
		}
	}
}

func FuzzParseBPFChunk(f *testing.F) {
	l := lp64MicroLayout()
	f.Add(buildRecord(l, 1, 1, []byte{0x01, 0x02, 0x03}, recOpt{capLen: -1, dataLen: -1}))
	f.Add(buildRecord(l, 0, 0, nil, recOpt{capLen: -1, dataLen: -1}))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, chunk []byte) {
		recs, _ := parseBPFChunk(nil, chunk, l)
		for _, r := range recs {
			if len(r.Frame) > len(chunk) {
				t.Fatalf("frame of %d bytes escaped a %d-byte chunk", len(r.Frame), len(chunk))
			}
		}
	})
}
