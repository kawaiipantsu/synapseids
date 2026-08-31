package nn

import (
	"bytes"
	"math"
	"testing"
)

func encodeVarint(x uint64) []byte {
	var b []byte
	for x >= 0x80 {
		b = append(b, byte(x)|0x80)
		x >>= 7
	}
	return append(b, byte(x))
}

func TestReadVarintRoundTrip(t *testing.T) {
	for _, want := range []uint64{0, 1, 127, 128, 300, 16384, 1 << 35, math.MaxUint64} {
		r := pbReader{buf: encodeVarint(want)}
		got, err := r.readVarint()
		if err != nil || got != want {
			t.Fatalf("varint %d: got %d, err %v", want, got, err)
		}
		if r.more() {
			t.Fatalf("varint %d: %d bytes left over", want, len(r.buf)-r.pos)
		}
	}
}

func TestReadVarintOverlong(t *testing.T) {
	r := pbReader{buf: bytes.Repeat([]byte{0x80}, 12)}
	if _, err := r.readVarint(); err == nil {
		t.Fatal("want error for an over-long varint")
	}
}

func TestReadVarintTruncated(t *testing.T) {
	r := pbReader{buf: []byte{0x80, 0x80}} // continuation bit set, then EOF
	if _, err := r.readVarint(); err == nil {
		t.Fatal("want error for a truncated varint")
	}
}

func TestReadBytesLengthOverrun(t *testing.T) {
	r := pbReader{buf: []byte{0x05, 0x01, 0x02}} // says 5 bytes, only 2 follow
	if _, err := r.readBytes(); err == nil {
		t.Fatal("want error when a length-delimited field overruns the buffer")
	}
}

func TestSkipUnknownWireTypes(t *testing.T) {
	// group-start (3) is unused by ONNX and must be refused, not skipped silently.
	r := pbReader{buf: []byte{0x00}}
	if err := r.skip(3); err == nil {
		t.Fatal("want error skipping a group wire type")
	}
}

func TestPackedHelpers(t *testing.T) {
	if _, err := packedFloat32([]byte{0x00, 0x01}); err == nil {
		t.Fatal("packedFloat32 must reject a non-multiple-of-4 payload")
	}
	got, err := packedVarints(append(encodeVarint(1), encodeVarint(300)...))
	if err != nil || len(got) != 2 || got[0] != 1 || got[1] != 300 {
		t.Fatalf("packedVarints = %v, err %v", got, err)
	}
}
