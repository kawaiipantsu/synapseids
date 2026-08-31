package nn

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// pbReader is a minimal protobuf wire-format decoder over an in-memory buffer. It
// implements just enough of https://protobuf.dev/programming-guides/encoding/ to
// walk an ONNX ModelProto: varints, length-delimited fields and the two
// fixed-width forms. Every method is bounds-checked and returns an error rather
// than panicking on malformed input (§28.11 spirit).
type pbReader struct {
	buf []byte
	pos int
}

// protobuf wire types (start/end group, 3 and 4, are deprecated and unused by ONNX).
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// pbMaxVarintBytes caps a varint at 10 bytes (64 bits / 7 bits per byte, rounded up).
const pbMaxVarintBytes = 10

func (r *pbReader) more() bool { return r.pos < len(r.buf) }

func (r *pbReader) readVarint() (uint64, error) {
	var x uint64
	var shift uint
	for i := 0; ; i++ {
		if i >= pbMaxVarintBytes {
			return 0, fmt.Errorf("nn: protobuf varint longer than %d bytes", pbMaxVarintBytes)
		}
		if r.pos >= len(r.buf) {
			return 0, io.ErrUnexpectedEOF
		}
		b := r.buf[r.pos]
		r.pos++
		x |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return x, nil
		}
		shift += 7
	}
}

// readTag reads a field key and splits it into field number and wire type.
func (r *pbReader) readTag() (field, wire int, err error) {
	key, err := r.readVarint()
	if err != nil {
		return 0, 0, err
	}
	field = int(key >> 3)
	wire = int(key & 7)
	if field <= 0 {
		return 0, 0, fmt.Errorf("nn: protobuf field number %d out of range", field)
	}
	return field, wire, nil
}

// readBytes reads a length-delimited field body. The returned slice aliases the
// underlying buffer; callers that retain it must copy.
func (r *pbReader) readBytes() ([]byte, error) {
	n, err := r.readVarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.buf)-r.pos) {
		return nil, fmt.Errorf("nn: protobuf field wants %d bytes, only %d remain", n, len(r.buf)-r.pos)
	}
	start := r.pos
	r.pos += int(n)
	return r.buf[start:r.pos], nil
}

func (r *pbReader) readFixed32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *pbReader) readFixed64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// skip advances past a field body of the given wire type.
func (r *pbReader) skip(wire int) error {
	switch wire {
	case wireVarint:
		_, err := r.readVarint()
		return err
	case wireFixed64:
		_, err := r.readFixed64()
		return err
	case wireBytes:
		_, err := r.readBytes()
		return err
	case wireFixed32:
		_, err := r.readFixed32()
		return err
	default:
		return fmt.Errorf("nn: unsupported protobuf wire type %d", wire)
	}
}

// packedFloat32 decodes a packed repeated float payload (a run of little-endian fixed32s).
func packedFloat32(b []byte) ([]float32, error) {
	if len(b)%4 != 0 {
		return nil, fmt.Errorf("nn: packed float32 payload of %d bytes is not a multiple of 4", len(b))
	}
	out := make([]float32, len(b)/4)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return out, nil
}

// packedVarints decodes a packed repeated varint payload (int32 / int64 fields).
func packedVarints(b []byte) ([]int64, error) {
	r := pbReader{buf: b}
	var out []int64
	for r.more() {
		v, err := r.readVarint()
		if err != nil {
			return nil, err
		}
		out = append(out, int64(v))
	}
	return out, nil
}
