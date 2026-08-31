package nn

import (
	"encoding/binary"
	"fmt"
	"math"
)

// attrTENSOR is the ONNX AttributeProto.AttributeType value for a tensor payload
// (used to sanity-check a Constant node's "value" attribute).
const attrTENSOR = 4

// ONNX TensorProto.DataType values this reader can materialize. Anything else
// (FLOAT16, BFLOAT16, DOUBLE, unsigned, complex, string, bool) is a hard error.
const (
	dtFLOAT = 1
	dtINT32 = 6
	dtINT64 = 7
)

// onnxModel is the decoded subset of an ONNX ModelProto.
type onnxModel struct {
	graph onnxGraph
}

// onnxGraph is the decoded subset of a GraphProto.
type onnxGraph struct {
	nodes        []onnxNode
	initializers []onnxTensor
	inputs       []onnxValueInfo
	outputs      []onnxValueInfo
}

// onnxNode is the decoded subset of a NodeProto.
type onnxNode struct {
	name   string
	opType string
	input  []string
	output []string
	attrs  []onnxAttr
}

// onnxAttr is the decoded subset of an AttributeProto.
type onnxAttr struct {
	name   string
	typ    int64
	f      float32
	i      int64
	floats []float32
	ints   []int64
	t      *onnxTensor
}

// onnxTensor is the decoded subset of a TensorProto.
type onnxTensor struct {
	name      string
	dims      []int64
	dataType  int32
	floatData []float32
	int32Data []int32
	int64Data []int64
	rawData   []byte
}

// onnxValueInfo is the decoded subset of a ValueInfoProto: a name and, when the
// model carries shape information, the tensor dimensions (a non-positive value
// marks a symbolic / dynamic dimension).
type onnxValueInfo struct {
	name     string
	shape    []int64
	hasShape bool
}

// parseModel decodes a ModelProto. Fields other than ir_version (1) and graph (7)
// are skipped.
func parseModel(b []byte) (*onnxModel, error) {
	m := &onnxModel{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		switch {
		case field == 7 && wire == wireBytes: // graph
			gb, err := r.readBytes()
			if err != nil {
				return nil, err
			}
			g, err := parseGraph(gb)
			if err != nil {
				return nil, err
			}
			m.graph = *g
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

func parseGraph(b []byte) (*onnxGraph, error) {
	g := &onnxGraph{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		if wire != wireBytes {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		body, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1: // node
			n, err := parseNode(body)
			if err != nil {
				return nil, err
			}
			g.nodes = append(g.nodes, *n)
		case 5: // initializer
			t, err := parseTensor(body)
			if err != nil {
				return nil, err
			}
			g.initializers = append(g.initializers, *t)
		case 11: // input
			vi, err := parseValueInfo(body)
			if err != nil {
				return nil, err
			}
			g.inputs = append(g.inputs, *vi)
		case 12: // output
			vi, err := parseValueInfo(body)
			if err != nil {
				return nil, err
			}
			g.outputs = append(g.outputs, *vi)
		default: // value_info, doc_string, sparse_initializer, quantization... ignored
		}
	}
	return g, nil
}

func parseNode(b []byte) (*onnxNode, error) {
	n := &onnxNode{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		if wire != wireBytes {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		body, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1:
			n.input = append(n.input, string(body))
		case 2:
			n.output = append(n.output, string(body))
		case 3:
			n.name = string(body)
		case 4:
			n.opType = string(body)
		case 5:
			a, err := parseAttr(body)
			if err != nil {
				return nil, err
			}
			n.attrs = append(n.attrs, *a)
		default: // domain (7), doc_string (6), overload... ignored
		}
	}
	return n, nil
}

func parseAttr(b []byte) (*onnxAttr, error) {
	a := &onnxAttr{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wire == wireBytes: // name
			body, err := r.readBytes()
			if err != nil {
				return nil, err
			}
			a.name = string(body)
		case field == 20 && wire == wireVarint: // type
			v, err := r.readVarint()
			if err != nil {
				return nil, err
			}
			a.typ = int64(v)
		case field == 2 && wire == wireFixed32: // f
			v, err := r.readFixed32()
			if err != nil {
				return nil, err
			}
			a.f = math.Float32frombits(v)
		case field == 3 && wire == wireVarint: // i
			v, err := r.readVarint()
			if err != nil {
				return nil, err
			}
			a.i = int64(v)
		case field == 5 && wire == wireBytes: // t (tensor)
			body, err := r.readBytes()
			if err != nil {
				return nil, err
			}
			t, err := parseTensor(body)
			if err != nil {
				return nil, err
			}
			a.t = t
		case field == 7: // floats
			if err := readRepeatedFloat(&r, wire, &a.floats); err != nil {
				return nil, err
			}
		case field == 8: // ints
			if err := readRepeatedVarint(&r, wire, &a.ints); err != nil {
				return nil, err
			}
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}

func parseTensor(b []byte) (*onnxTensor, error) {
	t := &onnxTensor{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		switch {
		case field == 1: // dims
			if err := readRepeatedVarint(&r, wire, &t.dims); err != nil {
				return nil, err
			}
		case field == 2 && wire == wireVarint: // data_type
			v, err := r.readVarint()
			if err != nil {
				return nil, err
			}
			t.dataType = int32(v)
		case field == 4: // float_data
			if err := readRepeatedFloat(&r, wire, &t.floatData); err != nil {
				return nil, err
			}
		case field == 5: // int32_data
			var tmp []int64
			if err := readRepeatedVarint(&r, wire, &tmp); err != nil {
				return nil, err
			}
			for _, v := range tmp {
				t.int32Data = append(t.int32Data, int32(v))
			}
		case field == 7: // int64_data
			if err := readRepeatedVarint(&r, wire, &t.int64Data); err != nil {
				return nil, err
			}
		case field == 8 && wire == wireBytes: // name
			body, err := r.readBytes()
			if err != nil {
				return nil, err
			}
			t.name = string(body)
		case field == 9 && wire == wireBytes: // raw_data
			body, err := r.readBytes()
			if err != nil {
				return nil, err
			}
			t.rawData = append([]byte(nil), body...)
		default: // segment, string_data, double_data, uint64_data, external_data... ignored
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
	return t, nil
}

func parseValueInfo(b []byte) (*onnxValueInfo, error) {
	vi := &onnxValueInfo{}
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, err
		}
		if wire != wireBytes {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		body, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		switch field {
		case 1: // name
			vi.name = string(body)
		case 2: // type (TypeProto)
			shape, ok, err := parseTypeShape(body)
			if err != nil {
				return nil, err
			}
			if ok {
				vi.shape = shape
				vi.hasShape = true
			}
		}
	}
	return vi, nil
}

// parseTypeShape walks TypeProto -> Tensor -> TensorShapeProto and returns the
// dimension list. ok is false when the model carries no shape for this value.
func parseTypeShape(b []byte) (dims []int64, ok bool, err error) {
	// TypeProto: tensor_type is field 1.
	tt, ok, err := nestedBytesField(b, 1)
	if err != nil || !ok {
		return nil, false, err
	}
	// TypeProto.Tensor: shape is field 2.
	sh, ok, err := nestedBytesField(tt, 2)
	if err != nil || !ok {
		return nil, false, err
	}
	// TensorShapeProto: dim is repeated field 1.
	r := pbReader{buf: sh}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, false, err
		}
		if field == 1 && wire == wireBytes {
			dimBody, err := r.readBytes()
			if err != nil {
				return nil, false, err
			}
			dv, err := parseDimension(dimBody)
			if err != nil {
				return nil, false, err
			}
			dims = append(dims, dv)
			continue
		}
		if err := r.skip(wire); err != nil {
			return nil, false, err
		}
	}
	return dims, true, nil
}

// parseDimension reads a TensorShapeProto.Dimension, returning dim_value or -1
// when the dimension is symbolic (dim_param) or unset.
func parseDimension(b []byte) (int64, error) {
	val := int64(-1)
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return 0, err
		}
		if field == 1 && wire == wireVarint {
			v, err := r.readVarint()
			if err != nil {
				return 0, err
			}
			val = int64(v)
			continue
		}
		if err := r.skip(wire); err != nil {
			return 0, err
		}
	}
	return val, nil
}

// nestedBytesField returns the body of the first length-delimited field with the
// given number inside b.
func nestedBytesField(b []byte, want int) (body []byte, ok bool, err error) {
	r := pbReader{buf: b}
	for r.more() {
		field, wire, err := r.readTag()
		if err != nil {
			return nil, false, err
		}
		if field == want && wire == wireBytes {
			body, err := r.readBytes()
			return body, err == nil, err
		}
		if err := r.skip(wire); err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

// readRepeatedFloat appends one float (wireFixed32) or a packed run (wireBytes) to dst.
func readRepeatedFloat(r *pbReader, wire int, dst *[]float32) error {
	switch wire {
	case wireBytes:
		body, err := r.readBytes()
		if err != nil {
			return err
		}
		fs, err := packedFloat32(body)
		if err != nil {
			return err
		}
		*dst = append(*dst, fs...)
	case wireFixed32:
		v, err := r.readFixed32()
		if err != nil {
			return err
		}
		*dst = append(*dst, math.Float32frombits(v))
	default:
		return r.skip(wire)
	}
	return nil
}

// readRepeatedVarint appends one varint (wireVarint) or a packed run (wireBytes) to dst.
func readRepeatedVarint(r *pbReader, wire int, dst *[]int64) error {
	switch wire {
	case wireBytes:
		body, err := r.readBytes()
		if err != nil {
			return err
		}
		vs, err := packedVarints(body)
		if err != nil {
			return err
		}
		*dst = append(*dst, vs...)
	case wireVarint:
		v, err := r.readVarint()
		if err != nil {
			return err
		}
		*dst = append(*dst, int64(v))
	default:
		return r.skip(wire)
	}
	return nil
}

// materialize converts a decoded initializer / attribute tensor into a float32
// tensor. Only float32 (and int32 / int64 for shape operands, cast to float32)
// are supported; any other data_type is a hard error so a model is never run
// with silently wrong weights (§28.11).
func (o *onnxTensor) materialize() (*tensor, error) {
	shape := make([]int, len(o.dims))
	n := 1
	for i, d := range o.dims {
		if d < 0 {
			return nil, fmt.Errorf("nn: initializer %q has negative dim %d", o.name, d)
		}
		shape[i] = int(d)
		n *= int(d)
	}

	var data []float32
	switch o.dataType {
	case dtFLOAT:
		if len(o.rawData) > 0 {
			d, err := rawFloat32(o.name, o.rawData)
			if err != nil {
				return nil, err
			}
			data = d
		} else {
			data = append([]float32(nil), o.floatData...)
		}
	case dtINT64:
		src := o.int64Data
		if len(o.rawData) > 0 {
			if len(o.rawData)%8 != 0 {
				return nil, fmt.Errorf("nn: initializer %q raw_data of %d bytes is not a multiple of 8", o.name, len(o.rawData))
			}
			src = make([]int64, len(o.rawData)/8)
			for i := range src {
				src[i] = int64(binary.LittleEndian.Uint64(o.rawData[i*8:]))
			}
		}
		data = make([]float32, len(src))
		for i, v := range src {
			data[i] = float32(v)
		}
	case dtINT32:
		src := o.int32Data
		if len(o.rawData) > 0 {
			if len(o.rawData)%4 != 0 {
				return nil, fmt.Errorf("nn: initializer %q raw_data of %d bytes is not a multiple of 4", o.name, len(o.rawData))
			}
			src = make([]int32, len(o.rawData)/4)
			for i := range src {
				src[i] = int32(binary.LittleEndian.Uint32(o.rawData[i*4:]))
			}
		}
		data = make([]float32, len(src))
		for i, v := range src {
			data[i] = float32(v)
		}
	default:
		return nil, fmt.Errorf("nn: initializer %q has unsupported data_type %d (only float32, int32 and int64 are supported — re-export weights as float32)", o.name, o.dataType)
	}

	if len(o.dims) == 0 {
		return &tensor{data: data, shape: nil}, nil
	}
	if n != len(data) {
		return nil, fmt.Errorf("nn: initializer %q shape %v implies %d values but carries %d", o.name, shape, n, len(data))
	}
	return &tensor{data: data, shape: shape}, nil
}

func rawFloat32(name string, raw []byte) ([]float32, error) {
	if len(raw)%4 != 0 {
		return nil, fmt.Errorf("nn: initializer %q raw_data of %d bytes is not a multiple of 4", name, len(raw))
	}
	out := make([]float32, len(raw)/4)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
	}
	return out, nil
}
