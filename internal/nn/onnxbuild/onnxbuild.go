// Package onnxbuild constructs small ONNX ModelProto files. It writes the same
// protobuf-wire subset that internal/nn reads, so tests can build a network with
// known weights (and hand-compute the expected output) and the fixture
// generator can regenerate internal/nn/testdata/model.onnx.
//
// It is test / tooling infrastructure: internal/nn never imports it.
package onnxbuild

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ONNX AttributeProto.AttributeType values.
const (
	AttrFloat  = 1
	AttrInt    = 2
	AttrTensor = 4
	AttrFloats = 6
	AttrInts   = 7
)

// Tensor is a float32 initializer; it is written as raw_data (little-endian).
type Tensor struct {
	Name string
	Dims []int64
	Data []float32
}

// Int64Tensor is an int64 initializer (e.g. a Reshape target shape).
type Int64Tensor struct {
	Name string
	Dims []int64
	Data []int64
}

// Attr is one node attribute. Set the field that matches Type.
type Attr struct {
	Name   string
	Type   int
	F      float32
	I      int64
	Floats []float32
	Ints   []int64
	Tensor *Tensor
}

// Node is one graph node.
type Node struct {
	Op      string
	Name    string
	Inputs  []string
	Outputs []string
	Attrs   []Attr
}

// ValueInfo names a graph input or output. A non-positive dim is written as a
// symbolic dimension (no dim_value).
type ValueInfo struct {
	Name string
	Dims []int64
}

// Graph is a whole model: inputs, outputs, initializers and nodes.
type Graph struct {
	Name      string
	Inputs    []ValueInfo
	Outputs   []ValueInfo
	Floats    []Tensor
	Int64s    []Int64Tensor
	Nodes     []Node
	IRVersion int64 // 0 => 7
	OpsetVer  int64 // 0 => 13
}

// Layer is one dense layer of an MLP: a Gemm(transB=1) with weight W ([out][in])
// and bias B ([out]), then the named activation ("", "Relu", "LeakyRelu",
// "Sigmoid", "Tanh").
type Layer struct {
	W          [][]float32
	B          []float32
	Activation string
}

// MLP builds a feed-forward classifier: input -> (Gemm, activation)* -> optional
// Softmax -> output, with fully specified [1, n] input and output shapes.
func MLP(inSize int, layers []Layer, finalSoftmax bool) Graph {
	g := Graph{Name: "mlp"}
	g.Inputs = []ValueInfo{{Name: "input", Dims: []int64{1, int64(inSize)}}}
	cur := "input"
	prev := inSize
	for li, l := range layers {
		out := len(l.W)
		wName := fmt.Sprintf("W%d", li)
		bName := fmt.Sprintf("B%d", li)
		g.Floats = append(g.Floats,
			Tensor{Name: wName, Dims: []int64{int64(out), int64(prev)}, Data: flatten(l.W)},
			Tensor{Name: bName, Dims: []int64{int64(out)}, Data: append([]float32(nil), l.B...)},
		)
		gemmOut := fmt.Sprintf("gemm%d", li)
		g.Nodes = append(g.Nodes, Node{
			Op: "Gemm", Name: gemmOut,
			Inputs:  []string{cur, wName, bName},
			Outputs: []string{gemmOut},
			Attrs: []Attr{
				{Name: "alpha", Type: AttrFloat, F: 1},
				{Name: "beta", Type: AttrFloat, F: 1},
				{Name: "transB", Type: AttrInt, I: 1},
			},
		})
		cur = gemmOut
		if l.Activation != "" {
			actOut := fmt.Sprintf("act%d", li)
			g.Nodes = append(g.Nodes, Node{Op: l.Activation, Name: actOut, Inputs: []string{cur}, Outputs: []string{actOut}})
			cur = actOut
		}
		prev = out
	}
	if finalSoftmax {
		g.Nodes = append(g.Nodes, Node{
			Op: "Softmax", Name: "softmax",
			Inputs: []string{cur}, Outputs: []string{"output"},
			Attrs: []Attr{{Name: "axis", Type: AttrInt, I: 1}},
		})
	} else if len(g.Nodes) > 0 {
		g.Nodes[len(g.Nodes)-1].Outputs[0] = "output"
	}
	g.Outputs = []ValueInfo{{Name: "output", Dims: []int64{1, int64(prev)}}}
	return g
}

// Unary builds input[1,size] -> op -> output[1,size], with the given attributes.
func Unary(size int, op string, attrs ...Attr) Graph {
	return Graph{
		Name:    op,
		Inputs:  []ValueInfo{{Name: "input", Dims: []int64{1, int64(size)}}},
		Outputs: []ValueInfo{{Name: "output", Dims: []int64{1, int64(size)}}},
		Nodes:   []Node{{Op: op, Name: op, Inputs: []string{"input"}, Outputs: []string{"output"}, Attrs: attrs}},
	}
}

func flatten(w [][]float32) []float32 {
	var out []float32
	for _, row := range w {
		out = append(out, row...)
	}
	return out
}

// Encode serializes the graph as ONNX ModelProto bytes.
func (g Graph) Encode() []byte {
	ir := g.IRVersion
	if ir == 0 {
		ir = 7
	}
	opset := g.OpsetVer
	if opset == 0 {
		opset = 13
	}
	var w encbuf
	w.varintField(1, uint64(ir)) // ir_version
	var ops encbuf
	ops.varintField(2, uint64(opset)) // OperatorSetIdProto.version (default domain "")
	w.bytesField(8, ops.b)            // opset_import
	w.stringField(2, "synapseids-onnxbuild")
	w.bytesField(7, encodeGraph(g)) // graph
	return w.b
}

func encodeGraph(g Graph) []byte {
	var w encbuf
	for _, n := range g.Nodes {
		w.bytesField(1, encodeNode(n))
	}
	if g.Name != "" {
		w.stringField(2, g.Name)
	}
	for _, t := range g.Floats {
		w.bytesField(5, encodeFloatTensor(t))
	}
	for _, t := range g.Int64s {
		w.bytesField(5, encodeInt64Tensor(t))
	}
	for _, v := range g.Inputs {
		w.bytesField(11, encodeValueInfo(v))
	}
	for _, v := range g.Outputs {
		w.bytesField(12, encodeValueInfo(v))
	}
	return w.b
}

func encodeNode(n Node) []byte {
	var w encbuf
	for _, in := range n.Inputs {
		w.stringField(1, in)
	}
	for _, out := range n.Outputs {
		w.stringField(2, out)
	}
	if n.Name != "" {
		w.stringField(3, n.Name)
	}
	w.stringField(4, n.Op)
	for _, a := range n.Attrs {
		w.bytesField(5, encodeAttr(a))
	}
	return w.b
}

func encodeAttr(a Attr) []byte {
	var w encbuf
	w.stringField(1, a.Name)
	w.varintField(20, uint64(a.Type))
	switch a.Type {
	case AttrFloat:
		w.fixed32Field(2, math.Float32bits(a.F))
	case AttrInt:
		w.varintField(3, uint64(a.I))
	case AttrTensor:
		if a.Tensor != nil {
			w.bytesField(5, encodeFloatTensor(*a.Tensor))
		}
	case AttrFloats:
		for _, f := range a.Floats {
			w.fixed32Field(7, math.Float32bits(f))
		}
	case AttrInts:
		for _, v := range a.Ints {
			w.varintField(8, uint64(v))
		}
	}
	return w.b
}

func encodeFloatTensor(t Tensor) []byte {
	var w encbuf
	for _, d := range t.Dims {
		w.varintField(1, uint64(d))
	}
	w.varintField(2, 1) // data_type = FLOAT
	raw := make([]byte, len(t.Data)*4)
	for i, f := range t.Data {
		binary.LittleEndian.PutUint32(raw[i*4:], math.Float32bits(f))
	}
	w.bytesField(9, raw) // raw_data
	if t.Name != "" {
		w.stringField(8, t.Name)
	}
	return w.b
}

func encodeInt64Tensor(t Int64Tensor) []byte {
	var w encbuf
	for _, d := range t.Dims {
		w.varintField(1, uint64(d))
	}
	w.varintField(2, 7) // data_type = INT64
	raw := make([]byte, len(t.Data)*8)
	for i, v := range t.Data {
		binary.LittleEndian.PutUint64(raw[i*8:], uint64(v))
	}
	w.bytesField(9, raw)
	if t.Name != "" {
		w.stringField(8, t.Name)
	}
	return w.b
}

func encodeValueInfo(v ValueInfo) []byte {
	var shape encbuf
	for _, d := range v.Dims {
		var dim encbuf
		if d >= 0 {
			dim.varintField(1, uint64(d)) // dim_value
		} else {
			dim.stringField(2, "N") // dim_param (symbolic)
		}
		shape.bytesField(1, dim.b) // TensorShapeProto.dim
	}
	var tt encbuf
	tt.varintField(1, 1)      // elem_type = FLOAT
	tt.bytesField(2, shape.b) // shape
	var tp encbuf
	tp.bytesField(1, tt.b) // TypeProto.tensor_type
	var w encbuf
	w.stringField(1, v.Name)
	w.bytesField(2, tp.b) // type
	return w.b
}

// encbuf is a tiny protobuf writer.
type encbuf struct{ b []byte }

func (w *encbuf) varint(x uint64) {
	for x >= 0x80 {
		w.b = append(w.b, byte(x)|0x80)
		x >>= 7
	}
	w.b = append(w.b, byte(x))
}

func (w *encbuf) tag(field, wire int) { w.varint(uint64(field)<<3 | uint64(wire)) }

func (w *encbuf) varintField(field int, x uint64) {
	w.tag(field, 0)
	w.varint(x)
}

func (w *encbuf) fixed32Field(field int, v uint32) {
	w.tag(field, 5)
	w.b = append(w.b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (w *encbuf) bytesField(field int, p []byte) {
	w.tag(field, 2)
	w.varint(uint64(len(p)))
	w.b = append(w.b, p...)
}

func (w *encbuf) stringField(field int, s string) { w.bytesField(field, []byte(s)) }
