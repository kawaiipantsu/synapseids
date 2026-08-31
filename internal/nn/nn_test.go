package nn_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

const tol = 1e-6

func load(t *testing.T, g onnxbuild.Graph) *nn.Model {
	t.Helper()
	m, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func run(t *testing.T, m *nn.Model, in []float32) []float32 {
	t.Helper()
	out, err := m.Run(in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out
}

func approx(t *testing.T, got, want []float32, eps float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if math.Abs(float64(got[i]-want[i])) > eps {
			t.Fatalf("index %d: got %v, want %v (Δ=%g)\n got=%v\nwant=%v",
				i, got[i], want[i], math.Abs(float64(got[i]-want[i])), got, want)
		}
	}
}

func argmax(v []float32) int {
	idx := 0
	for i, x := range v {
		if x > v[idx] {
			idx = i
		}
	}
	return idx
}

// TestMLPForwardExact checks a hand-computed 4->3->2 network, both the raw logits
// (no softmax) and the softmaxed output.
func TestMLPForwardExact(t *testing.T) {
	hidden := onnxbuild.Layer{
		W: [][]float32{
			{1, 0, 0, 0},
			{0, 1, 0, 0},
			{1, 1, 1, 1},
		},
		B:          []float32{0, 0, -10},
		Activation: "Relu",
	}
	out := onnxbuild.Layer{
		W: [][]float32{
			{1, 0, 0},
			{0, 0, 1},
		},
		B: []float32{0.5, -0.25},
	}
	in := []float32{1, 2, 3, 4}
	// hidden pre-activation: [1, 2, 10-10=0] -> ReLU -> [1, 2, 0]
	// output: [1*1 + 0.5, 0*1 + ... + 1*0 + (-0.25)] = [1.5, -0.25]
	wantLogits := []float32{1.5, -0.25}

	logitsNet := load(t, onnxbuild.MLP(4, []onnxbuild.Layer{hidden, out}, false))
	approx(t, run(t, logitsNet, in), wantLogits, 0) // exact in float32

	softNet := load(t, onnxbuild.MLP(4, []onnxbuild.Layer{hidden, out}, true))
	got := run(t, softNet, in)
	e0, e1 := math.Exp(1.5), math.Exp(-0.25)
	want := []float32{float32(e0 / (e0 + e1)), float32(e1 / (e0 + e1))}
	approx(t, got, want, tol)
	if argmax(got) != 0 {
		t.Fatalf("argmax = %d, want 0", argmax(got))
	}
	if s := got[0] + got[1]; math.Abs(float64(s)-1) > tol {
		t.Fatalf("softmax sum = %v", s)
	}
}

func TestActivations(t *testing.T) {
	in := []float32{-2, -1, 0, 1, 3}
	cases := []struct {
		op    string
		attrs []onnxbuild.Attr
		want  func(x float64) float64
	}{
		{"Relu", nil, func(x float64) float64 { return math.Max(0, x) }},
		{"LeakyRelu", []onnxbuild.Attr{{Name: "alpha", Type: onnxbuild.AttrFloat, F: 0.5}},
			func(x float64) float64 {
				if x < 0 {
					return 0.5 * x
				}
				return x
			}},
		{"LeakyRelu", nil, func(x float64) float64 { // default alpha 0.01
			if x < 0 {
				return 0.01 * x
			}
			return x
		}},
		{"Sigmoid", nil, func(x float64) float64 { return 1 / (1 + math.Exp(-x)) }},
		{"Tanh", nil, math.Tanh},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			m := load(t, onnxbuild.Unary(len(in), c.op, c.attrs...))
			got := run(t, m, in)
			want := make([]float32, len(in))
			for i, x := range in {
				want[i] = float32(c.want(float64(x)))
			}
			approx(t, got, want, tol)
		})
	}
}

func TestBatchNormFoldsToAffine(t *testing.T) {
	in := []float32{1, 2, 3, 4}
	bn := func(scale, bias, mean, variance []float32, eps float32) onnxbuild.Graph {
		g := onnxbuild.Unary(4, "BatchNormalization",
			onnxbuild.Attr{Name: "epsilon", Type: onnxbuild.AttrFloat, F: eps})
		g.Nodes[0].Inputs = []string{"input", "scale", "B", "mean", "var"}
		g.Floats = []onnxbuild.Tensor{
			{Name: "scale", Dims: []int64{4}, Data: scale},
			{Name: "B", Dims: []int64{4}, Data: bias},
			{Name: "mean", Dims: []int64{4}, Data: mean},
			{Name: "var", Dims: []int64{4}, Data: variance},
		}
		return g
	}

	// scale=2, B=1, mean=0, var=1, eps=0  ->  y = 2x + 1
	m := load(t, bn([]float32{2, 2, 2, 2}, []float32{1, 1, 1, 1}, []float32{0, 0, 0, 0}, []float32{1, 1, 1, 1}, 0))
	approx(t, run(t, m, in), []float32{3, 5, 7, 9}, 0)

	// scale=2, B=0.5, mean=1, var=3, eps=1 (denom = sqrt(4) = 2)  ->  y = (x-1) + 0.5
	m = load(t, bn([]float32{2, 2, 2, 2}, []float32{0.5, 0.5, 0.5, 0.5}, []float32{1, 1, 1, 1}, []float32{3, 3, 3, 3}, 1))
	approx(t, run(t, m, in), []float32{0.5, 1.5, 2.5, 3.5}, tol)
}

func TestDropoutIsIdentityAtInference(t *testing.T) {
	in := []float32{-1.5, 0, 2.25, 7}
	m := load(t, onnxbuild.Unary(4, "Dropout",
		onnxbuild.Attr{Name: "ratio", Type: onnxbuild.AttrFloat, F: 0.7}))
	approx(t, run(t, m, in), in, 0)
}

func TestIdentityAndFlatten(t *testing.T) {
	in := []float32{3, 1, 4, 1}
	approx(t, run(t, load(t, onnxbuild.Unary(4, "Identity")), in), in, 0)

	fl := onnxbuild.Unary(4, "Flatten", onnxbuild.Attr{Name: "axis", Type: onnxbuild.AttrInt, I: 1})
	approx(t, run(t, load(t, fl), in), in, 0)
}

func TestResidualAdd(t *testing.T) {
	// h = input @ I(3x3); output = input + h = 2*input
	g := onnxbuild.Graph{
		Name:    "residual",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 3}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{1, 3}}},
		Floats: []onnxbuild.Tensor{
			{Name: "I", Dims: []int64{3, 3}, Data: []float32{1, 0, 0, 0, 1, 0, 0, 0, 1}},
		},
		Nodes: []onnxbuild.Node{
			{Op: "MatMul", Name: "mm", Inputs: []string{"input", "I"}, Outputs: []string{"h"}},
			{Op: "Add", Name: "res", Inputs: []string{"input", "h"}, Outputs: []string{"output"}},
		},
	}
	approx(t, run(t, load(t, g), []float32{2, -3, 5}), []float32{4, -6, 10}, 0)
}

func TestGemmAlphaBetaTransB0(t *testing.T) {
	// Y = alpha*(X @ B) + beta*C, X=[1,2], B=[[1,2],[3,4]] (transB=0), C=[10,20], alpha=2, beta=3
	// X@B = [7, 10]; *2 = [14, 20]; + 3*C = [44, 80]
	g := onnxbuild.Graph{
		Name:    "gemm",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 2}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{1, 2}}},
		Floats: []onnxbuild.Tensor{
			{Name: "B", Dims: []int64{2, 2}, Data: []float32{1, 2, 3, 4}},
			{Name: "C", Dims: []int64{2}, Data: []float32{10, 20}},
		},
		Nodes: []onnxbuild.Node{{
			Op: "Gemm", Name: "gemm", Inputs: []string{"input", "B", "C"}, Outputs: []string{"output"},
			Attrs: []onnxbuild.Attr{
				{Name: "alpha", Type: onnxbuild.AttrFloat, F: 2},
				{Name: "beta", Type: onnxbuild.AttrFloat, F: 3},
				{Name: "transB", Type: onnxbuild.AttrInt, I: 0},
			},
		}},
	}
	approx(t, run(t, load(t, g), []float32{1, 2}), []float32{44, 80}, 0)
}

func TestMatMulVector(t *testing.T) {
	// [3,4] . W(2x3-as-input? no) ; use A=[1,2] @ W[2,3] -> [3]
	g := onnxbuild.Graph{
		Name:    "matmul",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 2}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{1, 3}}},
		Floats: []onnxbuild.Tensor{
			{Name: "W", Dims: []int64{2, 3}, Data: []float32{1, 0, 2, 0, 1, 3}},
		},
		Nodes: []onnxbuild.Node{
			{Op: "MatMul", Name: "mm", Inputs: []string{"input", "W"}, Outputs: []string{"output"}},
		},
	}
	// [3,4] @ [[1,0,2],[0,1,3]] = [3, 4, 6+12=18]
	approx(t, run(t, load(t, g), []float32{3, 4}), []float32{3, 4, 18}, 0)
}

func TestReshapeConstantShape(t *testing.T) {
	in := []float32{1, 2, 3, 4}
	g := onnxbuild.Graph{
		Name:    "reshape",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 4}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{4}}},
		Int64s: []onnxbuild.Int64Tensor{
			{Name: "shape", Dims: []int64{1}, Data: []int64{-1}},
		},
		Nodes: []onnxbuild.Node{
			{Op: "Reshape", Name: "rs", Inputs: []string{"input", "shape"}, Outputs: []string{"flat"}},
			{Op: "Relu", Name: "act", Inputs: []string{"flat"}, Outputs: []string{"output"}},
		},
	}
	approx(t, run(t, load(t, g), in), in, 0) // all positive, ReLU is a no-op
}

func TestSoftmaxSumsToOneAndPreservesOrder(t *testing.T) {
	in := []float32{1, 3, 2, 0, -1}
	m := load(t, onnxbuild.Unary(len(in), "Softmax",
		onnxbuild.Attr{Name: "axis", Type: onnxbuild.AttrInt, I: 1}))
	got := run(t, m, in)

	var sum float64
	for _, v := range got {
		if v < 0 || v > 1 {
			t.Fatalf("probability out of range: %v", v)
		}
		sum += float64(v)
	}
	if math.Abs(sum-1) > tol {
		t.Fatalf("softmax sum = %v", sum)
	}
	if argmax(got) != 1 {
		t.Fatalf("argmax = %d, want 1", argmax(got))
	}
	// reference
	var z float64
	exps := make([]float64, len(in))
	for i, x := range in {
		exps[i] = math.Exp(float64(x))
		z += exps[i]
	}
	want := make([]float32, len(in))
	for i := range exps {
		want[i] = float32(exps[i] / z)
	}
	approx(t, got, want, tol)
}

func TestConstantNodeFoldedAsReshapeShape(t *testing.T) {
	in := []float32{5, 6, 7, 8}
	g := onnxbuild.Graph{
		Name:    "const-reshape",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 4}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{4}}},
		Nodes: []onnxbuild.Node{
			{
				Op: "Constant", Name: "shape", Inputs: nil, Outputs: []string{"shp"},
				Attrs: []onnxbuild.Attr{{
					Name: "value", Type: onnxbuild.AttrTensor,
					Tensor: &onnxbuild.Tensor{Dims: []int64{1}, Data: []float32{-1}},
				}},
			},
			{Op: "Reshape", Name: "rs", Inputs: []string{"input", "shp"}, Outputs: []string{"output"}},
		},
	}
	m := load(t, g)
	if c := m.OpCounts()["Constant"]; c != 1 {
		t.Fatalf("Constant count = %d, want 1", c)
	}
	approx(t, run(t, m, in), in, 0)
}

func TestTopologicalOrderingIsResolved(t *testing.T) {
	// Nodes intentionally listed out of dependency order.
	g := onnxbuild.Graph{
		Name:    "unordered",
		Inputs:  []onnxbuild.ValueInfo{{Name: "input", Dims: []int64{1, 2}}},
		Outputs: []onnxbuild.ValueInfo{{Name: "output", Dims: []int64{1, 2}}},
		Nodes: []onnxbuild.Node{
			{Op: "Relu", Name: "b", Inputs: []string{"mid"}, Outputs: []string{"output"}},
			{Op: "Sigmoid", Name: "a", Inputs: []string{"input"}, Outputs: []string{"mid"}},
		},
	}
	got := run(t, load(t, g), []float32{0, 2})
	want := []float32{float32(1.0 / (1 + math.Exp(0))), float32(1.0 / (1 + math.Exp(-2)))}
	approx(t, got, want, tol)
}

func TestUnsupportedOpRejected(t *testing.T) {
	g := onnxbuild.Unary(4, "Conv")
	_, err := nn.Load(bytes.NewReader(g.Encode()))
	if err == nil || !contains(err.Error(), `unsupported op "Conv"`) {
		t.Fatalf("want unsupported-op error, got %v", err)
	}
}

func TestInputSizeMismatch(t *testing.T) {
	m := load(t, onnxbuild.MLP(4, []onnxbuild.Layer{{W: [][]float32{{1, 1, 1, 1}, {0, 0, 0, 0}}, B: []float32{0, 0}}}, true))
	if m.InputSize() != 4 {
		t.Fatalf("InputSize = %d", m.InputSize())
	}
	if _, err := m.Run([]float32{1, 2, 3}); err == nil {
		t.Fatal("want error for short input")
	}
	if _, err := m.Run([]float32{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("want error for long input")
	}
}

func TestMalformedModelsReturnErrorNoPanic(t *testing.T) {
	full := onnxbuild.MLP(4, []onnxbuild.Layer{{W: [][]float32{{1, 1, 1, 1}}, B: []float32{0}}}, true).Encode()
	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"garbage varint":   {0xff, 0xff, 0xff},
		"len overruns buf": {0x0a, 0x7f, 0x01, 0x02}, // field 1, wire 2, says 127 bytes
		"header only":      {0x08, 0x07},             // ir_version = 7, no graph
		"truncated model":  full[:len(full)/2],
		"trailing garbage": append(append([]byte(nil), full...), 0xff, 0xff),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := nn.Load(bytes.NewReader(b))
			if err == nil {
				t.Fatalf("want error, got model %+v", m)
			}
		})
	}
}

func TestOpCountsAndSizes(t *testing.T) {
	g := onnxbuild.MLP(6, []onnxbuild.Layer{
		{W: make6x4(), B: []float32{0, 0, 0, 0}, Activation: "Relu"},
		{W: make4x3(), B: []float32{0, 0, 0}},
	}, true)
	m := load(t, g)
	if m.InputSize() != 6 || m.OutputSize() != 3 {
		t.Fatalf("sizes: in=%d out=%d", m.InputSize(), m.OutputSize())
	}
	oc := m.OpCounts()
	if oc["Gemm"] != 2 || oc["Relu"] != 1 || oc["Softmax"] != 1 {
		t.Fatalf("op counts = %v", oc)
	}
	// returned map is a copy
	oc["Gemm"] = 99
	if m.OpCounts()["Gemm"] != 2 {
		t.Fatal("OpCounts must return a copy")
	}
}

// TestRunTinyONNXFixture loads the committed 48->8->7 fixture and checks it
// produces a valid probability distribution.
func TestRunTinyONNXFixture(t *testing.T) {
	m, err := nn.LoadFile("testdata/model.onnx")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if m.InputSize() != 48 {
		t.Fatalf("InputSize = %d, want 48", m.InputSize())
	}
	if m.OutputSize() != 7 {
		t.Fatalf("OutputSize = %d, want 7", m.OutputSize())
	}
	if oc := m.OpCounts(); oc["Gemm"] != 2 || oc["Relu"] != 1 || oc["Softmax"] != 1 {
		t.Fatalf("fixture op counts = %v", oc)
	}

	in := make([]float32, 48)
	for i := range in {
		in[i] = float32(i%7) * 0.1
	}
	out := run(t, m, in)
	if len(out) != 7 {
		t.Fatalf("output length = %d, want 7", len(out))
	}
	var sum float64
	for _, v := range out {
		if v < 0 || v > 1 || math.IsNaN(float64(v)) {
			t.Fatalf("bad probability %v in %v", v, out)
		}
		sum += float64(v)
	}
	if math.Abs(sum-1) > 1e-5 {
		t.Fatalf("softmax sum = %v (want ~1)", sum)
	}

	// determinism
	out2 := run(t, m, in)
	approx(t, out2, out, 0)
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func make6x4() [][]float32 {
	m := make([][]float32, 4)
	for i := range m {
		m[i] = []float32{0.1, 0.1, 0.1, 0.1, 0.1, 0.1}
	}
	return m
}

func make4x3() [][]float32 {
	m := make([][]float32, 3)
	for i := range m {
		m[i] = []float32{0.2, 0.2, 0.2, 0.2}
	}
	return m
}
