package inference

import (
	"bytes"
	"math"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

// alwaysClass builds a 48->7 network whose weights are zero and whose bias makes
// class `want` dominate after Softmax, so Classify always returns argmax == want.
func alwaysClass(t *testing.T, want int) *nn.Model {
	t.Helper()
	w := make([][]float32, OutputSize)
	b := make([]float32, OutputSize)
	for i := range w {
		w[i] = make([]float32, features.Size)
	}
	b[want] = 20
	g := onnxbuild.MLP(features.Size, []onnxbuild.Layer{{W: w, B: b}}, true)
	m, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func TestONNXModelSatisfiesClassifier(t *testing.T) {
	m, err := NewONNXModel("onnx-x", RoleExperimental, alwaysClass(t, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	var _ Classifier = m
	if m.ID() != "onnx-x" || m.Role() != RoleExperimental || m.Family() != "flow-classifier-v1" {
		t.Fatalf("metadata: id=%q role=%q family=%q", m.ID(), m.Role(), m.Family())
	}
}

func TestONNXModelClassifyArgmax(t *testing.T) {
	m, err := NewONNXModel("", RolePrimary, alwaysClass(t, 1), nil)
	if err != nil {
		t.Fatal(err)
	}

	var v features.Vector
	for i := range v.Values {
		v.Values[i] = float64(i) // non-trivial input; weights are zero so it cannot matter
	}
	sc := m.Classify(v)

	idx, p := sc.Top()
	if idx != 1 {
		t.Fatalf("argmax = %d (%.4f), want 1; scores=%v", idx, p, sc)
	}
	var sum float64
	for _, x := range sc {
		if x < 0 || x > 1 {
			t.Fatalf("score out of range: %v", sc)
		}
		sum += x
	}
	if math.Abs(sum-1) > 1e-6 {
		t.Fatalf("scores sum = %v", sum)
	}
}

func TestONNXModelNormalizerApplied(t *testing.T) {
	// A network that just forwards its first 7 inputs (identity-ish) so the
	// normalizer's effect is observable: weight[i][i] = 1 for i < 7.
	w := make([][]float32, OutputSize)
	for i := range w {
		w[i] = make([]float32, features.Size)
		w[i][i] = 1
	}
	g := onnxbuild.MLP(features.Size, []onnxbuild.Layer{{W: w, B: make([]float32, OutputSize)}}, true)
	net, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	// Normalizer forces feature 3 sky-high and zeroes the rest -> class 3 wins.
	norm := func(features.Vector) [features.Size]float64 {
		var out [features.Size]float64
		out[3] = 50
		return out
	}
	m, err := NewONNXModel("n", RolePrimary, net, norm)
	if err != nil {
		t.Fatal(err)
	}

	var v features.Vector // all zeros; without the normalizer every class is equal
	if idx, _ := m.Classify(v).Top(); idx != 3 {
		t.Fatalf("with normalizer argmax = %d, want 3", idx)
	}

	// Same net, no normalizer: all-zero logits -> uniform -> argmax is class 0.
	m2, _ := NewONNXModel("r", RolePrimary, net, nil)
	sc := m2.Classify(v)
	for _, x := range sc {
		if math.Abs(x-1.0/float64(OutputSize)) > 1e-6 {
			t.Fatalf("raw path expected uniform, got %v", sc)
		}
	}
}

func onnxMLP(t *testing.T, inSize, outSize int) *nn.Model {
	t.Helper()
	w := make([][]float32, outSize)
	for i := range w {
		w[i] = make([]float32, inSize)
	}
	g := onnxbuild.MLP(inSize, []onnxbuild.Layer{{W: w, B: make([]float32, outSize)}}, true)
	m, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load %d->%d: %v", inSize, outSize, err)
	}
	return m
}

func TestONNXModelRejectsWrongShape(t *testing.T) {
	if _, err := NewONNXModel("bad-in", RolePrimary, onnxMLP(t, 10, OutputSize), nil); err == nil {
		t.Fatal("want error for input size 10 != 48")
	}
	if _, err := NewONNXModel("bad-out", RolePrimary, onnxMLP(t, features.Size, 5), nil); err == nil {
		t.Fatal("want error for output size 5 != 7")
	}
	if _, err := NewONNXModel("nil", RolePrimary, nil, nil); err == nil {
		t.Fatal("want error for nil model")
	}
}

func TestONNXModelRuntimeIntegration(t *testing.T) {
	primary := NewHeuristic("primary", RolePrimary)
	shadow, err := NewONNXModel("onnx-shadow", RoleExperimental, alwaysClass(t, 2), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRuntime(primary, shadow)

	var v features.Vector
	v.Schema = features.SchemaID
	res := rt.Score(v)
	if len(res.Models) != 2 {
		t.Fatalf("want 2 model outputs, got %d", len(res.Models))
	}
	var sawONNX bool
	for _, mo := range res.Models {
		if mo.ModelID == "onnx-shadow" {
			sawONNX = true
			if mo.ClassID != 2 {
				t.Fatalf("onnx shadow ClassID = %d, want 2", mo.ClassID)
			}
		}
	}
	if !sawONNX {
		t.Fatal("onnx model output not recorded by Runtime")
	}
}
