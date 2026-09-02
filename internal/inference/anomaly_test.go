package inference

import (
	"bytes"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

// constAnomaly is a fake AnomalyScorer that returns a fixed output regardless of
// input, so Runtime wiring is what is under test.
type constAnomaly struct {
	id  string
	out AnomalyOutput
}

func (c constAnomaly) ID() string     { return c.id }
func (c constAnomaly) Family() string { return "flow-anomaly-v1" }
func (c constAnomaly) Role() Role     { return RoleAnomaly }
func (c constAnomaly) ScoreAnomaly(features.Vector) AnomalyOutput {
	o := c.out
	o.ModelID = c.id
	return o
}

func TestScoreAnomalyPopulatesResultWithoutTouchingVerdict(t *testing.T) {
	prim := constModel{id: "prim", role: RolePrimary, class: classScan}
	anom := constAnomaly{id: "ae", out: AnomalyOutput{
		Available: true, ReconError: 0.42, Score: 0.8, Threshold: 0.3, Exceeds: true,
		TopDeltas: []FeatureDelta{{Index: 3, Name: "bytes_forward", Delta: 0.9}},
	}}

	rt := NewRuntime(prim)
	rt.SetAnomalyModels(anom)
	res := rt.Score(zeroVec(7))

	if res.Class != "scan" {
		t.Fatalf("anomaly model changed the verdict: %q", res.Class)
	}
	if res.Disagreement {
		t.Fatalf("anomaly model raised Disagreement")
	}
	for _, m := range res.Models {
		if m.ModelID == "ae" {
			t.Fatalf("anomaly model must not appear in Result.Models: %+v", res.Models)
		}
	}
	if res.Anomaly == nil {
		t.Fatal("Result.Anomaly not set")
	}
	if !res.Anomaly.Available || res.Anomaly.ModelID != "ae" || res.Anomaly.Score != 0.8 ||
		res.Anomaly.ReconError != 0.42 || res.Anomaly.Threshold != 0.3 || !res.Anomaly.Exceeds {
		t.Fatalf("Result.Anomaly = %+v", res.Anomaly)
	}
}

func TestScoreNoAnomalyModelLeavesResultAnomalyNil(t *testing.T) {
	res := NewRuntime(constModel{id: "prim", role: RolePrimary, class: classNormal}).Score(zeroVec(1))
	if res.Anomaly != nil {
		t.Fatalf("Result.Anomaly must stay nil with no anomaly model: %+v", res.Anomaly)
	}
}

func TestAnomalyModelsAccessorAndReplace(t *testing.T) {
	rt := NewRuntime()
	if len(rt.AnomalyModels()) != 0 {
		t.Fatal("fresh Runtime must have no anomaly models")
	}
	rt.SetAnomalyModels(constAnomaly{id: "a"}, constAnomaly{id: "b"})
	if len(rt.AnomalyModels()) != 2 {
		t.Fatalf("SetAnomalyModels: got %d", len(rt.AnomalyModels()))
	}
	rt.SetAnomalyModels()
	if len(rt.AnomalyModels()) != 0 {
		t.Fatal("SetAnomalyModels() with no args must clear the anomaly role")
	}
}

// zeroNet is a 48->48 linear graph with all-zero weights and bias: its output is
// the zero vector for any input, so the reconstruction error is mean(in_i^2) and
// the scoring maths can be checked by hand.
func zeroNet(t *testing.T) *nn.Model {
	t.Helper()
	w := make([][]float32, features.Size)
	for i := range w {
		w[i] = make([]float32, features.Size)
	}
	g := onnxbuild.MLP(features.Size, []onnxbuild.Layer{{W: w, B: make([]float32, features.Size)}}, false)
	net, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load zero net: %v", err)
	}
	return net
}

func TestONNXAnomalyModelScoring(t *testing.T) {
	net := zeroNet(t)

	// four features at 0.5 → sse = 4*0.25 = 1.0 → recon = 1/48.
	var v features.Vector
	for _, i := range []int{2, 5, 9, 40} {
		v.Values[i] = 0.5
	}
	const recon = 1.0 / 48.0

	// Uncalibrated: p50=0 → denominator falls back to 1, never Exceeds.
	m, err := NewONNXAnomalyModel("ae", net, nil, 0, 0)
	if err != nil {
		t.Fatalf("NewONNXAnomalyModel: %v", err)
	}
	got := m.ScoreAnomaly(v)
	if !got.Available {
		t.Fatal("must be Available")
	}
	if !approx(got.ReconError, recon) {
		t.Fatalf("ReconError = %g, want %g", got.ReconError, recon)
	}
	if !approx(got.Score, recon/(recon+1)) {
		t.Fatalf("uncalibrated Score = %g, want %g", got.Score, recon/(recon+1))
	}
	if got.Exceeds {
		t.Fatal("uncalibrated model must never flag Exceeds")
	}
	if len(got.TopDeltas) != anomalyTopK {
		t.Fatalf("TopDeltas len = %d, want %d", len(got.TopDeltas), anomalyTopK)
	}
	top := map[int]bool{}
	for _, d := range got.TopDeltas[:4] {
		top[d.Index] = true
		if !approx(d.Delta, -0.5) {
			t.Fatalf("delta for feature %d = %g, want -0.5", d.Index, d.Delta)
		}
	}
	for _, i := range []int{2, 5, 9, 40} {
		if !top[i] {
			t.Fatalf("feature %d should be among the largest gaps: %+v", i, got.TopDeltas)
		}
	}

	// Calibrated: p50 == recon → score exactly 0.5; threshold below recon → Exceeds.
	m2, _ := NewONNXAnomalyModel("ae", net, nil, recon, recon/2)
	got2 := m2.ScoreAnomaly(v)
	if !approx(got2.Score, 0.5) {
		t.Fatalf("calibrated Score = %g, want 0.5", got2.Score)
	}
	if !got2.Exceeds {
		t.Fatal("recon above threshold must flag Exceeds")
	}

	// A larger input moves more error → a strictly larger score (monotonicity).
	var v2 features.Vector
	for i := range v2.Values {
		v2.Values[i] = 1.0
	}
	if m.ScoreAnomaly(v2).Score <= got.Score {
		t.Fatal("score must be monotone in reconstruction error")
	}
}

func TestNewONNXAnomalyModelRejectsWrongOutputSize(t *testing.T) {
	g := onnxbuild.MLP(features.Size, []onnxbuild.Layer{
		{W: zeroMatrix(7, features.Size), B: make([]float32, 7)},
	}, false)
	net, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load 48->7 net: %v", err)
	}
	if _, err := NewONNXAnomalyModel("ae", net, nil, 0, 0); err == nil {
		t.Fatal("a 48->7 network must be rejected as an anomaly model")
	}
	if _, err := NewONNXAnomalyModel("ae", nil, nil, 0, 0); err == nil {
		t.Fatal("a nil network must be rejected")
	}
}

func zeroMatrix(rows, cols int) [][]float32 {
	m := make([][]float32, rows)
	for i := range m {
		m[i] = make([]float32, cols)
	}
	return m
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
