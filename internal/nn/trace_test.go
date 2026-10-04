package nn_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

func TestTraceMatchesForwardPassAndWeightedEdges(t *testing.T) {
	g := onnxbuild.MLP(2, []onnxbuild.Layer{{W: [][]float32{{1, 2}, {-1, 3}}, B: []float32{.5, -.5}, Activation: "Relu"}}, false)
	m := load(t, g)
	in := []float32{2, 3}
	want := run(t, m, in)
	tr, e := m.RunTrace(in)
	if e != nil {
		t.Fatal(e)
	}
	approx(t, tr.Output, want, 1e-6)
	if len(tr.Nodes) != 3 {
		t.Fatal("missing operations")
	}
	approx(t, tr.Nodes[1].Values, []float32{8.5, 6.5}, 1e-6)
	found := false
	for _, e := range tr.Nodes[1].Connections {
		if e.From == 1 && e.To == 0 {
			found = true
			if e.Weight != 2 || e.Contribution != 6 {
				t.Fatal(e)
			}
		}
	}
	if !found {
		t.Fatal("weighted edge missing")
	}
	tr.Nodes[0].Values[0] = 999
	again := run(t, m, in)
	approx(t, again, want, 1e-6)
}
