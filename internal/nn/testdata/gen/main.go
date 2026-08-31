// Command gen writes internal/nn/testdata/model.onnx: a 48 -> 8 -> 7 feed-forward
// classifier that matches the flow-classifier-v1 contract (flow-features-v1 in,
// traffic-classes-v1 out). Committing the generator next to its output keeps the
// fixture's provenance in the tree, the same way testdata/gen does for the PCAP
// fixtures (PROJECT.md §25).
//
// Run from the repo root:  go run ./internal/nn/testdata/gen
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

func main() {
	out := "internal/nn/testdata"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	// Deterministic pseudo-random weights from a fixed seed (a plain LCG, so the
	// fixture never shifts with a math/rand change). Small magnitudes keep the
	// pre-softmax logits well conditioned.
	r := &lcg{state: 0x5EED}
	g := onnxbuild.MLP(48, []onnxbuild.Layer{
		{W: r.matrix(8, 48, 0.25), B: r.vec(8, 0.1), Activation: "Relu"},
		{W: r.matrix(7, 8, 0.25), B: r.vec(7, 0.1)},
	}, true)

	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(out, "model.onnx")
	data := g.Encode()
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // a public test fixture
		log.Fatal(err)
	}
	log.Printf("wrote %s (%d bytes)", path, len(data))
}

// lcg is a 64-bit linear congruential generator (constants from Knuth's MMIX).
type lcg struct{ state uint64 }

func (l *lcg) next() float64 {
	l.state = l.state*6364136223846793005 + 1442695040888963407
	return float64(l.state>>11) / float64(uint64(1)<<53)
}

func (l *lcg) matrix(rows, cols int, scale float64) [][]float32 {
	m := make([][]float32, rows)
	for i := range m {
		m[i] = l.vec(cols, scale)
	}
	return m
}

func (l *lcg) vec(n int, scale float64) []float32 {
	v := make([]float32, n)
	for i := range v {
		v[i] = float32((l.next()*2 - 1) * scale)
	}
	return v
}
