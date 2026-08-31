package nn_test

import (
	"bytes"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

// benchLCG mirrors the fixture generator's deterministic weight source.
type benchLCG struct{ s uint64 }

func (l *benchLCG) mat(rows, cols int) [][]float32 {
	m := make([][]float32, rows)
	for i := range m {
		m[i] = make([]float32, cols)
		for j := range m[i] {
			l.s = l.s*6364136223846793005 + 1442695040888963407
			m[i][j] = float32(float64(l.s>>11)/float64(uint64(1)<<53)*0.5 - 0.25)
		}
	}
	return m
}

func (l *benchLCG) vec(n int) []float32 { return l.mat(1, n)[0] }

// BenchmarkRun scores a 48 -> 64 -> 32 -> 7 classifier (Gemm+ReLU, Gemm+ReLU,
// Gemm, Softmax), the shape PROJECT.md §10 gives as a representative hidden
// architecture.
func BenchmarkRun(b *testing.B) {
	r := &benchLCG{s: 1}
	g := onnxbuild.MLP(48, []onnxbuild.Layer{
		{W: r.mat(64, 48), B: r.vec(64), Activation: "Relu"},
		{W: r.mat(32, 64), B: r.vec(32), Activation: "Relu"},
		{W: r.mat(7, 32), B: r.vec(7)},
	}, true)
	m, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		b.Fatal(err)
	}
	in := make([]float32, 48)
	for i := range in {
		in[i] = float32(i) * 0.01
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Run(in); err != nil {
			b.Fatal(err)
		}
	}
}
