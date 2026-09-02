package inference

import (
	"bytes"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// constSequence is a fake SequenceScorer that returns a fixed top class and
// records the window length it was handed.
type constSequence struct {
	id      string
	class   int
	lastLen int
}

func (c *constSequence) ID() string     { return c.id }
func (c *constSequence) Family() string { return schema.FamilySequenceV1 }
func (c *constSequence) Role() Role     { return RoleSequence }
func (c *constSequence) ScoreSequence(w [][features.Size]float64) Scores {
	c.lastLen = len(w)
	var s Scores
	s[c.class] = 1
	return s
}

func TestScoreSequenceFoldsTemporalPeerIntoModelsAndDisagreement(t *testing.T) {
	prim := constModel{id: "prim", role: RolePrimary, class: classNormal}
	seq := &constSequence{id: "seq", class: classScan}

	rt := NewRuntime(prim)
	rt.SetSequenceModels(seq)

	// No window → the sequence peer does not run; verdict is just the primary.
	plain := rt.Score(zeroVec(1))
	for _, m := range plain.Models {
		if m.Role == RoleSequence {
			t.Fatal("sequence peer ran without a window")
		}
	}
	if plain.Disagreement {
		t.Fatal("disagreement raised with no sequence output")
	}

	// With a window → the peer's top class is in Models and it disagrees with
	// the primary, but it does not drive the verdict.
	win := make([][features.Size]float64, 5)
	res := rt.ScoreSequence(zeroVec(1), win)
	if seq.lastLen != 5 {
		t.Fatalf("sequence model got window len %d, want 5", seq.lastLen)
	}
	if res.Class != "normal" {
		t.Fatalf("sequence peer drove the verdict: %q", res.Class)
	}
	if !res.Disagreement {
		t.Fatal("primary=normal vs sequence=scan must disagree")
	}
	if !hasModelOutput(res.Models, "seq", "scan") {
		t.Fatalf("sequence output not recorded: %+v", res.Models)
	}
}

func TestRuntimeSequenceRoleActivateDeactivate(t *testing.T) {
	rt := NewRuntime(constModel{id: "prim", role: RolePrimary, class: classNormal})
	if len(rt.SequenceModels()) != 0 {
		t.Fatal("fresh runtime has a sequence model")
	}
	seq := &constSequence{id: "s1", class: classScan}
	rt.ActivateRole(RoleSequence, seq)
	if len(rt.SequenceModels()) != 1 || rt.SequenceModels()[0].ID() != "s1" {
		t.Fatalf("ActivateRole(sequence) = %v", rt.SequenceModels())
	}
	// The primary set is untouched.
	if len(rt.Models()) != 1 || rt.Models()[0].ID() != "prim" {
		t.Fatalf("primary disturbed by sequence activation: %v", rt.Models())
	}
	// A wrong-typed model is a no-op.
	rt.ActivateRole(RoleSequence, "not a model")
	if rt.SequenceModels()[0].ID() != "s1" {
		t.Fatal("mismatched model replaced the sequence peer")
	}
	rt.DeactivateRole(RoleSequence)
	if len(rt.SequenceModels()) != 0 {
		t.Fatal("DeactivateRole(sequence) left a model")
	}
}

// seqNet builds a real [T*48] -> [7] softmax graph with all-zero weights: its
// output is a uniform distribution, so ScoreSequence's plumbing (left-pad,
// flatten, run, renormalise) is what is under test.
func seqNet(t *testing.T, seqLen int) *nn.Model {
	t.Helper()
	in := seqLen * features.Size
	g := onnxbuild.MLP(in, []onnxbuild.Layer{
		{W: zeroMatrix(7, in), B: make([]float32, 7)},
	}, true)
	net, err := nn.Load(bytes.NewReader(g.Encode()))
	if err != nil {
		t.Fatalf("load seq net: %v", err)
	}
	return net
}

func TestONNXSequenceModelPadsFlattensAndScores(t *testing.T) {
	const T = schema.SequenceLenV1
	net := seqNet(t, T)

	m, err := NewONNXSequenceModel("seq", RoleSequence, T, net, nil)
	if err != nil {
		t.Fatalf("NewONNXSequenceModel: %v", err)
	}
	if m.Family() != "flow-sequence-v1" || m.Role() != RoleSequence {
		t.Fatalf("family/role = %q/%q", m.Family(), m.Role())
	}

	// A short window (3 rows) is left-padded to T; a zero-weight net yields a
	// uniform 7-way distribution regardless.
	short := make([][features.Size]float64, 3)
	for i := range short {
		short[i][0] = 1
	}
	s := m.ScoreSequence(short)
	var sum float64
	for _, p := range s {
		if p < 0 {
			t.Fatalf("negative prob in %v", s)
		}
		sum += p
	}
	if sum < 0.99 || sum > 1.01 {
		t.Fatalf("scores sum = %v, want ~1", sum)
	}

	// An over-length window keeps only the newest T rows (no panic, still ~1).
	long := make([][features.Size]float64, T+9)
	if s := m.ScoreSequence(long); s[classNormal] < 0 {
		t.Fatal("over-length window broke scoring")
	}
}

func TestNewONNXSequenceModelRejectsWrongDims(t *testing.T) {
	const T = schema.SequenceLenV1
	// input sized for T-1, not T
	bad := seqNet(t, T-1)
	if _, err := NewONNXSequenceModel("s", RoleSequence, T, bad, nil); err == nil {
		t.Fatal("wrong input width accepted")
	}
	if _, err := NewONNXSequenceModel("s", RoleSequence, T, nil, nil); err == nil {
		t.Fatal("nil net accepted")
	}
	if _, err := NewONNXSequenceModel("s", RoleSequence, 0, seqNet(t, T), nil); err == nil {
		t.Fatal("seq_len 0 accepted")
	}
}
