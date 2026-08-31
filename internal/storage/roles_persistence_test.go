package storage

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
)

// modelOutput builds a ModelOutput with a distinct, fully populated 7-wide
// score vector so the round-trip can prove nothing is truncated.
func modelOutput(id string, role inference.Role, top int) inference.ModelOutput {
	var sc inference.Scores
	for i := range sc {
		sc[i] = 0.01 * float64(i+1)
	}
	sc[top] = 0.9
	return inference.ModelOutput{
		ModelID: id, Role: role,
		Class: "x", ClassID: top, Score: sc[top], Scores: sc,
	}
}

// A Classification carrying several per-model outputs must survive
// PutClassification → RecentClassifications byte-for-byte: no model dropped, and
// each 7-element Scores vector intact (PROJECT.md §12).
func TestPutClassificationRetainsEveryModelOutput(t *testing.T) {
	m := NewMem(10, 10)

	want := inference.Result{
		FlowID: 42, Class: "scan", ClassID: 1, Score: 0.9, Disagreement: true,
		Models: []inference.ModelOutput{
			modelOutput("primary-v2", inference.RolePrimary, 1),
			modelOutput("global-v1", inference.RoleGlobal, 0),
			modelOutput("exp-autoencoder", inference.RoleExperimental, 6),
		},
	}
	m.PutClassification(Classification{FlowID: 42, Result: want})

	got := m.RecentClassifications(10)
	if len(got) != 1 {
		t.Fatalf("want 1 stored verdict, got %d", len(got))
	}
	gm := got[0].Result.Models
	if len(gm) != len(want.Models) {
		t.Fatalf("per-model outputs dropped: want %d, got %d", len(want.Models), len(gm))
	}
	for i, wm := range want.Models {
		// ModelOutput is comparable (Scores is a [7]float64 array), so == checks
		// every field including the whole distribution.
		if gm[i] != wm {
			t.Fatalf("model %d changed in storage:\n want %+v\n got  %+v", i, wm, gm[i])
		}
	}

	// The Flow-side feature vector must likewise round-trip at full width.
	var fv features.Vector
	fv.FlowID = 42
	fv.Schema = features.SchemaID
	for i := range fv.Values {
		fv.Values[i] = float64(i) + 0.5
	}
	m.PutFlow(FlowRecord{ID: 42, Features: fv})
	fr, ok := m.Flow(42)
	if !ok {
		t.Fatalf("flow 42 not retained")
	}
	if fr.Features.Values != fv.Values {
		t.Fatalf("stored feature vector not preserved verbatim")
	}
}

// Stats.Disagreements is a cumulative count of stored verdicts whose ensemble
// flagged model disagreement, incremented in PutClassification.
func TestStatsCountsDisagreements(t *testing.T) {
	m := NewMem(10, 3) // small class ring: eviction must not disturb the counter

	put := func(flowID uint64, disagree bool) {
		m.PutClassification(Classification{
			FlowID: flowID,
			Result: inference.Result{FlowID: flowID, Disagreement: disagree},
		})
	}
	put(1, true)
	put(2, false)
	put(3, true)
	put(4, false)
	put(5, true) // ring (cap 3) has now evicted verdicts 1 and 2

	if s := m.Stats(); s.Disagreements != 3 {
		t.Fatalf("Disagreements = %d, want 3 (cumulative, survives eviction)", s.Disagreements)
	}
	if s := m.Stats(); s.ClassEvicted != 2 {
		t.Fatalf("ClassEvicted = %d, want 2", s.ClassEvicted)
	}
}
