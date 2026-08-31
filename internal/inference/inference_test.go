package inference

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

// zeroVec is an empty feature vector. The constModel classifiers used below
// ignore their input, so it is the ensemble wiring in Runtime.Score — role
// semantics, verdict selection, the disagreement set — that is under test here.
func zeroVec(id uint64) features.Vector { return features.Vector{FlowID: id} }

func hasModelOutput(ms []ModelOutput, id, class string) bool {
	for _, m := range ms {
		if m.ModelID == id && m.Class == class {
			return true
		}
	}
	return false
}

// An experimental model must never drive the verdict, even when it is listed
// first (PROJECT.md §12: "shadow model whose predictions are recorded but do
// not drive alerts").
func TestScoreExperimentalNeverDrivesVerdict(t *testing.T) {
	exp := constModel{id: "exp", role: RoleExperimental, class: classScan}
	prim := constModel{id: "prim", role: RolePrimary, class: classNormal}

	res := NewRuntime(exp, prim).Score(zeroVec(1))

	if res.Class != "normal" || res.ClassID != classNormal {
		t.Fatalf("primary (normal) must drive the verdict, got %s/%d", res.Class, res.ClassID)
	}
	if len(res.Models) != 2 {
		t.Fatalf("want 2 recorded model outputs, got %d", len(res.Models))
	}
	if !hasModelOutput(res.Models, "exp", "scan") {
		t.Fatalf("experimental prediction must still be recorded: %+v", res.Models)
	}
}

// An experimental model disagreeing with the primary must NOT raise the
// disagreement flag.
func TestScoreExperimentalDisagreementIgnored(t *testing.T) {
	prim := constModel{id: "prim", role: RolePrimary, class: classScan}
	exp := constModel{id: "exp", role: RoleExperimental, class: classNormal}

	res := NewRuntime(prim, exp).Score(zeroVec(2))

	if res.Class != "scan" {
		t.Fatalf("verdict should be scan, got %s", res.Class)
	}
	if res.Disagreement {
		t.Fatalf("experimental disagreeing with primary must NOT set Disagreement")
	}
}

// Two alert-driving supervised models (primary + global/location) with
// different top classes DO raise the disagreement flag.
func TestScoreSupervisedPeersDisagreement(t *testing.T) {
	prim := constModel{id: "prim", role: RolePrimary, class: classScan}
	glob := constModel{id: "glob", role: RoleGlobal, class: classNormal}
	loc := constModel{id: "loc", role: RoleLocation, class: classScan}

	res := NewRuntime(prim, glob, loc).Score(zeroVec(3))

	if !res.Disagreement {
		t.Fatalf("primary=scan vs global=normal must set Disagreement")
	}
	if res.Class != "scan" {
		t.Fatalf("primary still drives the verdict, got %s", res.Class)
	}
}

// The anomaly model emits a novelty score, not a supervised class: it is
// excluded from the disagreement set (unchanged behaviour) but its output is
// still recorded.
func TestScoreAnomalyExcludedFromDisagreement(t *testing.T) {
	prim := constModel{id: "prim", role: RolePrimary, class: classScan}
	anom := constModel{id: "anom", role: RoleAnomaly, class: classNormal}

	res := NewRuntime(prim, anom).Score(zeroVec(4))

	if res.Disagreement {
		t.Fatalf("anomaly model must not contribute to Disagreement")
	}
	if !hasModelOutput(res.Models, "anom", "normal") {
		t.Fatalf("anomaly output must still be recorded: %+v", res.Models)
	}
}

// With no RolePrimary present, the first non-experimental model drives the
// verdict; experimental peers are still skipped.
func TestScoreNoPrimaryUsesFirstNonExperimental(t *testing.T) {
	exp := constModel{id: "exp", role: RoleExperimental, class: classScan}
	glob := constModel{id: "glob", role: RoleGlobal, class: classNormal}
	loc := constModel{id: "loc", role: RoleLocation, class: classScan}

	res := NewRuntime(exp, glob, loc).Score(zeroVec(5))

	if res.Class != "normal" {
		t.Fatalf("first non-experimental model (global=normal) should drive, got %s", res.Class)
	}
	if !res.Disagreement {
		t.Fatalf("global=normal vs location=scan must set Disagreement")
	}
}

// A RolePrimary listed after its peers still wins the verdict.
func TestScorePrimaryWinsWhenListedLast(t *testing.T) {
	glob := constModel{id: "glob", role: RoleGlobal, class: classNormal}
	prim := constModel{id: "prim", role: RolePrimary, class: classScan}

	res := NewRuntime(glob, prim).Score(zeroVec(6))

	if res.Class != "scan" {
		t.Fatalf("primary listed last must still drive the verdict, got %s", res.Class)
	}
}

// An ensemble of only experimental models falls back to the first model so the
// Result is never left empty, and disagreement is never raised.
func TestScoreAllExperimentalFallsBackToFirst(t *testing.T) {
	a := constModel{id: "a", role: RoleExperimental, class: classScan}
	b := constModel{id: "b", role: RoleExperimental, class: classNormal}

	res := NewRuntime(a, b).Score(zeroVec(7))

	if res.Class != "scan" {
		t.Fatalf("all-experimental ensemble should fall back to the first model (scan), got %s", res.Class)
	}
	if res.Disagreement {
		t.Fatalf("experimental-only ensemble must never set Disagreement")
	}
}
