package dataset_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// The curated (human-reviewed) cut — PROJECT.md §16, issue #42. These tests are
// the gate: labeling_source may say "human_review" only when the labels in
// dataset.csv actually came from a person.

// reviewed builds a store of n alternating normal/scan flows plus a review store
// over them, and returns both. reviewFn decides what the operator did with each
// flow id.
func reviewed(t *testing.T, n int, reviewFn func(id uint64) (review.State, string)) (*storage.Mem, *review.Store) {
	t.Helper()
	st := twoClassStore(t, n)
	rv := review.Open(t.TempDir(), st, nil, nil, quiet)
	for id := uint64(1); id <= uint64(n); id++ { //nolint:gosec // small loop bound
		state, label := reviewFn(id)
		if state == "" {
			continue
		}
		if _, err := rv.Put(id, state, label, ""); err != nil {
			t.Fatalf("review flow %d as %s/%q: %v", id, state, label, err)
		}
	}
	return st, rv
}

// labelsByFlow maps a dataset CSV's rows to their labels. The CSV has no flow-id
// column, but rows are sorted by flow id, so the i-th data row belongs to the
// i-th selected flow.
func labelsInOrder(t *testing.T, d *dataset.Dataset) []string {
	t.Helper()
	rows := csvRows(t, filepath.Join(d.Dir, dataset.CSVFileName))
	out := make([]string, 0, len(rows))
	for _, line := range rows {
		cols := strings.Split(line, ",")
		out = append(out, cols[len(cols)-1])
	}
	return out
}

func reviewedSpec(id string) dataset.Spec {
	s := spec(id)
	s.Selection = dataset.Selection{Reviewed: true}
	return s
}

// TestReviewedCutUsesHumanLabels is the headline test: the CSV label column
// carries the operator's decision, not the model's prediction, and the manifest
// says so.
func TestReviewedCutUsesHumanLabels(t *testing.T) {
	// Odd flows are class "normal" and the human agrees. Even flows are class
	// "scan" and the human says they are actually brute_force.
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)

	d, err := m.Create(reviewedSpec("hq/reviewed-2026-09"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if d.LabelingSource != "human_review" {
		t.Errorf("labeling_source = %q, want %q", d.LabelingSource, "human_review")
	}
	if d.FlowCount != 40 {
		t.Fatalf("flow_count = %d, want 40", d.FlowCount)
	}
	want := map[string]int{"normal": 20, "brute_force": 20}
	for k, v := range want {
		if d.LabelCounts[k] != v {
			t.Errorf("label_counts[%s] = %d, want %d", k, d.LabelCounts[k], v)
		}
	}
	if d.LabelCounts["scan"] != 0 {
		t.Errorf("label_counts[scan] = %d — the model's rejected prediction must not appear as a label", d.LabelCounts["scan"])
	}

	// Row order is flow id ascending, so labels alternate normal, brute_force, …
	labels := labelsInOrder(t, d)
	if len(labels) != 40 {
		t.Fatalf("csv has %d data rows, want 40", len(labels))
	}
	for i, got := range labels {
		flowID := i + 1
		exp := "normal"
		if flowID%2 == 0 {
			exp = "brute_force"
		}
		if got != exp {
			t.Fatalf("row %d (flow %d) label = %q, want %q", i, flowID, got, exp)
		}
	}
	if !d.Selection.Reviewed {
		t.Error("the manifest's selection does not record reviewed:true")
	}
	// Every existing guarantee still holds.
	if d.FeatureCount != 48 || len(d.Columns) != 49 {
		t.Errorf("feature_count = %d, columns = %d — the trainer contract changed", d.FeatureCount, len(d.Columns))
	}
	if !strings.HasPrefix(d.ContentHash, "sha256:") {
		t.Errorf("content_hash = %q", d.ContentHash)
	}
	if d.TimeRange.From == "" || d.TimeRange.To == "" {
		t.Errorf("time_range = %+v, want the flows' span", d.TimeRange)
	}
}

// TestReviewedCutExcludesUnsureAndIgnored: only a settled human class becomes a
// training row.
func TestReviewedCutExcludesUnsureAndIgnored(t *testing.T) {
	// 1..30 are decided; 31..40 are unsure or muted and must not appear.
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		switch {
		case id > 35:
			return review.StateIgnoredPattern, ""
		case id > 30:
			return review.StateUnsure, ""
		case id%2 == 1:
			return review.StateCorrect, ""
		default:
			return review.StateIncorrect, "brute_force"
		}
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)

	d, err := m.Create(reviewedSpec("hq/settled"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.FlowCount != 30 {
		t.Errorf("flow_count = %d, want 30 (unsure and ignored_pattern excluded)", d.FlowCount)
	}
	if d.LabelingSource != "human_review" {
		t.Errorf("labeling_source = %q, want human_review", d.LabelingSource)
	}
	total := 0
	for _, n := range d.LabelCounts {
		total += n
	}
	if total != 30 {
		t.Errorf("label counts total %d, want 30", total)
	}
}

// TestReviewedCutWithIncludeIgnoredIsHonestlyMixed: opting ignored_pattern in
// means part of the cut is labelled by the model, and labeling_source says so.
func TestReviewedCutWithIncludeIgnoredIsHonestlyMixed(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		switch {
		case id > 30:
			return review.StateIgnoredPattern, "" // 10 muted, class "normal"/"scan"
		case id%2 == 1:
			return review.StateCorrect, ""
		default:
			return review.StateIncorrect, "brute_force"
		}
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)

	spec := reviewedSpec("hq/mixed-cut")
	spec.Selection.IncludeIgnored = true
	d, err := m.Create(spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.FlowCount != 40 {
		t.Errorf("flow_count = %d, want 40 with include_ignored", d.FlowCount)
	}
	if d.LabelingSource != "human_review+model_prediction:heuristic-v1" {
		t.Errorf("labeling_source = %q, want the mixed value naming the model", d.LabelingSource)
	}
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "ignored_pattern") && strings.Contains(w, "unconfirmed") {
			found = true
		}
	}
	if !found {
		t.Errorf("a mixed cut must warn about the unconfirmed rows; warnings = %v", d.Warnings)
	}
}

// TestIncludeIgnoredNeedsReviewed rejects a meaningless combination up front.
func TestIncludeIgnoredNeedsReviewed(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), nil, quiet)
	s := spec("x/bad")
	s.Selection = dataset.Selection{IncludeIgnored: true}
	_, err := m.Create(s)
	if !errors.Is(err, dataset.ErrInvalid) {
		t.Fatalf("Create → %v, want ErrInvalid", err)
	}
}

// TestReviewedRejectsDisagreementFilter: a review record does not carry the
// ensemble's disagreement flag, so the combination is refused rather than
// silently ignored.
func TestReviewedRejectsDisagreementFilter(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), nil, quiet)
	s := spec("x/bad2")
	s.Selection = dataset.Selection{Reviewed: true, Disagreement: true}
	_, err := m.Create(s)
	if !errors.Is(err, dataset.ErrInvalid) {
		t.Fatalf("Create → %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "disagreement") {
		t.Errorf("error should name the offending field: %v", err)
	}
}

// TestReviewedWithNoReviewStoreFailsCleanly — a read-only manager must not
// pretend it can produce human labels.
func TestReviewedWithNoReviewStoreFailsCleanly(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), nil, quiet)
	_, err := m.Create(reviewedSpec("x/no-reviews"))
	if !errors.Is(err, dataset.ErrInvalid) {
		t.Fatalf("Create → %v, want ErrInvalid", err)
	}
}

// TestReviewedWithNothingReviewedIsUnusable — the guard rails still apply.
func TestReviewedWithNothingReviewedIsUnusable(t *testing.T) {
	st := twoClassStore(t, 40)
	rv := review.Open(t.TempDir(), st, nil, nil, quiet)
	m := dataset.Open(t.TempDir(), st, rv, quiet)
	_, err := m.Create(reviewedSpec("x/empty"))
	if !errors.Is(err, dataset.ErrUnusable) {
		t.Fatalf("Create → %v, want ErrUnusable", err)
	}
	if !strings.Contains(err.Error(), "review some flows first") {
		t.Errorf("the error should tell the operator what to do: %v", err)
	}
}

// TestReviewedRefusesASingleClassCut keeps the one-class guard rail.
func TestReviewedRefusesASingleClassCut(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		if id%2 == 1 {
			return review.StateCorrect, "" // all "normal"
		}
		return review.StateIncorrect, "normal" // scan corrected to normal too
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)
	_, err := m.Create(reviewedSpec("x/one-class"))
	if !errors.Is(err, dataset.ErrUnusable) {
		t.Fatalf("Create → %v, want ErrUnusable", err)
	}
	if !strings.Contains(err.Error(), "one class") {
		t.Errorf("error = %v", err)
	}
}

// TestReviewedRefusesBelowTheRowFloor keeps the MinRows guard rail.
func TestReviewedRefusesBelowTheRowFloor(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		if id > 10 {
			return "", ""
		}
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)
	_, err := m.Create(reviewedSpec("x/too-small"))
	if !errors.Is(err, dataset.ErrUnusable) {
		t.Fatalf("Create → %v, want ErrUnusable", err)
	}
	if !strings.Contains(err.Error(), "row floor") {
		t.Errorf("error = %v", err)
	}
}

// TestReviewedCutFiltersOnTheHumanLabel: in a reviewed cut, `class` means "the
// label a human settled on", which is the only reading that makes sense.
func TestReviewedCutFiltersOnTheHumanLabel(t *testing.T) {
	st, rv := reviewed(t, 60, func(id uint64) (review.State, string) {
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)
	s := reviewedSpec("x/only-brute")
	s.Selection.Class = "brute_force"
	_, err := m.Create(s)
	// Every remaining row is one class, which the guard rail refuses — and the
	// message must name the *human* label, proving the filter matched on it.
	if !errors.Is(err, dataset.ErrUnusable) {
		t.Fatalf("Create → %v, want ErrUnusable", err)
	}
	if !strings.Contains(err.Error(), `"brute_force"`) {
		t.Errorf("the one-class refusal should name brute_force: %v", err)
	}
}

// TestReviewedCutIsImmutableAndReproducible: two identical reviewed cuts hash
// the same, and an existing version is never overwritten.
func TestReviewedCutIsImmutableAndReproducible(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	a, err := dataset.Open(t.TempDir(), st, rv, quiet).Create(reviewedSpec("x/repro"))
	if err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b, err := dataset.Open(t.TempDir(), st, rv, quiet).Create(reviewedSpec("x/repro"))
	if err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("content hash is not reproducible: %s vs %s", a.ContentHash, b.ContentHash)
	}

	m := dataset.Open(t.TempDir(), st, rv, quiet)
	if _, err := m.Create(reviewedSpec("x/twice")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := m.Create(reviewedSpec("x/twice")); !errors.Is(err, dataset.ErrExists) {
		t.Fatalf("second create → %v, want ErrExists", err)
	}
}

// TestReviewedCutRecordsLineage: derive works on the curated path too.
func TestReviewedCutRecordsLineage(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)
	parent, err := m.Create(reviewedSpec("hq/curated"))
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	child := reviewedSpec("hq/curated")
	child.Version = "v2"
	d, err := m.Derive(parent.ID, parent.Version, child)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(d.ParentDatasets) == 0 || d.ParentDatasets[0] != parent.Ref() {
		t.Errorf("parent_datasets = %v, want %s first", d.ParentDatasets, parent.Ref())
	}
	if d.LabelingSource != "human_review" {
		t.Errorf("labeling_source = %q, want human_review", d.LabelingSource)
	}
}

// TestModelLabelledCutIsUnchanged is the regression guard: everything above is
// additive, and a default cut must still say model_prediction.
func TestModelLabelledCutIsUnchanged(t *testing.T) {
	st, rv := reviewed(t, 40, func(id uint64) (review.State, string) {
		// Reviews exist, but a default cut must ignore them entirely.
		if id%2 == 1 {
			return review.StateCorrect, ""
		}
		return review.StateIncorrect, "brute_force"
	})
	m := dataset.Open(t.TempDir(), st, rv, quiet)

	d, err := m.Create(spec("hq/model-labelled")) // no Selection.Reviewed
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.LabelingSource != "model_prediction:heuristic-v1" {
		t.Errorf("labeling_source = %q, want model_prediction:heuristic-v1", d.LabelingSource)
	}
	if d.LabelCounts["brute_force"] != 0 {
		t.Errorf("a model-labelled cut leaked a human label: %v", d.LabelCounts)
	}
	if d.LabelCounts["normal"] != 20 || d.LabelCounts["scan"] != 20 {
		t.Errorf("label_counts = %v, want the model's own 20/20 split", d.LabelCounts)
	}
	if d.Selection.Reviewed {
		t.Error("selection.reviewed is set on a default cut")
	}
}
