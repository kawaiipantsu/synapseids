package review_test

import (
	"math"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// ids returns the flow ids of a queue, in order.
func ids(q []review.QueueItem) []uint64 {
	out := make([]uint64, 0, len(q))
	for _, it := range q {
		out = append(out, it.FlowID)
	}
	return out
}

func eqIDs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The synthetic set the ranking tests share. The probability vectors are chosen
// so the margin order is obvious by eye:
//
//	flow  vector (normal, scan, …)          margin  note
//	  10  0.99 / 0.01                        0.98   very confident
//	  20  0.51 / 0.49                        0.02   a near-tie
//	  30  1/7 × 7                            0.00   uniform: no idea at all
//	  40  0.70 / 0.20                        0.50   middling
func rankingStore() *storage.Mem {
	u := 1.0 / 7.0
	return store(
		verdict(10, "normal", 0.99, scores(0.99, 0.01)),
		verdict(20, "normal", 0.51, scores(0.51, 0.49)),
		verdict(30, "normal", u, scores(u, u, u, u, u, u, u)),
		verdict(40, "normal", 0.70, scores(0.70, 0.20, 0.10)),
	)
}

func TestQueueUncertaintyOrdersByMargin(t *testing.T) {
	st := rankingStore()
	s, _ := open(t, st)

	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortUncertainty})
	want := []uint64{30, 20, 40, 10} // margin 0.00, 0.02, 0.50, 0.98
	if got := ids(q); !eqIDs(got, want) {
		t.Fatalf("uncertainty order = %v, want %v", got, want)
	}

	// The near-tie must outrank the confident flow — the whole point of #64.
	if q[1].FlowID != 20 || q[len(q)-1].FlowID != 10 {
		t.Errorf("the near-tie (20) should sit above the confident flow (10): %v", ids(q))
	}

	// Margins and the reported uncertainty must agree.
	for _, it := range q {
		if math.Abs(it.Uncertainty-(1-it.Margin)) > 1e-9 {
			t.Errorf("flow %d: uncertainty %g != 1 - margin %g", it.FlowID, it.Uncertainty, it.Margin)
		}
		if it.Margin < 0 || it.Margin > 1 || it.Entropy < 0 || it.Entropy > 1 {
			t.Errorf("flow %d: margin %g / entropy %g outside 0..1", it.FlowID, it.Margin, it.Entropy)
		}
		if !it.ScoresAvailable {
			t.Errorf("flow %d: scores_available false, but a vector was stored", it.FlowID)
		}
	}

	byID := map[uint64]review.QueueItem{}
	for _, it := range q {
		byID[it.FlowID] = it
	}
	if got := byID[20].Margin; math.Abs(got-0.02) > 1e-9 {
		t.Errorf("flow 20 margin = %g, want 0.02", got)
	}
	if got := byID[20].Top1; got != "normal" {
		t.Errorf("flow 20 top1 = %q, want normal", got)
	}
	if got := byID[20].Top2; got != "scan" {
		t.Errorf("flow 20 top2 = %q, want scan", got)
	}
}

// TestQueueDegenerateUniformVector pins the all-equal case: margin 0, entropy 1,
// first in the queue.
func TestQueueDegenerateUniformVector(t *testing.T) {
	u := 1.0 / 7.0
	st := store(verdict(30, "normal", u, scores(u, u, u, u, u, u, u)))
	s, _ := open(t, st)

	q := s.Queue(st.RecentClassifications(10), review.QueueOptions{Sort: review.SortUncertainty})
	if len(q) != 1 {
		t.Fatalf("queue = %d items, want 1", len(q))
	}
	if q[0].Margin != 0 {
		t.Errorf("margin = %g, want exactly 0 for a uniform vector", q[0].Margin)
	}
	if math.Abs(q[0].Entropy-1) > 1e-9 {
		t.Errorf("entropy = %g, want 1 for a uniform vector", q[0].Entropy)
	}
	if q[0].Uncertainty != 1 {
		t.Errorf("uncertainty = %g, want 1", q[0].Uncertainty)
	}
}

// TestQueueOneHotVectorIsLast: a one-hot distribution is maximally certain.
func TestQueueOneHotVectorIsLast(t *testing.T) {
	st := store(
		verdict(1, "normal", 1, scores(1)),
		verdict(2, "normal", 0.5, scores(0.5, 0.5)),
	)
	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(10), review.QueueOptions{Sort: review.SortUncertainty})
	if got := ids(q); !eqIDs(got, []uint64{2, 1}) {
		t.Fatalf("order = %v, want the coin-flip first", got)
	}
	if q[1].Margin != 1 || q[1].Entropy != 0 {
		t.Errorf("one-hot: margin %g entropy %g, want 1 and 0", q[1].Margin, q[1].Entropy)
	}
}

// TestQueueMissingProbabilityVector: a verdict with no usable distribution is
// treated as maximally uncertain and flagged, not hidden.
func TestQueueMissingProbabilityVector(t *testing.T) {
	noModels := verdict(50, "normal", 0.9, scores(0.9, 0.1))
	noModels.Result.Models = nil
	allZero := verdict(60, "normal", 0, inference.Scores{})

	st := store(
		verdict(10, "normal", 0.99, scores(0.99, 0.01)),
		noModels,
		allZero,
	)
	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(10), review.QueueOptions{Sort: review.SortUncertainty})

	if q[len(q)-1].FlowID != 10 {
		t.Errorf("the confident flow should be last: %v", ids(q))
	}
	for _, it := range q {
		if it.FlowID == 10 {
			continue
		}
		if it.ScoresAvailable {
			t.Errorf("flow %d: scores_available true with no usable vector", it.FlowID)
		}
		if it.Margin != 0 || it.Entropy != 1 {
			t.Errorf("flow %d: margin %g entropy %g, want maximal uncertainty", it.FlowID, it.Margin, it.Entropy)
		}
		if it.Top1 != "" || it.Top2 != "" {
			t.Errorf("flow %d: top1/top2 should be blank without a vector, got %q/%q", it.FlowID, it.Top1, it.Top2)
		}
	}
}

// TestQueueUnnormalisedVector: the margin must not depend on the vector's scale.
func TestQueueUnnormalisedVector(t *testing.T) {
	st := store(verdict(1, "normal", 5.1, scores(5.1, 4.9)))
	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(10), review.QueueOptions{})
	if got := q[0].Margin; math.Abs(got-0.02) > 1e-9 {
		t.Errorf("margin = %g, want 0.02 after normalisation", got)
	}
}

func TestQueueDisagreementFirst(t *testing.T) {
	dis := func(c *storage.Classification) { c.Result.Disagreement = true }
	st := store(
		verdict(10, "normal", 0.99, scores(0.99, 0.01)),      // certain, agrees
		verdict(20, "normal", 0.51, scores(0.51, 0.49)),      // near-tie, agrees
		verdict(30, "normal", 0.95, scores(0.95, 0.05), dis), // certain, disagrees
		verdict(40, "normal", 0.60, scores(0.60, 0.40), dis), // fuzzy, disagrees
	)
	s, _ := open(t, st)

	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortDisagreement})
	// Disagreeing flows first (40 then 30, by margin), then the rest by margin.
	want := []uint64{40, 30, 20, 10}
	if got := ids(q); !eqIDs(got, want) {
		t.Fatalf("disagreement order = %v, want %v", got, want)
	}
	if !q[0].Disagreement || !q[1].Disagreement {
		t.Error("the first two items should be the disagreeing ones")
	}
}

func TestQueueRecentIsTheDefault(t *testing.T) {
	st := rankingStore()
	s, _ := open(t, st)

	// verdict() stamps TS = baseTS + id seconds, so 40 is newest.
	want := []uint64{40, 30, 20, 10}
	for _, opt := range []review.QueueOptions{{}, {Sort: review.SortRecent}} {
		if got := ids(s.Queue(st.RecentClassifications(100), opt)); !eqIDs(got, want) {
			t.Errorf("Queue(%+v) = %v, want %v", opt, got, want)
		}
	}
}

// TestQueueExcludesTerminalStatesButKeepsUnsure is the exclusion rule §16
// implies: a decided flow leaves the queue, an undecided one does not.
func TestQueueExcludesTerminalStatesButKeepsUnsure(t *testing.T) {
	cs := []storage.Classification{}
	for id := uint64(1); id <= 5; id++ {
		cs = append(cs, verdict(id, "normal", 0.5, scores(0.5, 0.5)))
	}
	st := store(cs...)
	s, _ := open(t, st)

	mustPut(t, s, 1, review.StateCorrect, "", "")        // terminal → out
	mustPut(t, s, 2, review.StateIncorrect, "scan", "")  // terminal → out
	mustPut(t, s, 3, review.StateIgnoredPattern, "", "") // terminal → out
	mustPut(t, s, 4, review.StateUnsure, "", "which is it?")
	mustPut(t, s, 5, review.StateUnreviewed, "", "")

	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortRecent})
	if got := ids(q); !eqIDs(got, []uint64{5, 4}) {
		t.Fatalf("queue = %v, want only the unreviewed (5) and unsure (4) flows", got)
	}
	byID := map[uint64]review.QueueItem{}
	for _, it := range q {
		byID[it.FlowID] = it
	}
	if byID[4].ReviewState != review.StateUnsure {
		t.Errorf("flow 4 review_state = %q, want unsure", byID[4].ReviewState)
	}
	if byID[4].Note != "which is it?" {
		t.Errorf("flow 4 note = %q — an unsure note must carry forward to the next reviewer", byID[4].Note)
	}
	if byID[5].ReviewState != review.StateUnreviewed {
		t.Errorf("flow 5 review_state = %q, want unreviewed", byID[5].ReviewState)
	}
}

// TestQueueOneEntryPerFlow: a long flow is classified repeatedly; the newest
// verdict wins, as in dataset.build.
func TestQueueOneEntryPerFlow(t *testing.T) {
	st := storage.NewMem(100, 100)
	old := verdict(1, "normal", 0.9, scores(0.9, 0.1))
	old.TS = baseTS
	fresh := verdict(1, "scan", 0.55, scores(0.45, 0.55))
	fresh.TS = baseTS.Add(time.Minute)
	st.PutClassification(old)
	st.PutClassification(fresh)
	// A second flow so the queue is not single-element by accident.
	st.PutClassification(verdict(2, "normal", 0.99, scores(0.99, 0.01)))

	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortRecent})
	count := 0
	for _, it := range q {
		if it.FlowID == 1 {
			count++
			if it.PredictedClass != "scan" {
				t.Errorf("flow 1 predicted class = %q, want the newest verdict scan", it.PredictedClass)
			}
		}
	}
	if count != 1 {
		t.Errorf("flow 1 appears %d times, want 1", count)
	}
}

func TestQueueLimit(t *testing.T) {
	st := rankingStore()
	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{Sort: review.SortUncertainty, Limit: 2})
	if got := ids(q); !eqIDs(got, []uint64{30, 20}) {
		t.Fatalf("limited queue = %v, want the two least-certain flows", got)
	}
}

func TestQueueCarriesTheTupleAndTheModel(t *testing.T) {
	st := rankingStore()
	s, _ := open(t, st)
	q := s.Queue(st.RecentClassifications(100), review.QueueOptions{})
	it := q[0]
	if it.InitiatorIP != "10.0.0.5" || it.ResponderIP != "10.0.0.9" || it.ResponderPort != 80 || it.Proto != "TCP" {
		t.Errorf("queue item lost the tuple: %+v", it)
	}
	if it.ModelID != "heuristic-v1" {
		t.Errorf("model_id = %q, want heuristic-v1", it.ModelID)
	}
	if it.Sensor != "local" {
		t.Errorf("sensor = %q, want local", it.Sensor)
	}
}

func TestParseSort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want review.Sort
		ok   bool
	}{
		{"", review.SortRecent, true},
		{"recent", review.SortRecent, true},
		{"uncertainty", review.SortUncertainty, true},
		{"disagreement", review.SortDisagreement, true},
		{"Uncertainty", "", false},
		{"margin", "", false},
	} {
		got, ok := review.ParseSort(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ParseSort(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestStateTerminalAndLabelled(t *testing.T) {
	for _, tc := range []struct {
		s                  review.State
		terminal, labelled bool
	}{
		{review.StateUnreviewed, false, false},
		{review.StateCorrect, true, true},
		{review.StateIncorrect, true, true},
		{review.StateUnsure, false, false},
		{review.StateIgnoredPattern, true, false},
	} {
		if tc.s.Terminal() != tc.terminal {
			t.Errorf("%q.Terminal() = %v, want %v", tc.s, tc.s.Terminal(), tc.terminal)
		}
		if tc.s.Labelled() != tc.labelled {
			t.Errorf("%q.Labelled() = %v, want %v", tc.s, tc.s.Labelled(), tc.labelled)
		}
		if !tc.s.Valid() {
			t.Errorf("%q.Valid() = false", tc.s)
		}
	}
	if review.State("nearly").Valid() {
		t.Error(`State("nearly").Valid() = true`)
	}
	if len(review.States()) != 5 {
		t.Errorf("States() = %d, want the 5 §16 states", len(review.States()))
	}
	if len(review.ClassNames()) != 7 {
		t.Errorf("ClassNames() = %d, want the 7 traffic-classes-v1 classes", len(review.ClassNames()))
	}
}
