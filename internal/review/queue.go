package review

import (
	"math"
	"sort"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// The review queue and its active-learning ranking (PROJECT.md §16; issues #42,
// #64).
//
// # Why rank at all
//
// A person can review a few hundred flows a day; a sensor produces that many in
// a minute. So the order the queue offers them in *is* the product. Issue #64
// asks for active learning: spend the human's attention where the model is least
// able to spend its own.
//
// # The uncertainty formula: margin
//
//	margin = p_top1 - p_top2
//
// over the authoritative model's 7-class traffic-classes-v1 probability vector,
// sorted ascending — smallest margin first. `uncertainty` is reported as
// 1 - margin so bigger always means "review me sooner".
//
// Margin is chosen over entropy because it measures the thing a reviewer
// actually resolves: which of two classes is this? A flow at
// {normal 0.49, scan 0.48, …} has a tiny margin and is a genuine coin-flip a
// human settles in one glance. Entropy would rank {0.4, 0.3, 0.3} — diffuse but
// not contested — above it, which is the less useful question. Margin is also
// the standard active-learning acquisition function for exactly this reason
// (Scheffer et al.'s "smallest margin"), and it is cheap and explainable: the UI
// can print the two classes that are fighting.
//
// Normalised Shannon entropy is computed and reported anyway, because it is the
// better summary of "the model has no idea at all" and costs nothing:
//
//	entropy = -Σ pᵢ ln pᵢ / ln 7      (0 = certain, 1 = uniform)
//
// Degenerate cases, all handled explicitly:
//
//   - a uniform vector (all 1/7) → margin 0, entropy 1: maximally uncertain,
//     ranks first. This is also what an untrained or broken model looks like,
//     which is the correct thing to surface to a human.
//   - no probability vector at all (no model output, or a vector summing to
//     zero) → ScoresAvailable false, margin 0, entropy 1. "We know nothing" is
//     maximally uncertain; hiding it would let a silently-failing model keep its
//     flows out of review.
//   - fewer than two non-zero classes cannot happen (the vector is fixed at 7),
//     so top2 always exists; a one-hot vector gives margin 1, entropy 0, last.
//
// Ties break by newest first, so the order is total and stable.
//
// # What is in the queue
//
// Flows that still need a human. A flow is excluded when its review state is
// terminal — correct, incorrect or ignored_pattern — because a decision has been
// made. `unsure` stays in: the operator said "I don't know", which is a request
// to come back to it, not an answer. `unreviewed` (explicit or implied by having
// no record) obviously stays in.
//
// One entry per flow: a long flow is classified repeatedly (periodic snapshots),
// and the newest verdict wins, matching dataset.build.

// Sort is a queue ordering.
type Sort string

// Queue orderings.
const (
	// SortRecent is newest verdict first — the default, and what an operator
	// watching live traffic expects.
	SortRecent Sort = "recent"
	// SortUncertainty is the issue #64 active-learning order: smallest
	// top1-top2 margin first.
	SortUncertainty Sort = "uncertainty"
	// SortDisagreement puts flows the ensemble disagreed on first, then falls
	// back to the uncertainty order within each group. Multi-model disagreement
	// is the other high-value review signal (PROJECT.md §12).
	SortDisagreement Sort = "disagreement"
)

// Sorts lists the orderings in a stable order for error messages and the UI.
func Sorts() []Sort { return []Sort{SortUncertainty, SortRecent, SortDisagreement} }

// SortNames is Sorts() as strings.
func SortNames() []string {
	ss := Sorts()
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, string(s))
	}
	return out
}

// ParseSort maps a query value to a Sort. "" means SortRecent.
func ParseSort(v string) (Sort, bool) {
	if v == "" {
		return SortRecent, true
	}
	for _, s := range Sorts() {
		if string(s) == v {
			return s, true
		}
	}
	return "", false
}

// QueueItem is one flow awaiting review: the tuple and the model's claim, plus
// the ranking numbers so the UI can show *why* a row is near the top.
type QueueItem struct {
	FlowID        uint64    `json:"flow_id"`
	TS            time.Time `json:"ts"`
	Sensor        string    `json:"sensor"`
	Proto         string    `json:"proto"`
	InitiatorIP   string    `json:"initiator_ip"`
	InitiatorPort uint16    `json:"initiator_port"`
	ResponderIP   string    `json:"responder_ip"`
	ResponderPort uint16    `json:"responder_port"`

	// The model's prediction. This is *not* the §16 stored prediction — nothing
	// is captured until the operator reviews the flow; it is the live verdict the
	// queue is asking about.
	PredictedClass string           `json:"predicted_class"`
	PredictedScore float64          `json:"predicted_score"`
	ModelID        string           `json:"model_id"`
	Disagreement   bool             `json:"disagreement"`
	Scores         inference.Scores `json:"scores"`

	// Ranking. Top1/Top2 name the two classes the margin is between.
	Top1 string `json:"top1"`
	Top2 string `json:"top2"`
	// Margin is p_top1 - p_top2, 0..1. Smaller = less sure.
	Margin float64 `json:"margin"`
	// Uncertainty is 1 - Margin, so larger = review sooner. This is the value
	// SortUncertainty orders by (descending).
	Uncertainty float64 `json:"uncertainty"`
	// Entropy is normalised Shannon entropy over the 7 classes, 0..1.
	Entropy float64 `json:"entropy"`
	// ScoresAvailable is false when the verdict carried no usable probability
	// vector; Margin/Entropy then report maximal uncertainty.
	ScoresAvailable bool `json:"scores_available"`

	// ReviewState is StateUnreviewed or StateUnsure — the only non-terminal
	// states, and therefore the only ones that reach the queue.
	ReviewState State `json:"review_state"`
	// Note carries forward an earlier `unsure` note so the next reviewer sees
	// what stumped the last one.
	Note string `json:"note,omitempty"`
}

// QueueOptions selects the ordering and the page size.
type QueueOptions struct {
	Sort  Sort
	Limit int
}

// Queue ranks the flows in rows that still need a human.
//
// rows are stored classifications, newest first, already narrowed by whatever
// class/model/min_confidence/disagreement filters the caller applied (the API
// reuses parseClassFilters so those predicates mean the same thing here as
// everywhere else). Queue dedupes by flow id, drops terminal review states,
// computes the ranking numbers and returns at most Limit items.
func (s *Store) Queue(rows []storage.Classification, opt QueueOptions) []QueueItem {
	if opt.Sort == "" {
		opt.Sort = SortRecent
	}
	out := make([]QueueItem, 0, min(len(rows), 512))
	seen := make(map[uint64]bool, len(rows))
	for _, c := range rows {
		if c.FlowID == 0 || seen[c.FlowID] {
			continue // newest verdict already taken for this flow
		}
		seen[c.FlowID] = true

		st := StateUnreviewed
		note := ""
		if r, ok := s.Get(c.FlowID); ok {
			st, note = r.State, r.Note
		}
		if st.Terminal() {
			continue // decided: correct / incorrect / ignored_pattern
		}
		out = append(out, newQueueItem(c, st, note))
	}

	sortQueue(out, opt.Sort)
	if opt.Limit > 0 && len(out) > opt.Limit {
		out = out[:opt.Limit]
	}
	return out
}

// newQueueItem denormalises one classification and computes its ranking numbers.
func newQueueItem(c storage.Classification, st State, note string) QueueItem {
	it := QueueItem{
		FlowID:         c.FlowID,
		TS:             c.TS,
		Sensor:         c.Sensor,
		Proto:          c.Proto,
		InitiatorIP:    c.InitiatorIP,
		InitiatorPort:  c.InitiatorPort,
		ResponderIP:    c.ResponderIP,
		ResponderPort:  c.ResponderPort,
		PredictedClass: c.Result.Class,
		PredictedScore: c.Result.Score,
		Disagreement:   c.Result.Disagreement,
		ReviewState:    st,
		Note:           note,
	}
	if m := primaryOutput(c.Result); m != nil {
		it.ModelID = m.ModelID
		it.Scores = m.Scores
	}
	rk := rank(it.Scores)
	it.Margin, it.Uncertainty, it.Entropy, it.ScoresAvailable = rk.margin, 1-rk.margin, rk.entropy, rk.available
	names := classNames()
	if rk.available {
		it.Top1 = nameAt(names, rk.top1)
		it.Top2 = nameAt(names, rk.top2)
	}
	return it
}

// ranking is the numeric output of the uncertainty formula.
type ranking struct {
	margin    float64
	entropy   float64
	top1      int
	top2      int
	available bool
}

// rank computes margin and normalised entropy over a 7-class probability
// vector. See the file comment for the formula and the degenerate cases.
func rank(s inference.Scores) ranking {
	sum := 0.0
	for _, v := range s {
		if isFinite(v) && v > 0 {
			sum += v
		}
	}
	if sum <= 0 {
		// No usable distribution: maximal uncertainty, flagged as such.
		return ranking{margin: 0, entropy: 1, top1: -1, top2: -1, available: false}
	}

	// Normalise defensively: a model bundle is validated, but a hand-rolled or
	// experimental classifier may hand back an unnormalised vector, and the
	// margin must not depend on its scale.
	i1, i2 := -1, -1
	p1, p2 := -1.0, -1.0
	entropy := 0.0
	for i, raw := range s {
		v := 0.0
		if isFinite(raw) && raw > 0 {
			v = raw / sum
		}
		if v > p1 {
			i2, p2 = i1, p1
			i1, p1 = i, v
		} else if v > p2 {
			i2, p2 = i, v
		}
		if v > 0 {
			entropy -= v * math.Log(v)
		}
	}
	if p2 < 0 {
		p2, i2 = 0, -1
	}
	n := float64(len(s))
	if n > 1 {
		entropy /= math.Log(n) // 0..1
	}
	return ranking{
		margin:    clamp01(p1 - p2),
		entropy:   clamp01(entropy),
		top1:      i1,
		top2:      i2,
		available: true,
	}
}

// sortQueue applies the requested ordering. sort.SliceStable is not needed —
// every comparator below is total (it ends in a flow-id tiebreak), so the result
// is deterministic regardless of the input order.
func sortQueue(q []QueueItem, by Sort) {
	newest := func(i, j int) bool {
		if !q[i].TS.Equal(q[j].TS) {
			return q[i].TS.After(q[j].TS)
		}
		return q[i].FlowID > q[j].FlowID
	}
	leastSure := func(i, j int) bool {
		if q[i].Margin != q[j].Margin {
			return q[i].Margin < q[j].Margin
		}
		return newest(i, j)
	}
	switch by {
	case SortUncertainty:
		sort.Slice(q, leastSure)
	case SortDisagreement:
		sort.Slice(q, func(i, j int) bool {
			if q[i].Disagreement != q[j].Disagreement {
				return q[i].Disagreement // true first
			}
			return leastSure(i, j)
		})
	default: // SortRecent
		sort.Slice(q, newest)
	}
}

func nameAt(names []string, i int) string {
	if i < 0 || i >= len(names) {
		return ""
	}
	return names[i]
}

func clamp01(f float64) float64 {
	if !isFinite(f) || f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
