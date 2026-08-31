// Package review is the human review loop (PROJECT.md §16; issues #42, #64).
//
// Every classification is reviewable. An operator marks a verdict correct,
// corrects it with the right traffic-classes-v1 class, says they are unsure, or
// mutes the pattern; the reviewed flows then become a curated dataset whose
// labels came from a person rather than from the daemon grading its own homework
// (internal/dataset, `reviewed` selection).
//
// # The §16 invariant
//
// "Always retain the original model prediction separately from the
// human-reviewed label." That sentence is the whole point of this package, so it
// is enforced structurally rather than by convention. Two locks:
//
//  1. The prediction lives in an unexported `prediction` value inside Review.
//     Its fields are unexported and it has no exported constructor, so no code
//     outside this package can build or assign one. Readers get
//     PredictedClass/PredictedScore/ModelID accessors and the flat
//     predicted_class / predicted_score / model_id JSON keys.
//
//  2. The only write entry point is Put(flowID, state, label, note) — it takes
//     no prediction argument, so a caller has nothing to pass. The store reads
//     the prediction itself, once, from the classification store on the *first*
//     review of a flow. Every later Put copies the stored value forward
//     verbatim; nothing in this package ever assigns to an existing record's
//     prediction. See TestPredictionIsNeverOverwritten.
//
// A correction therefore adds information (state, human label, history) and can
// never destroy the model's original claim — even if the model has since been
// replaced and the flow re-classified differently.
//
// # Persistence
//
// One JSON file per reviewed flow under review.directory, written atomically
// (temp file + rename) and reloaded on start; a corrupt or unreadable file is
// logged and skipped, never fatal — the posture registry.Open, dataset.Open and
// training.Open all take (PROJECT.md §21). The store is safe for concurrent use.
//
// # Why reviews are not capped
//
// Every other store here is bounded because a packet, a flow or a verdict
// arrives at wire speed. A review does not: it is created by a person clicking a
// button, so growth is human-paced — a busy operator might produce a few hundred
// a day, tens of kilobytes. Capping would silently discard the most expensive
// data in the system (hand-labelled ground truth) to save nothing. Reviews are
// therefore retained until an operator deletes the directory. See ADR 0021.
package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// State is a §16 review state.
type State string

// The five review states of PROJECT.md §16. There is no sixth: the enum is the
// spec's, and a new one would be a spec change.
const (
	// StateUnreviewed is the default for a flow nobody has looked at. It is
	// storable: writing it is how an operator un-reviews a flow and puts it back
	// in the queue, with the previous decision preserved in History.
	StateUnreviewed State = "unreviewed"
	// StateCorrect — the human agrees with the model. The effective label is the
	// prediction they confirmed.
	StateCorrect State = "correct"
	// StateIncorrect — the model was wrong; human_label carries the right class.
	StateIncorrect State = "incorrect"
	// StateUnsure — the human could not decide. Stays in the review queue so a
	// second pair of eyes (or more context) can finish the job.
	StateUnsure State = "unsure"
	// StateIgnoredPattern — "stop showing me this". A judgement about the queue,
	// not about the traffic's class, so it carries no label and is excluded from
	// curated datasets unless explicitly opted in.
	StateIgnoredPattern State = "ignored_pattern"
)

// States lists the five states in a stable order, for error messages and the UI.
func States() []State {
	return []State{StateUnreviewed, StateCorrect, StateIncorrect, StateUnsure, StateIgnoredPattern}
}

// StateNames is States() as strings.
func StateNames() []string {
	ss := States()
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, string(s))
	}
	return out
}

// Valid reports whether s is one of the five §16 states.
func (s State) Valid() bool {
	for _, k := range States() {
		if k == s {
			return true
		}
	}
	return false
}

// Terminal reports whether the state settles the flow and therefore removes it
// from the review queue. `unsure` is deliberately *not* terminal: the operator
// said "I don't know", which is a request to come back to it, not an answer
// (PROJECT.md §16). `unreviewed` is not terminal either — it is the absence of a
// decision.
func (s State) Terminal() bool {
	switch s {
	case StateCorrect, StateIncorrect, StateIgnoredPattern:
		return true
	default:
		return false
	}
}

// Labelled reports whether the state carries a class a trainer can learn from:
// `correct` (the confirmed prediction) and `incorrect` (the correction). An
// `ignored_pattern` row has no human class — see dataset's include_ignored.
func (s State) Labelled() bool { return s == StateCorrect || s == StateIncorrect }

// prediction is the model verdict captured at the moment of the first review.
//
// Its fields are unexported and it has no exported constructor or setter: this
// is lock (1) of the §16 invariant. Outside this package the values are
// reachable only through Review's accessors and its JSON form, both read-only.
// Inside this package the value is produced exactly once, by capture(), and
// afterwards only ever copied.
type prediction struct {
	class   string
	score   float64
	modelID string
}

// capture reads the model's claim off a stored classification. It is the only
// constructor of a prediction, and Put calls it only when a flow has no review
// yet.
func capture(c storage.Classification) prediction {
	p := prediction{class: c.Result.Class, score: c.Result.Score}
	if m := primaryOutput(c.Result); m != nil {
		p.modelID = m.ModelID
	}
	if p.modelID == "" && len(c.Result.Models) > 0 {
		p.modelID = c.Result.Models[0].ModelID
	}
	return p
}

// Change is one superseded decision, kept so a correction is traceable.
type Change struct {
	// TS is when this decision was *replaced*, i.e. the UpdatedAt it had.
	TS         string `json:"ts"`
	State      State  `json:"state"`
	HumanLabel string `json:"human_label,omitempty"`
	Note       string `json:"note,omitempty"`
	Reviewer   string `json:"reviewer"`
}

// Review is one flow's review record: the human's decision alongside — never
// instead of — the model's original prediction.
//
// The fields carry no struct tags: MarshalJSON/UnmarshalJSON below define the
// wire and on-disk form, because the prediction is unexported and cannot be
// tagged.
type Review struct {
	FlowID     uint64
	State      State
	HumanLabel string

	// pred holds predicted_class / predicted_score / model_id. Unexported on
	// purpose; see the package comment.
	pred prediction

	Reviewer  string
	Note      string
	CreatedAt string
	UpdatedAt string
	History   []Change
}

// PredictedClass is the traffic-classes-v1 class the model claimed when this
// flow was first reviewed. Read-only by construction.
func (r Review) PredictedClass() string { return r.pred.class }

// PredictedScore is the model's confidence in PredictedClass at review time.
func (r Review) PredictedScore() float64 { return r.pred.score }

// ModelID names the model whose prediction is recorded here.
func (r Review) ModelID() string { return r.pred.modelID }

// EffectiveLabel is the class a curated dataset would use for this flow, or ""
// when the state implies none:
//
//	correct         → the prediction the human confirmed
//	incorrect       → the human's correction
//	everything else → "" (no human class was asserted)
//
// It is derived on every read, so it can never drift from state/human_label.
func (r Review) EffectiveLabel() string {
	switch r.State {
	case StateCorrect:
		if r.HumanLabel != "" {
			return r.HumanLabel
		}
		return r.pred.class
	case StateIncorrect:
		return r.HumanLabel
	default:
		return ""
	}
}

// Agrees reports whether the human's effective label matches the model's
// original prediction. Useful for a confusion view; also the reason `correct`
// may omit human_label.
func (r Review) Agrees() bool {
	l := r.EffectiveLabel()
	return l != "" && l == r.pred.class
}

// reviewJSON is the wire and on-disk form. It exists because the prediction's
// fields are unexported and so cannot carry struct tags of their own; keeping
// the mapping in one place also keeps the JSON flat, which is what the SPA and
// the dataset builder want.
type reviewJSON struct {
	FlowID     uint64 `json:"flow_id"`
	State      State  `json:"state"`
	HumanLabel string `json:"human_label"`
	// EffectiveLabel is derived (see Review.EffectiveLabel). It is emitted for
	// readers and deliberately ignored on load so a hand-edited file cannot
	// introduce a label that state/human_label do not support.
	EffectiveLabel string `json:"effective_label"`
	PredictedClass string `json:"predicted_class"`
	// PredictedScore is the model's confidence, 0..1.
	PredictedScore float64  `json:"predicted_score"`
	ModelID        string   `json:"model_id"`
	Reviewer       string   `json:"reviewer"`
	Note           string   `json:"note"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	History        []Change `json:"history"`
}

// MarshalJSON writes the flat §16 record.
func (r Review) MarshalJSON() ([]byte, error) {
	h := r.History
	if h == nil {
		h = []Change{}
	}
	return json.Marshal(reviewJSON{
		FlowID:         r.FlowID,
		State:          r.State,
		HumanLabel:     r.HumanLabel,
		EffectiveLabel: r.EffectiveLabel(),
		PredictedClass: r.pred.class,
		PredictedScore: r.pred.score,
		ModelID:        r.pred.modelID,
		Reviewer:       r.Reviewer,
		Note:           r.Note,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		History:        h,
	})
}

// UnmarshalJSON reads a record back off disk. This is the only path that fills
// the prediction from outside a live classification, and it exists solely so a
// restart does not lose it. It never runs against request data: the REST layer
// decodes its own request struct and calls Put, which takes no prediction.
func (r *Review) UnmarshalJSON(b []byte) error {
	var w reviewJSON
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&w); err != nil {
		return err
	}
	*r = Review{
		FlowID:     w.FlowID,
		State:      w.State,
		HumanLabel: w.HumanLabel,
		pred:       prediction{class: w.PredictedClass, score: w.PredictedScore, modelID: w.ModelID},
		Reviewer:   w.Reviewer,
		Note:       w.Note,
		CreatedAt:  w.CreatedAt,
		UpdatedAt:  w.UpdatedAt,
		History:    w.History,
	}
	if r.History == nil {
		r.History = []Change{}
	}
	return nil
}

// Errors callers match with errors.Is to choose an HTTP status.
var (
	// ErrInvalid is an unknown state, a human_label that is not a
	// traffic-classes-v1 class, or a state/label combination that contradicts
	// itself. Maps to 400.
	ErrInvalid = errors.New("review: invalid review")
	// ErrNoFlow is a flow with no stored classification to review — usually one
	// that has already been evicted from the bounded store. Maps to 404.
	ErrNoFlow = errors.New("review: flow has no stored classification")
)

// PredictionScan is how many recent verdicts Put walks to find the flow's
// classification. The memory store has no index by flow id, so this is a linear
// scan of the newest window — the same shape as the api classification filters,
// just wider, because reviewing is a human-paced action well off the packet path
// (PROJECT.md §22). A verdict older than this window can no longer be reviewed;
// Put says so with ErrNoFlow. A predicate-pushdown backend (SQLite) removes the
// limit.
const PredictionScan = 50_000

// Source is the read side of the classification store this package needs: the
// model verdict behind a flow id. *storage.Mem and any future storage.Store
// satisfy it.
//
// Note what is *not* here: nothing that would let a caller supply a prediction.
// The store fetches it; that is lock (2) of the §16 invariant.
type Source interface {
	RecentClassifications(limit int) []storage.Classification
}

// Publisher is the event-bus write side. *events.Bus satisfies it; nil disables
// publishing. events.ReviewUpdated is already a member of the frozen
// event-envelope-v1 enum, so no schema change was needed (PROJECT.md §17).
type Publisher interface {
	Publish(t events.Type, data any)
}

// Logf is a structured-log sink; cmd/synapsed passes log.Printf.
type Logf func(format string, args ...any)

// fileSuffix is the per-review file extension under the review directory.
const fileSuffix = ".json"

// Store is the review record store: a memory index over one JSON file per
// reviewed flow.
type Store struct {
	mu   sync.RWMutex
	dir  string
	src  Source
	bus  Publisher
	aud  *audit.Logger
	logf Logf
	now  func() time.Time
	// byFlow values are replaced wholesale, never mutated in place, so a reader
	// holding a *Review from before a Put keeps a consistent snapshot.
	byFlow map[uint64]*Review
}

// Open returns a Store over dir, loading every review file it can parse.
//
// src is the classification store Put reads the prediction from; it may be nil
// in a read-only context, in which case Put fails cleanly with ErrNoFlow. bus
// and aud may be nil (publishing/auditing become no-ops). A missing directory is
// not an error — it is created on the first write.
//
// The signature carries src because the store must fetch the prediction itself:
// handing it in as a Put argument is exactly the hole §16 warns about. It mirrors
// dataset.Open(dir, src, …), the established shape here for a store that reads
// the flow store.
func Open(dir string, src Source, bus Publisher, aud *audit.Logger, logf Logf) *Store {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Store{
		dir:    dir,
		src:    src,
		bus:    bus,
		aud:    aud,
		logf:   logf,
		now:    time.Now,
		byFlow: map[uint64]*Review{},
	}
	s.load()
	return s
}

// Dir returns the store's directory.
func (s *Store) Dir() string { return s.dir }

// load scans dir for *.json review files. A file that cannot be read or parsed,
// or that carries an id/state the code does not recognise, is logged and skipped
// so one bad file cannot wedge the daemon (PROJECT.md §21).
func (s *Store) load() {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*"+fileSuffix))
	if err != nil {
		s.logf("review: cannot scan %q: %v — starting empty", s.dir, err)
		return
	}
	skipped := 0
	for _, path := range matches {
		raw, rerr := os.ReadFile(path) //nolint:gosec // path from Glob of the configured dir
		if rerr != nil {
			s.logf("review: cannot read %q: %v — skipping", path, rerr)
			skipped++
			continue
		}
		var r Review
		if uerr := json.Unmarshal(raw, &r); uerr != nil {
			s.logf("review: %q is corrupt (%v) — skipping", path, uerr)
			skipped++
			continue
		}
		if r.FlowID == 0 {
			s.logf("review: %q has no flow_id — skipping", path)
			skipped++
			continue
		}
		if !r.State.Valid() {
			s.logf("review: %q has unknown state %q — skipping", path, r.State)
			skipped++
			continue
		}
		if r.Reviewer == "" {
			r.Reviewer = audit.ActorLocal
		}
		cp := r
		s.byFlow[r.FlowID] = &cp
	}
	s.logf("review: loaded %d review(s) from %q (%d skipped)", len(s.byFlow), s.dir, skipped)
}

// Put records or replaces a human decision for one flow.
//
// It takes no prediction: on the first review of a flow the store captures the
// model's verdict from the classification store, and on every later review it
// copies the captured value forward untouched. state must be one of the five
// §16 states; label must be a traffic-classes-v1 class or "" and must not
// contradict state (see validate).
//
// Returns the stored record. Publishes events.ReviewUpdated and writes one
// audit line per successful write (PROJECT.md §21, §28.15).
func (s *Store) Put(flowID uint64, state State, label, note string) (Review, error) {
	if flowID == 0 {
		return Review{}, fmt.Errorf("%w: flow id 0 is not a flow", ErrInvalid)
	}
	if !state.Valid() {
		return Review{}, fmt.Errorf("%w: unknown state %q (want one of %s)", ErrInvalid, state, strings.Join(StateNames(), ", "))
	}
	label = strings.TrimSpace(label)
	if label != "" && !validClass(label) {
		return Review{}, fmt.Errorf("%w: %q is not a traffic-classes-v1 class (want one of %s)", ErrInvalid, label, strings.Join(classNames(), ", "))
	}
	note = strings.TrimSpace(note)
	if len(note) > MaxNoteLen {
		return Review{}, fmt.Errorf("%w: note is %d bytes, the limit is %d", ErrInvalid, len(note), MaxNoteLen)
	}

	s.mu.Lock()
	cur, existing := s.byFlow[flowID]

	// The prediction: captured once, then carried forward. There is exactly one
	// assignment to upd.pred in this package and it is the `capture` branch
	// below, reached only when the flow has no review yet.
	var upd Review
	switch {
	case existing:
		upd = *cur // copies pred verbatim — the §16 invariant in one line
		upd.History = append(append([]Change{}, cur.History...), Change{
			TS:         cur.UpdatedAt,
			State:      cur.State,
			HumanLabel: cur.HumanLabel,
			Note:       cur.Note,
			Reviewer:   cur.Reviewer,
		})
	default:
		c, ok := s.classificationFor(flowID)
		if !ok {
			s.mu.Unlock()
			return Review{}, fmt.Errorf("%w: flow %d is not in the classification store — it was never classified, or its verdict has already been evicted from the bounded ring, so there is no prediction to review against", ErrNoFlow, flowID)
		}
		upd = Review{
			FlowID:    flowID,
			pred:      capture(c),
			CreatedAt: s.nowStr(),
			History:   []Change{},
		}
	}

	if err := validate(state, label, upd.pred.class); err != nil {
		s.mu.Unlock()
		return Review{}, err
	}

	upd.State = state
	upd.HumanLabel = label
	upd.Note = note
	upd.Reviewer = audit.ActorLocal // TODO(#58): the authenticated operator
	upd.UpdatedAt = s.nowStr()

	if err := s.persistLocked(&upd); err != nil {
		s.mu.Unlock()
		return Review{}, err
	}
	stored := upd
	s.byFlow[flowID] = &stored
	s.mu.Unlock()

	s.publish(stored)
	return stored, nil
}

// MaxNoteLen bounds an operator's free-text note. Notes are operator-typed, not
// packet-derived, but the API still caps them so a stray paste cannot grow a
// review file without limit (PROJECT.md §21).
const MaxNoteLen = 4096

// validate enforces the state/label rules. They are the ones §16 implies once
// "retain the prediction separately" is taken seriously: a state either asserts
// a class or it does not, and it may never assert one that contradicts itself.
//
//	unreviewed      no label — it is the absence of a decision
//	correct         label optional; when given it must equal the prediction,
//	                because "correct" *means* "the prediction is the label".
//	                Omitted, the label is derived from the prediction.
//	incorrect       label required, and it must differ from the prediction —
//	                agreeing with the model is `correct`, not `incorrect`
//	unsure          no label — the operator said they do not know
//	ignored_pattern no label — "stop showing me this" is not "this is class X"
func validate(state State, label, predicted string) error {
	switch state {
	case StateCorrect:
		if label != "" && label != predicted {
			return fmt.Errorf("%w: state \"correct\" means the model was right, but human_label %q differs from the prediction %q — use \"incorrect\" to correct a verdict", ErrInvalid, label, predicted)
		}
		if label == "" && predicted == "" {
			return fmt.Errorf("%w: state \"correct\" has no prediction to confirm for this flow", ErrInvalid)
		}
	case StateIncorrect:
		if label == "" {
			return fmt.Errorf("%w: state \"incorrect\" requires human_label — the correct class (one of %s)", ErrInvalid, strings.Join(classNames(), ", "))
		}
		if label == predicted {
			return fmt.Errorf("%w: state \"incorrect\" with human_label %q equal to the prediction says the model was both wrong and right — use \"correct\" instead", ErrInvalid, label)
		}
	case StateUnreviewed, StateUnsure, StateIgnoredPattern:
		if label != "" {
			return fmt.Errorf("%w: state %q asserts no class, so human_label must be empty (got %q)", ErrInvalid, state, label)
		}
	}
	return nil
}

// classificationFor finds the newest stored verdict for flowID. The caller holds
// s.mu; the scan touches only the classification store, which has its own lock.
func (s *Store) classificationFor(flowID uint64) (storage.Classification, bool) {
	if s.src == nil {
		return storage.Classification{}, false
	}
	// Newest first, so the first hit is the freshest verdict — the same
	// "newest verdict wins" rule dataset.build uses for snapshot flows.
	for _, c := range s.src.RecentClassifications(PredictionScan) {
		if c.FlowID == flowID {
			return c, true
		}
	}
	return storage.Classification{}, false
}

// publish mirrors a write to the live event bus and the durable audit log. The
// bus drops under backpressure by design, so the audit log is the record an
// operator audits after the fact (PROJECT.md §17, §21).
func (s *Store) publish(r Review) {
	if s.bus != nil {
		s.bus.Publish(events.ReviewUpdated, map[string]any{
			"flow_id":         r.FlowID,
			"state":           string(r.State),
			"human_label":     r.EffectiveLabel(),
			"predicted_class": r.PredictedClass(),
		})
	}
	if s.aud != nil {
		s.aud.LogSubject(audit.EventReviewUpdated, audit.ActorLocal, audit.SubjectReview,
			strconv.FormatUint(r.FlowID, 10),
			fmt.Sprintf("state=%s human_label=%s predicted_class=%s predicted_score=%.4f model_id=%s revisions=%d",
				r.State, orDash(r.EffectiveLabel()), orDash(r.PredictedClass()), r.PredictedScore(), orDash(r.ModelID()), len(r.History)))
	}
	s.logf("review: flow %d → %s (human_label=%s, prediction kept: %s %.1f%% by %s)",
		r.FlowID, r.State, orDash(r.EffectiveLabel()), orDash(r.PredictedClass()), r.PredictedScore()*100, orDash(r.ModelID()))
}

// Get returns the review for a flow.
func (s *Store) Get(flowID uint64) (Review, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byFlow[flowID]
	if !ok {
		return Review{}, false
	}
	return *r, true
}

// StateOf returns the recorded state for a flow, or StateUnreviewed when the
// flow has never been reviewed. This is what the queue filters on.
func (s *Store) StateOf(flowID uint64) State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.byFlow[flowID]; ok {
		return r.State
	}
	return StateUnreviewed
}

// Filter selects reviews for List. Every field is optional; the zero Filter
// means "everything".
type Filter struct {
	// State keeps only reviews in this state.
	State State
	// Labelled keeps only reviews whose state asserts a class (correct or
	// incorrect) — what a curated dataset can learn from.
	Labelled bool
	// IncludeIgnored, with Labelled, also keeps ignored_pattern reviews. It has
	// no effect on its own.
	IncludeIgnored bool
	// Limit caps the result at the newest N (0 = no cap).
	Limit int
}

func (f Filter) match(r *Review) bool {
	if f.State != "" && r.State != f.State {
		return false
	}
	if f.Labelled && !r.State.Labelled() {
		// The one exception: an explicit opt-in also keeps ignored_pattern, whose
		// label is the (unconfirmed) prediction. See dataset's include_ignored.
		if !f.IncludeIgnored || r.State != StateIgnoredPattern {
			return false
		}
	}
	return true
}

// List returns matching reviews, most recently updated first; equal timestamps
// fall back to flow id descending so the order is total and stable.
func (s *Store) List(f Filter) []Review {
	s.mu.RLock()
	out := make([]Review, 0, len(s.byFlow))
	for _, r := range s.byFlow {
		if f.match(r) {
			out = append(out, *r)
		}
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return out[i].FlowID > out[j].FlowID
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Stats is a per-state count snapshot for the review strip.
type Stats struct {
	Total int `json:"total"`
	// ByState has an entry for every one of the five states, zero included, so
	// the UI strip does not change shape as reviews arrive.
	ByState map[string]int `json:"by_state"`
	// Terminal is correct + incorrect + ignored_pattern: settled, out of the
	// queue.
	Terminal int `json:"terminal"`
	// Open is unreviewed + unsure: still in the queue.
	Open int `json:"open"`
	// Labelled is correct + incorrect: rows a curated dataset can use.
	Labelled  int    `json:"labelled"`
	Directory string `json:"directory"`
}

// Stats counts the stored reviews per state.
func (s *Store) Stats() Stats {
	st := Stats{ByState: map[string]int{}, Directory: s.dir}
	for _, k := range States() {
		st.ByState[string(k)] = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.byFlow {
		st.Total++
		st.ByState[string(r.State)]++
		if r.State.Terminal() {
			st.Terminal++
		} else {
			st.Open++
		}
		if r.State.Labelled() {
			st.Labelled++
		}
	}
	return st
}

func (s *Store) nowStr() string { return s.now().UTC().Format(time.RFC3339) }

// persistLocked writes one review file atomically (temp file + rename), the same
// primitive training.persistLocked uses. The caller holds s.mu.
func (s *Store) persistLocked(r *Review) error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("review: cannot create %q: %w", s.dir, err)
	}
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("review: marshal flow %d: %w", r.FlowID, err)
	}
	name := strconv.FormatUint(r.FlowID, 10)
	tmp, err := os.CreateTemp(s.dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("review: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(blob, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("review: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("review: close temp: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(s.dir, name+fileSuffix)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("review: rename: %w", err)
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------

// primaryOutput returns the ensemble's authoritative model output: the first
// with RolePrimary, else the first output, else nil. It mirrors
// inference.Runtime's role contract and the Flow Inspector's choice, so the
// probability vector the queue ranks on is the one the UI shows.
func primaryOutput(res inference.Result) *inference.ModelOutput {
	for i := range res.Models {
		if res.Models[i].Role == inference.RolePrimary {
			return &res.Models[i]
		}
	}
	if len(res.Models) > 0 {
		return &res.Models[0]
	}
	return nil
}

func validClass(name string) bool {
	for _, c := range schema.TrafficClassesV1().Classes {
		if c.Name == name {
			return true
		}
	}
	return false
}

// classNames lists traffic-classes-v1 in frozen schema order.
func classNames() []string {
	cs := schema.TrafficClassesV1().Classes
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// ClassNames exposes the traffic-classes-v1 class names an operator may pick
// from, in frozen schema order, for error messages and the UI's class picker.
func ClassNames() []string { return classNames() }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func isFinite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
