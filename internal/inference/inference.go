// Package inference scores flow feature vectors with one or more models and
// combines their verdicts. Phase 1 ships a single rule-based model; Phase 2 adds
// ONNX models loaded from validated bundles. The runtime always records each
// model's individual output, not just the combined decision (PROJECT.md §12).
package inference

import (
	"sort"
	"sync"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Role is a model's operational role in the ensemble (PROJECT.md §12).
type Role string

// Model roles.
const (
	RolePrimary      Role = "primary"
	RoleLocation     Role = "location"
	RoleGlobal       Role = "global"
	RoleSequence     Role = "sequence"
	RoleExperimental Role = "experimental"
	RoleAnomaly      Role = "anomaly"
)

// OutputSize mirrors traffic-classes-v1.
const OutputSize = 7

// Scores is a probability distribution over traffic-classes-v1.
type Scores [OutputSize]float64

func init() {
	if got := schema.TrafficClassesV1().OutputSize; got != OutputSize {
		panic("inference: OutputSize out of sync with traffic-classes-v1")
	}
}

// Top returns the highest-scoring class index and its probability.
func (s Scores) Top() (idx int, p float64) {
	for i, v := range s {
		if v > p {
			idx, p = i, v
		}
	}
	return idx, p
}

// Classifier is one model. Family is the locked contract it belongs to; ID is a
// unique instance name; Role places it in the ensemble.
type Classifier interface {
	ID() string
	Family() string
	Role() Role
	Classify(v features.Vector) Scores
}

// ModelOutput is one model's verdict for one flow.
type ModelOutput struct {
	ModelID string  `json:"model_id"`
	Role    Role    `json:"role"`
	Class   string  `json:"class"`
	ClassID int     `json:"class_id"`
	Score   float64 `json:"score"`
	Scores  Scores  `json:"scores"`
}

// AnomalyScorer is a novelty detector: it reconstructs the feature vector and
// reports the reconstruction error as an anomaly score, not a class
// distribution. It always has RoleAnomaly, never drives the ensemble verdict and
// never contributes to Result.Disagreement — an autoencoder answers "how
// unfamiliar is this flow", not "which class" (PROJECT.md §13, ADR 0037).
type AnomalyScorer interface {
	ID() string
	Family() string
	Role() Role
	ScoreAnomaly(v features.Vector) AnomalyOutput
}

// FeatureDelta is one feature's reconstruction gap in normalized-input space:
// what the model was fed (Input), what it reconstructed (Output), and their
// difference (Delta = Output - Input).
type FeatureDelta struct {
	Index  int     `json:"index"`
	Name   string  `json:"name"`
	Input  float64 `json:"input"`
	Output float64 `json:"output"`
	Delta  float64 `json:"delta"`
}

// SequenceScorer is a temporal classifier: it scores the last T feature vectors
// of one conversation (a [T, 48] window, oldest first) into a
// traffic-classes-v1 distribution. It is a supervised peer *with memory* — its
// top class feeds Result.Models and the disagreement set exactly like a
// location/global peer, but it never drives the verdict (PROJECT.md §30, issue
// #62, ADR 0040). Always RoleSequence.
type SequenceScorer interface {
	ID() string
	Family() string
	Role() Role
	// ScoreSequence takes the window oldest-first, length 1..T. The
	// implementation left-pads a short window to its fixed T.
	ScoreSequence(window [][features.Size]float64) Scores
}

// AnomalyOutput is one anomaly model's full verdict for one flow, including the
// largest per-feature reconstruction gaps for an explain view. Runtime.Score
// keeps only the scalars (see AnomalyResult); the per-flow log never stores the
// deltas.
type AnomalyOutput struct {
	ModelID    string         `json:"model_id"`
	Available  bool           `json:"available"`
	ReconError float64        `json:"recon_error"`
	Score      float64        `json:"score"`
	Threshold  float64        `json:"threshold"`
	Exceeds    bool           `json:"exceeds"`
	TopDeltas  []FeatureDelta `json:"top_deltas,omitempty"`
}

// AnomalyResult is the ensemble-level anomaly verdict recorded on Result: five
// scalars, additive and optional so a Result with no anomaly model serialises
// exactly as before (ADR 0037).
type AnomalyResult struct {
	Available  bool    `json:"available"`
	ModelID    string  `json:"model_id"`
	Score      float64 `json:"score"`
	ReconError float64 `json:"recon_error"`
	Threshold  float64 `json:"threshold"`
	Exceeds    bool    `json:"exceeds"`
}

// Result is the ensemble verdict for one flow.
type Result struct {
	FlowID       uint64         `json:"flow_id"`
	Class        string         `json:"class"`
	ClassID      int            `json:"class_id"`
	Score        float64        `json:"score"`
	Disagreement bool           `json:"disagreement"`
	Models       []ModelOutput  `json:"models"`
	Anomaly      *AnomalyResult `json:"anomaly,omitempty"`
}

// Runtime holds the loaded models and scores flows through all of them. It is
// safe for concurrent use: the packet path calls Score while an operator's
// activate/deactivate request swaps the model set (PROJECT.md §22, §28.10).
type Runtime struct {
	mu              sync.RWMutex
	models          []Classifier    // the live supervised set Score iterates
	fallback        []Classifier    // restored by Deactivate — the models NewRuntime was given
	anomaly         []AnomalyScorer // the live anomaly-role models Score also runs
	fallbackAnomaly []AnomalyScorer // restored when the anomaly role is deactivated (nil in the daemon)

	sequence         []SequenceScorer // the live temporal peers ScoreSequence runs
	fallbackSequence []SequenceScorer // restored when the sequence role is deactivated (nil in the daemon)
}

// NewRuntime returns a Runtime over the given models. The first model with
// RolePrimary is authoritative; if none is primary the first non-experimental
// model wins (see Score for the full role contract). The models passed here are
// also the fallback set Deactivate restores — cmd/synapsed starts the Runtime
// with just inference.Heuristic, so deactivating a trained model returns the
// daemon to the transparent rule-based classifier.
func NewRuntime(models ...Classifier) *Runtime {
	return &Runtime{models: models, fallback: models}
}

// live returns the current model slice under the read lock. The slice is
// replaced wholesale by Activate/Deactivate/SetModels and never mutated in
// place, so a caller may range over the returned value without holding the lock.
func (r *Runtime) live() []Classifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.models
}

// Models returns the currently loaded classifiers.
func (r *Runtime) Models() []Classifier { return r.live() }

// liveAnomaly returns the current anomaly-model slice under the read lock. Like
// models it is replaced wholesale, never mutated in place.
func (r *Runtime) liveAnomaly() []AnomalyScorer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.anomaly
}

// AnomalyModels returns the currently loaded anomaly-role models.
func (r *Runtime) AnomalyModels() []AnomalyScorer { return r.liveAnomaly() }

// SetAnomalyModels atomically replaces the live anomaly-model slice. It is the
// general form for tests and multi-model wiring; it does not change the fallback
// set. Passing no models clears the anomaly role.
func (r *Runtime) SetAnomalyModels(models ...AnomalyScorer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.anomaly = models
}

// liveSequence returns the current temporal-model slice under the read lock.
func (r *Runtime) liveSequence() []SequenceScorer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sequence
}

// SequenceModels returns the currently loaded temporal (flow-sequence-v1) models.
func (r *Runtime) SequenceModels() []SequenceScorer { return r.liveSequence() }

// SetSequenceModels atomically replaces the live temporal-model slice. It does
// not change the fallback set; passing no models clears the sequence role.
func (r *Runtime) SetSequenceModels(models ...SequenceScorer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence = models
}

// Activate atomically replaces the live model set with a single trained primary
// (issue #26 / PROJECT.md §29 steps 16–18). It never runs on load, scan or
// startup — only an explicit operator action reaches here. A concurrent Score
// either sees the whole previous set or the whole new one, never a mix.
func (r *Runtime) Activate(primary Classifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.models = []Classifier{primary}
}

// Deactivate atomically restores the fallback set NewRuntime was given (the
// heuristic, in the daemon), so classification keeps flowing after a trained
// model is turned off.
func (r *Runtime) Deactivate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.models = r.fallback
}

// SetModels atomically replaces the live model set with an arbitrary ensemble.
// It is the general form of Activate for tests and future multi-model wiring; it
// does not change the fallback set.
func (r *Runtime) SetModels(models ...Classifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.models = models
}

// ActivateRole atomically installs one trained model in the given role, leaving
// every other role's live models untouched — unlike Activate, which replaces the
// whole supervised set. model must be an *AnomalyScorer for RoleAnomaly, a
// *SequenceScorer for RoleSequence, or a Classifier otherwise; a mismatched or
// nil model is a no-op. It runs only from an explicit operator action, never on
// load or startup (PROJECT.md §28.10).
func (r *Runtime) ActivateRole(role Role, model any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch role {
	case RoleAnomaly:
		if m, ok := model.(AnomalyScorer); ok && m != nil {
			r.anomaly = []AnomalyScorer{m}
		}
	case RoleSequence:
		if m, ok := model.(SequenceScorer); ok && m != nil {
			r.sequence = []SequenceScorer{m}
		}
	default:
		if m, ok := model.(Classifier); ok && m != nil {
			r.models = []Classifier{m}
		}
	}
}

// DeactivateRole atomically removes the given role's trained model. The
// supervised roles fall back to the set NewRuntime was given (the heuristic, in
// the daemon); the anomaly and sequence roles fall back to their own fallback
// sets (nil in the daemon, so that role simply goes dark).
func (r *Runtime) DeactivateRole(role Role) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch role {
	case RoleAnomaly:
		r.anomaly = r.fallbackAnomaly
	case RoleSequence:
		r.sequence = r.fallbackSequence
	default:
		r.models = r.fallback
	}
}

// Score runs every loaded model over v and combines their outputs into one
// ensemble Result. Each model's individual verdict is always recorded in
// Result.Models — never just the combined decision (PROJECT.md §12).
//
// Role contract (locked here, exercised by inference_test.go):
//
//   - primary — authoritative; drives Result.Class / ClassID / Score.
//   - location, global — supervised peers; never drive the verdict, but a top
//     class differing from another driving model raises Result.Disagreement.
//   - experimental — shadow model (PROJECT.md §12): recorded in Result.Models,
//     but never influences the verdict and never contributes to
//     Result.Disagreement.
//   - sequence — temporal classifier over the flow's [T, 48] history. Runs only
//     when Score is called with a window (see ScoreSequence). Its top class is
//     recorded in Result.Models and joins the disagreement set like a
//     location/global peer, but it never drives the verdict.
//   - anomaly — novelty detector: reconstruction error, not a supervised class.
//     Anomaly models run through the separate AnomalyScorer path; their verdict
//     lands in Result.Anomaly and never touches Result.Class/Score/Disagreement
//     or Result.Models.
//
// Verdict driver: the first primary model; absent any primary, the first
// non-experimental model; if every loaded model is experimental, the first model
// (so Result is never left empty).
//
// Disagreement is true when the alert-driving models — every role except
// experimental and anomaly — predict more than one distinct top class.
func (r *Runtime) Score(v features.Vector) Result {
	return r.score(v, nil)
}

// ScoreSequence is Score plus the temporal (flow-sequence-v1) peers, given the
// flow's recent feature-vector history (oldest first, length 1..T). The pipeline
// supplies the window from its per-flow ring; every other caller uses Score.
func (r *Runtime) ScoreSequence(v features.Vector, window [][features.Size]float64) Result {
	return r.score(v, window)
}

func (r *Runtime) score(v features.Vector, window [][features.Size]float64) Result {
	res := Result{FlowID: v.FlowID}
	var driver *ModelOutput
	primaryLocked := false
	seen := map[int]int{}

	models := r.live()
	for i := range models {
		m := models[i]
		sc := m.Classify(v)
		id, p := sc.Top()
		mo := ModelOutput{
			ModelID: m.ID(), Role: m.Role(),
			Class: schema.ClassName(id), ClassID: id, Score: p, Scores: sc,
		}
		res.Models = append(res.Models, mo)

		if m.Role() != RoleAnomaly && m.Role() != RoleExperimental {
			seen[id]++
		}

		switch {
		case m.Role() == RolePrimary && !primaryLocked:
			d := mo
			driver, primaryLocked = &d, true
		case !primaryLocked && driver == nil && m.Role() != RoleExperimental:
			d := mo
			driver = &d
		}
	}

	// Temporal peers: score the [T, 48] window, if one was supplied. A sequence
	// model is a supervised peer with memory — its top class joins Result.Models
	// and the disagreement set, but it is never a verdict driver.
	if len(window) > 0 {
		for _, sm := range r.liveSequence() {
			sc := sm.ScoreSequence(window)
			id, p := sc.Top()
			res.Models = append(res.Models, ModelOutput{
				ModelID: sm.ID(), Role: sm.Role(),
				Class: schema.ClassName(id), ClassID: id, Score: p, Scores: sc,
			})
			seen[id]++
		}
	}

	if driver == nil && len(res.Models) > 0 {
		d := res.Models[0] // every model is experimental — keep it simple
		driver = &d
	}
	if driver != nil {
		res.Class, res.ClassID, res.Score = driver.Class, driver.ClassID, driver.Score
	}
	// Disagreement: more than one distinct top class among the alert-driving
	// models (experimental and anomaly excluded; sequence peers included).
	res.Disagreement = len(seen) > 1

	// Anomaly models score in parallel: a reconstruction error, not a class.
	// In practice there is at most one; the first wins.
	for _, am := range r.liveAnomaly() {
		ao := am.ScoreAnomaly(v)
		res.Anomaly = &AnomalyResult{
			Available:  ao.Available,
			ModelID:    ao.ModelID,
			Score:      ao.Score,
			ReconError: ao.ReconError,
			Threshold:  ao.Threshold,
			Exceeds:    ao.Exceeds,
		}
		break
	}

	sort.SliceStable(res.Models, func(i, j int) bool {
		return roleRank(res.Models[i].Role) < roleRank(res.Models[j].Role)
	})
	return res
}

func roleRank(r Role) int {
	switch r {
	case RolePrimary:
		return 0
	case RoleGlobal:
		return 1
	case RoleLocation:
		return 2
	case RoleSequence:
		return 3
	case RoleExperimental:
		return 4
	case RoleAnomaly:
		return 5
	default:
		return 6
	}
}
