// Package inference scores flow feature vectors with one or more models and
// combines their verdicts. Phase 1 ships a single rule-based model; Phase 2 adds
// ONNX models loaded from validated bundles. The runtime always records each
// model's individual output, not just the combined decision (PROJECT.md §12).
package inference

import (
	"sort"

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

// Result is the ensemble verdict for one flow.
type Result struct {
	FlowID       uint64        `json:"flow_id"`
	Class        string        `json:"class"`
	ClassID      int           `json:"class_id"`
	Score        float64       `json:"score"`
	Disagreement bool          `json:"disagreement"`
	Models       []ModelOutput `json:"models"`
}

// Runtime holds the loaded models and scores flows through all of them.
type Runtime struct {
	models []Classifier
}

// NewRuntime returns a Runtime over the given models. The first model with
// RolePrimary is authoritative; if none is primary the first model wins.
func NewRuntime(models ...Classifier) *Runtime {
	return &Runtime{models: models}
}

// Models returns the loaded classifiers.
func (r *Runtime) Models() []Classifier { return r.models }

// Score runs every model over v and combines the outputs.
func (r *Runtime) Score(v features.Vector) Result {
	res := Result{FlowID: v.FlowID}
	var primary *ModelOutput
	seen := map[int]int{}

	for _, m := range r.models {
		sc := m.Classify(v)
		id, p := sc.Top()
		mo := ModelOutput{
			ModelID: m.ID(), Role: m.Role(),
			Class: schema.ClassName(id), ClassID: id, Score: p, Scores: sc,
		}
		res.Models = append(res.Models, mo)
		if m.Role() != RoleAnomaly {
			seen[id]++
		}
		if primary == nil || m.Role() == RolePrimary {
			cp := mo
			primary = &cp
		}
	}

	if primary != nil {
		res.Class, res.ClassID, res.Score = primary.Class, primary.ClassID, primary.Score
	}
	// Disagreement: more than one distinct non-anomaly class predicted.
	distinct := 0
	for range seen {
		distinct++
	}
	res.Disagreement = distinct > 1

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
	case RoleExperimental:
		return 3
	case RoleAnomaly:
		return 4
	default:
		return 5
	}
}
