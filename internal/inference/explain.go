package inference

import (
	"sort"
	"strconv"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Explanation kinds. These are a contract with the UI: it must render "why" very
// differently depending on how much the model can actually justify.
const (
	// ExplainRules means the verdict came from transparent, readable rules over
	// named features, and Rules lists exactly the ones that fired. This is an
	// exact account of the decision, not an approximation.
	ExplainRules = "rules"

	// ExplainUnavailable means this model cannot attribute its output to
	// individual features in this build. Rules is empty and Note says why.
	ExplainUnavailable = "unavailable"
)

// RuleFeature is one feature value a rule's condition compared, carrying its
// flow-features-v1 name and unit so it renders without a client-side join.
type RuleFeature struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

// FiredRule is one rule that matched, and the feature values it matched on.
//
// Rule is a stable identifier (`<class>.<condition>`) safe to filter or link on;
// Detail is a human sentence. Deliberately there is no per-rule "contribution"
// or "importance" number: several rules can feed one class and the mapping from
// rule to probability runs through a softmax over class weights, so any
// per-rule percentage would be invented. Read ClassWeights for the actual
// pre-softmax arithmetic.
type FiredRule struct {
	Rule     string        `json:"rule"`
	Class    string        `json:"class"`
	ClassID  int           `json:"class_id"`
	Detail   string        `json:"detail"`
	Features []RuleFeature `json:"features"`
}

// ClassWeight is one class's pre-softmax weight — the real input to the
// distribution the model returned.
type ClassWeight struct {
	Class   string  `json:"class"`
	ClassID int     `json:"class_id"`
	Weight  float64 `json:"weight"`
}

// Explanation is a model's account of one verdict.
//
// What it claims depends entirely on Kind. For ExplainRules the content is
// exact: those rules, on those values, produced those weights. For
// ExplainUnavailable it claims nothing at all beyond Note. There is deliberately
// no baseline comparison here — behavioural baselines are Phase 7 work and this
// package will not invent one (PROJECT.md §13, §19.3).
type Explanation struct {
	ModelID string `json:"model_id"`
	Role    Role   `json:"role"`
	Kind    string `json:"kind"`

	// Rules are the rules that fired, in evaluation order. Empty means no rule
	// matched — for a rule-based model that is itself the explanation, and
	// NormalPrior says what decided the verdict instead.
	Rules []FiredRule `json:"rules"`

	// ClassWeights is every class with a non-zero pre-softmax weight, highest
	// first. Only set for ExplainRules.
	ClassWeights []ClassWeight `json:"class_weights,omitempty"`

	// NormalPrior is the standing weight given to "normal" before any rule runs.
	// Only meaningful for ExplainRules.
	NormalPrior float64 `json:"normal_prior,omitempty"`

	// Note is prose an operator should read before trusting the panel. It is
	// always populated.
	Note string `json:"note"`
}

// Explainer is implemented by a classifier that can account for its own verdict.
// A classifier that cannot is not required to pretend: callers should fall back
// to UnavailableExplanation rather than fabricating an attribution.
type Explainer interface {
	Explain(v features.Vector) Explanation
}

// Explain reports exactly which rules fired for this vector and on what values.
//
// It re-runs the same evaluation Classify runs, so the result is the true
// decision path rather than a reconstruction. Pure: it mutates nothing and holds
// no state between calls.
func (h *Heuristic) Explain(v features.Vector) Explanation {
	w, rules := h.evaluate(v, true)
	if rules == nil {
		// Marshal as [] rather than null: "no rule fired" is a meaningful answer
		// a client renders, and a null there is an easy crash in a consumer that
		// reasonably expects a list.
		rules = []FiredRule{}
	}

	ex := Explanation{
		ModelID:     h.id,
		Role:        h.role,
		Kind:        ExplainRules,
		Rules:       rules,
		NormalPrior: HeuristicNormalPrior,
	}

	for id, weight := range w {
		if weight == 0 {
			continue
		}
		ex.ClassWeights = append(ex.ClassWeights, ClassWeight{
			Class: schema.ClassName(id), ClassID: id, Weight: weight,
		})
	}
	// Highest weight first; ties by class index so the order is deterministic
	// (map iteration is not).
	sort.SliceStable(ex.ClassWeights, func(i, j int) bool {
		if ex.ClassWeights[i].Weight != ex.ClassWeights[j].Weight {
			return ex.ClassWeights[i].Weight > ex.ClassWeights[j].Weight
		}
		return ex.ClassWeights[i].ClassID < ex.ClassWeights[j].ClassID
	})

	if len(rules) == 0 {
		ex.Note = "No rule fired. This model classifies by explicit rules over named " +
			"flow-features-v1 values, so the verdict here is its standing `normal` prior " +
			"(weight " + trimFloat(HeuristicNormalPrior) + ") and not a positive finding: " +
			"nothing was detected, which is not the same as having been checked against a " +
			"behavioural baseline. Baselines are Phase 7 (PROJECT.md §13)."
	} else {
		ex.Note = "Every rule listed is an exact account of the decision: these conditions, " +
			"on these feature values, produced the class weights below, which were then " +
			"soft-maxed into the reported probabilities. No baseline comparison is involved " +
			"— behavioural baselines are Phase 7 (PROJECT.md §13)."
	}
	return ex
}

// UnavailableExplanation is the honest answer for a model that cannot attribute
// its output to individual features. Callers must use this rather than shipping a
// proxy that looks like an explanation.
func UnavailableExplanation(modelID string, role Role, why string) Explanation {
	return Explanation{
		ModelID: modelID,
		Role:    role,
		Kind:    ExplainUnavailable,
		Rules:   []FiredRule{}, // never null on the wire; see Explain
		Note:    why,
	}
}

// featureUnits maps a flow-features-v1 name to its unit. schema guarantees
// Features[i].Index == i but offers no name lookup, so build one once.
var featureUnits = func() map[string]string {
	fs := schema.FlowFeaturesV1().Features
	m := make(map[string]string, len(fs))
	for _, f := range fs {
		m[f.Name] = f.Unit
	}
	return m
}()

// featureUnit returns a feature's unit, or "" for an unknown name.
func featureUnit(name string) string { return featureUnits[name] }

// trimFloat renders a float for prose without trailing zeros.
func trimFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
