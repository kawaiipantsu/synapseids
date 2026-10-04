package inference

import (
	"fmt"
	"math"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// DetailOutput retains the independent, versioned threat/application distribution.
type DetailOutput struct {
	ModelID   string    `json:"model_id"`
	Schema    string    `json:"schema"`
	Available bool      `json:"available"`
	Class     string    `json:"class"`
	ClassID   int       `json:"class_id"`
	Score     float64   `json:"score"`
	Scores    []float64 `json:"scores"`
	Note      string    `json:"note,omitempty"`
}

// BehaviorModel scores the 160 ordered timing, protocol and host-context inputs.
// Applications occupy their own role and never drive a threat verdict.
type BehaviorModel struct {
	id, family string
	role       Role
	net        *nn.Model
	norm       func([]float64) []float32
	outputs    schema.OutputSchema
}

// NewBehaviorModel validates the graph dimensions before use.
func NewBehaviorModel(id, family string, net *nn.Model, norm func([]float64) []float32) (*BehaviorModel, error) {
	out := schema.AttackV2()
	if family == schema.FamilyApplicationV1 {
		out = schema.ApplicationV1()
	} else if family != schema.FamilyBehaviorV1 {
		return nil, fmt.Errorf("unsupported behavior family")
	}
	if net == nil || net.InputSize() != features.BehaviorSize || net.OutputSize() != out.OutputSize {
		return nil, fmt.Errorf("behavior model graph dimensions do not match contract")
	}
	return &BehaviorModel{id: id, family: family, net: net, norm: norm, outputs: out}, nil
}

// ID returns the stable model identity.
func (m *BehaviorModel) ID() string { return m.id }

// Family returns the frozen edge contract.
func (m *BehaviorModel) Family() string { return m.family }

// Role returns the operational scoring role.
func (m *BehaviorModel) Role() Role {
	if m.role != "" {
		return m.role
	}
	if m.family == schema.FamilyApplicationV1 {
		return RoleApplication
	}
	return RolePrimary
}
func (m *BehaviorModel) input(v features.BehaviorVector) []float32 {
	v.Sanitize()
	if m.norm != nil {
		return m.norm(v.Values[:])
	}
	out := make([]float32, features.BehaviorSize)
	for i, x := range v.Values {
		out[i] = float32(x)
	}
	return out
}

// Classify is the legacy entry point; absence of richer data stays explicit in masks.
func (m *BehaviorModel) Classify(v features.Vector) Scores {
	b := features.BehaviorVector{Schema: features.BehaviorSchemaID}
	copy(b.Values[:48], v.Values[:])
	sc, _ := m.ClassifyBehavior(b)
	return sc
}

// ClassifyBehavior preserves detailed outputs while projecting threat scores to
// the immutable seven-class alert contract for existing downstream consumers.
func (m *BehaviorModel) ClassifyBehavior(v features.BehaviorVector) (Scores, DetailOutput) {
	d := DetailOutput{ModelID: m.id, Schema: m.outputs.Schema, Class: "unknown", ClassID: -1, Scores: make([]float64, m.outputs.OutputSize)}
	out, err := m.net.Run(m.input(v))
	if err != nil || len(out) != len(d.Scores) {
		d.Note = "Inference unavailable"
		return normalFallback(), d
	}
	total := 0.0
	for i, x := range out {
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			d.Note = "Invalid model output"
			return normalFallback(), d
		}
		d.Scores[i] = f
		total += f
	}
	if total <= 0 {
		d.Note = "Empty model distribution"
		return normalFallback(), d
	}
	d.Available = true
	d.ClassID = 0
	for i := range d.Scores {
		d.Scores[i] /= total
		if d.Scores[i] > d.Scores[d.ClassID] {
			d.ClassID = i
		}
	}
	d.Class = m.outputs.Classes[d.ClassID].Name
	d.Score = d.Scores[d.ClassID]
	if m.family == schema.FamilyApplicationV1 {
		return normalFallback(), d
	}
	var sc Scores
	// normal,scan,sweep,ddos,syn,udp,icmp,dns-exhaustion,brute,botnet,
	// malware,web,rce,phishing,dga,download,malformed,suspicious,unknown.
	coarse := [19]int{0, 1, 1, 2, 2, 2, 2, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 6, 6}
	for i, p := range d.Scores {
		sc[coarse[i]] += p
	}
	return sc, d
}

// TraceBehavior returns actual ONNX activations for exactly these retained inputs.
func (m *BehaviorModel) TraceBehavior(v features.BehaviorVector) (nn.Trace, error) {
	return m.net.RunTrace(m.input(v))
}

// InputValues returns the exact fitted float32 values used by the network.
func (m *BehaviorModel) InputValues(v features.BehaviorVector) []float32 { return m.input(v) }

// AsShadow returns an immutable role-adjusted copy; the original stays unchanged.
func (m *BehaviorModel) AsShadow() *BehaviorModel {
	copy := *m
	copy.role = RoleExperimental
	return &copy
}
