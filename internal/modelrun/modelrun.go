// Package modelrun turns a validated model bundle into a live inference model:
// it loads the ONNX graph with internal/nn, bridges the bundle's fitted
// normalizer.json into inference's per-model Normalizer, and adapts the pair to
// the right interface for the bundle's family — inference.NewONNXModel for a
// flow-classifier-v1 supervised classifier, inference.NewONNXAnomalyModel for a
// flow-anomaly-v1 autoencoder (BuildLive dispatches on family; ADR 0037).
//
// It is the seam between "a bundle exists and passed the gate" (internal/model,
// internal/registry) and "a model is scoring flows" (inference.Runtime). It runs
// only from an explicit activation step, never on load or startup (PROJECT.md
// §28.10).
package modelrun

import (
	"fmt"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/nn"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Build compiles b's model.onnx, wires its normalizer, and returns a
// RolePrimary Classifier named id. The bundle must already have passed
// model.Validate (registry.Register is the gate); Build re-checks the
// input/output dimensions defensively via inference.NewONNXModel. Any failure —
// an unreadable or unsupported ONNX graph, a structurally broken normalizer, a
// dimension mismatch — is returned, not logged, so the caller can answer the
// activate request with a 409.
func Build(id string, b *model.Bundle) (inference.Classifier, error) {
	if b == nil {
		return nil, fmt.Errorf("modelrun: nil bundle")
	}

	net, err := nn.LoadFile(b.ONNXPath())
	if err != nil {
		return nil, fmt.Errorf("modelrun: load %s: %w", b.ONNXPath(), err)
	}

	norm, err := b.Normalizer()
	if err != nil {
		return nil, fmt.Errorf("modelrun: normalizer: %w", err)
	}

	bridged := func(v features.Vector) [features.Size]float64 {
		return norm.Normalize(v).Values
	}

	m, err := inference.NewONNXModel(id, inference.RolePrimary, net, bridged)
	if err != nil {
		return nil, fmt.Errorf("modelrun: %w", err)
	}
	return m, nil
}

// Live is the outcome of BuildLive: a compiled model plus the ensemble role it
// belongs in. Exactly one of Classifier / Anomaly is non-nil, matching Role.
type Live struct {
	Role       inference.Role
	Classifier inference.Classifier
	Anomaly    inference.AnomalyScorer
}

// BuildLive compiles b into the right kind of live model for its family: a
// supervised inference.Classifier for flow-classifier-v1, or an
// inference.AnomalyScorer for flow-anomaly-v1 (ADR 0037). The bundle must
// already have passed model.Validate.
func BuildLive(id string, b *model.Bundle) (Live, error) {
	if b == nil {
		return Live{}, fmt.Errorf("modelrun: nil bundle")
	}
	if b.Meta().Family == schema.FamilyAnomalyV1 {
		a, err := BuildAnomaly(id, b)
		if err != nil {
			return Live{}, err
		}
		return Live{Role: inference.RoleAnomaly, Anomaly: a}, nil
	}
	c, err := Build(id, b)
	if err != nil {
		return Live{}, err
	}
	return Live{Role: inference.RolePrimary, Classifier: c}, nil
}

// BuildAnomaly compiles b's model.onnx as a 48→48 autoencoder, wires its fitted
// normalizer (the reconstruction error is measured in normalized space), and
// reads the p50 / threshold from the bundle's metadata.json "anomaly" block —
// both default to zero when the bundle carries no calibration. The bundle must
// already have passed model.Validate; Build re-checks the dimensions defensively
// via inference.NewONNXAnomalyModel.
func BuildAnomaly(id string, b *model.Bundle) (inference.AnomalyScorer, error) {
	if b == nil {
		return nil, fmt.Errorf("modelrun: nil bundle")
	}

	net, err := nn.LoadFile(b.ONNXPath())
	if err != nil {
		return nil, fmt.Errorf("modelrun: load %s: %w", b.ONNXPath(), err)
	}

	norm, err := b.Normalizer()
	if err != nil {
		return nil, fmt.Errorf("modelrun: normalizer: %w", err)
	}
	bridged := func(v features.Vector) [features.Size]float64 {
		return norm.Normalize(v).Values
	}

	var p50, threshold float64
	if cal := b.Meta().Anomaly; cal != nil {
		p50 = cal.ErrorPercentiles["p50"]
		threshold = cal.Threshold
	}

	m, err := inference.NewONNXAnomalyModel(id, net, bridged, p50, threshold)
	if err != nil {
		return nil, fmt.Errorf("modelrun: %w", err)
	}
	return m, nil
}
