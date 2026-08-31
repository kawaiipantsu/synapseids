// Package modelrun turns a validated model bundle into a live
// inference.Classifier: it loads the ONNX graph with internal/nn, bridges the
// bundle's fitted normalizer.json into inference's per-model Normalizer, and
// adapts the pair to the Classifier interface via inference.NewONNXModel.
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
