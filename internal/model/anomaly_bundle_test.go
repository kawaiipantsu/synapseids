package model_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
)

// TestAnomalyBundlePassesGate builds a flow-anomaly-v1 autoencoder bundle with
// modeltest and runs it through the same Load + Validate gate a trained bundle
// faces (ADR 0037).
func TestAnomalyBundlePassesGate(t *testing.T) {
	dir := t.TempDir()
	if _, err := modeltest.Write(dir, modeltest.Bundle{Family: "flow-anomaly-v1"}); err != nil {
		t.Fatalf("write anomaly bundle: %v", err)
	}

	b, err := model.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("anomaly bundle must pass the gate: %v", err)
	}

	m := b.Meta()
	if m.Family != "flow-anomaly-v1" || m.OutputSchema != "reconstruction-v1" || m.OutputSize != 48 {
		t.Fatalf("unexpected meta: family=%q output=%q/%d", m.Family, m.OutputSchema, m.OutputSize)
	}
	if m.Architecture.InputSize != 48 || m.Architecture.OutputSize != 48 {
		t.Fatalf("architecture edges = %d/%d, want 48/48", m.Architecture.InputSize, m.Architecture.OutputSize)
	}
	if m.Anomaly == nil {
		t.Fatal("anomaly calibration block not parsed")
	}
	if m.Anomaly.Threshold <= 0 || m.Anomaly.ErrorPercentiles["p50"] <= 0 {
		t.Fatalf("anomaly calibration values wrong: %+v", m.Anomaly)
	}
}
