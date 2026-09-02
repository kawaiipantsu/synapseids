package model_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
)

// TestSequenceBundlePassesGate builds a flow-sequence-v1 windowed-FFN bundle
// with modeltest and runs it through the Load + Validate gate (ADR 0040).
func TestSequenceBundlePassesGate(t *testing.T) {
	dir := t.TempDir()
	if _, err := modeltest.Write(dir, modeltest.Bundle{Family: "flow-sequence-v1"}); err != nil {
		t.Fatalf("write sequence bundle: %v", err)
	}

	b, err := model.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("sequence bundle must pass the gate: %v", err)
	}

	m := b.Meta()
	if m.Family != "flow-sequence-v1" || m.OutputSchema != "traffic-classes-v1" || m.OutputSize != 7 {
		t.Fatalf("unexpected meta: family=%q output=%q/%d", m.Family, m.OutputSchema, m.OutputSize)
	}
	if m.SeqLen != 16 || m.Architecture.SeqLen != 16 {
		t.Fatalf("seq_len = %d / arch %d, want 16", m.SeqLen, m.Architecture.SeqLen)
	}
	if m.Architecture.InputSize != 48 || m.Architecture.OutputSize != 7 {
		t.Fatalf("architecture edges = %d/%d, want 48/7", m.Architecture.InputSize, m.Architecture.OutputSize)
	}
	// The declared parameter count reflects a 768-wide first Dense.
	if want := int64(16*768 + 16 + 7*16 + 7); m.ParameterCount != want {
		t.Fatalf("parameter_count = %d, want %d", m.ParameterCount, want)
	}
}
