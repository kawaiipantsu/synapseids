package modeltest_test

import (
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modelrun"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
)

func TestWriteBundlePassesGateAndRuns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := modeltest.Write(dir, modeltest.Bundle{ModelID: "smoke-1"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := model.Load(dir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	cls, err := modelrun.Build("smoke-1", b)
	if err != nil {
		t.Fatalf("modelrun.Build: %v", err)
	}
	if cls.ID() != "smoke-1" || cls.Family() != "flow-classifier-v1" {
		t.Fatalf("classifier id/family = %q/%q", cls.ID(), cls.Family())
	}
}
