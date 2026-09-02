package modelrun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modelrun"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
)

func load(t *testing.T, dir string, b modeltest.Bundle) *model.Bundle {
	t.Helper()
	if _, err := modeltest.Write(dir, b); err != nil {
		t.Fatalf("modeltest.Write: %v", err)
	}
	loaded, err := model.Load(dir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	return loaded
}

func TestBuildRunnableClassifier(t *testing.T) {
	b := load(t, filepath.Join(t.TempDir(), "bundle"), modeltest.Bundle{ModelID: "m-1"})

	cls, err := modelrun.Build("m-1", b)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cls.ID() != "m-1" || cls.Family() != "flow-classifier-v1" || string(cls.Role()) != "primary" {
		t.Fatalf("classifier id/family/role = %q/%q/%q", cls.ID(), cls.Family(), cls.Role())
	}

	// It must actually score a vector into a 7-class distribution that sums to ~1.
	sc := cls.Classify(features.Vector{})
	var sum float64
	for _, p := range sc {
		if p < 0 {
			t.Fatalf("negative probability in %v", sc)
		}
		sum += p
	}
	if sum < 0.99 || sum > 1.01 {
		t.Fatalf("scores sum = %v, want ~1 (%v)", sum, sc)
	}
}

func TestBuildRejectsBrokenONNX(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	b := load(t, dir, modeltest.Bundle{ModelID: "m-2"})
	if err := os.WriteFile(filepath.Join(dir, model.FileModel), []byte("not onnx"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := modelrun.Build("m-2", b); err == nil {
		t.Fatalf("Build must fail when model.onnx cannot be compiled")
	}
}

func TestBuildNilBundle(t *testing.T) {
	if _, err := modelrun.Build("x", nil); err == nil {
		t.Fatalf("Build(nil) must error")
	}
	if _, err := modelrun.BuildLive("x", nil); err == nil {
		t.Fatalf("BuildLive(nil) must error")
	}
	if _, err := modelrun.BuildAnomaly("x", nil); err == nil {
		t.Fatalf("BuildAnomaly(nil) must error")
	}
}

func TestBuildLiveDispatchesOnFamily(t *testing.T) {
	clf := load(t, filepath.Join(t.TempDir(), "clf"), modeltest.Bundle{ModelID: "clf-1"})
	live, err := modelrun.BuildLive("clf-1", clf)
	if err != nil {
		t.Fatalf("BuildLive classifier: %v", err)
	}
	if string(live.Role) != "primary" || live.Classifier == nil || live.Anomaly != nil {
		t.Fatalf("classifier Live = %+v", live)
	}

	ae := load(t, filepath.Join(t.TempDir(), "ae"), modeltest.Bundle{Family: "flow-anomaly-v1", ModelID: "ae-1"})
	live, err = modelrun.BuildLive("ae-1", ae)
	if err != nil {
		t.Fatalf("BuildLive autoencoder: %v", err)
	}
	if string(live.Role) != "anomaly" || live.Anomaly == nil || live.Classifier != nil {
		t.Fatalf("autoencoder Live = %+v", live)
	}
	if live.Anomaly.ID() != "ae-1" || live.Anomaly.Family() != "flow-anomaly-v1" {
		t.Fatalf("anomaly id/family = %q/%q", live.Anomaly.ID(), live.Anomaly.Family())
	}

	// It scores a vector into a bounded reconstruction result.
	out := live.Anomaly.ScoreAnomaly(features.Vector{})
	if !out.Available || out.Score < 0 || out.Score >= 1 {
		t.Fatalf("ScoreAnomaly = %+v", out)
	}
}
