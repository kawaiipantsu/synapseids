package api

// GET /api/v1/drift (issue #49): current flow-features-v1 distribution vs the
// active model's training distribution.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var driftBase = time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)

// seedFlows writes n flow records whose feature vector is a copy of tmpl (only
// the flow id and timestamps vary).
func seedFlows(store *storage.Mem, n int, tmpl [features.Size]float64) {
	for i := 0; i < n; i++ {
		at := driftBase.Add(time.Duration(i) * time.Second)
		store.PutFlow(storage.FlowRecord{
			ID: uint64(i + 1), Proto: "tcp", Sensor: "local",
			FirstSeen: at.Add(-time.Second), LastSeen: at,
			Features: features.Vector{Schema: features.SchemaID, Values: tmpl},
		})
	}
}

// writeStandardNormalizer replaces a bundle's normalizer.json with a "standard"
// spec carrying the given per-feature mean/std (same value for every feature).
func writeStandardNormalizer(t *testing.T, bundleDir string, mean, std float64) {
	t.Helper()
	perFeature := make([]map[string]any, features.Size)
	for i := range perFeature {
		perFeature[i] = map[string]any{"index": i, "name": "f", "mean": mean, "std": std}
	}
	blob, _ := json.MarshalIndent(map[string]any{
		"method": "standard", "feature_schema": "flow-features-v1", "per_feature": perFeature,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(bundleDir, model.FileNormalizer), blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

func driftServerWithActive(t *testing.T, store *storage.Mem, normMethod string, mut ...func(*config.Config)) http.Handler {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Models.Directory = dir
	for _, m := range mut {
		m(&cfg)
	}
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	reg := registry.Open(dir, quiet)
	aud := audit.New(dir, quiet)

	bdir := filepath.Join(dir, "b1")
	if _, err := modeltest.Write(bdir, modeltest.Bundle{ModelID: "flow-classifier-v1-test-0001"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := model.Load(bdir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register(loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetStatus("flow-classifier-v1-test-0001", registry.StatusActive); err != nil {
		t.Fatal(err)
	}
	if normMethod == "standard" {
		writeStandardNormalizer(t, bdir, 0.0, 1.0)
	}
	// else: leave modeltest's "identity" normalizer in place.

	return New(cfg, events.New(), store, rt, reg, aud, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
}

type driftResp struct {
	State    string `json:"state"`
	Baseline struct {
		Source  string `json:"source"`
		ModelID string `json:"model_id"`
		Method  string `json:"method"`
	} `json:"baseline"`
	BaselineNote string `json:"baseline_note"`
	Window       struct {
		Flows     int  `json:"flows"`
		Truncated bool `json:"truncated"`
	} `json:"window"`
	Overall struct {
		MaxZ          float64 `json:"max_z"`
		FeaturesWarn  int     `json:"features_warn"`
		FeaturesDrift int     `json:"features_drift"`
	} `json:"overall"`
	Features []struct {
		Index        int      `json:"index"`
		CurrentMean  float64  `json:"current_mean"`
		CurrentStd   float64  `json:"current_std"`
		BaselineMean *float64 `json:"baseline_mean"`
		Z            *float64 `json:"z"`
		State        string   `json:"state"`
	} `json:"features"`
	Suggestion *struct {
		RetrainSuggested bool   `json:"retrain_suggested"`
		Reason           string `json:"reason"`
		Advisory         string `json:"advisory"`
	} `json:"suggestion"`
}

func getDrift(t *testing.T, h http.Handler) (*httptest.ResponseRecorder, driftResp) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/drift", nil))
	var d driftResp
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
			t.Fatalf("bad JSON: %v\n%s", err, rr.Body.String())
		}
	}
	return rr, d
}

func TestDriftWithStandardBaseline(t *testing.T) {
	store := storage.NewMem(2000, 2000)
	var tmpl [features.Size]float64
	tmpl[0] = 10 // baseline mean 0, std 1 -> z = 10 -> drift
	tmpl[1] = 3  // z = 3 -> warn
	seedFlows(store, 50, tmpl)

	h := driftServerWithActive(t, store, "standard")
	rr, d := getDrift(t, h)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if d.State != "drift" {
		t.Fatalf("state = %q, want drift", d.State)
	}
	if d.Baseline.Source != "model_normalizer" || d.Baseline.ModelID != "flow-classifier-v1-test-0001" {
		t.Fatalf("baseline = %+v", d.Baseline)
	}
	if d.Window.Flows != 50 {
		t.Fatalf("window.flows = %d, want 50", d.Window.Flows)
	}
	if d.Overall.FeaturesDrift != 1 || d.Overall.FeaturesWarn != 1 {
		t.Fatalf("overall = %+v, want 1 drift / 1 warn", d.Overall)
	}
	// Worst offender (feature 0, z=10) sorts first and is flagged drift.
	if d.Features[0].Index != 0 || d.Features[0].State != "drift" {
		t.Fatalf("features[0] = %+v, want index 0 / drift", d.Features[0])
	}
	if d.Features[0].Z == nil || *d.Features[0].Z < 9.99 || *d.Features[0].Z > 10.01 {
		t.Fatalf("features[0].z = %v, want ~10", d.Features[0].Z)
	}
	if d.Features[0].BaselineMean == nil || *d.Features[0].BaselineMean != 0 {
		t.Fatalf("features[0].baseline_mean = %v, want 0", d.Features[0].BaselineMean)
	}
	// max z is 10 ≥ the default retrain_suggest_z of 6 → an advisory suggestion.
	if d.Suggestion == nil || !d.Suggestion.RetrainSuggested {
		t.Fatalf("suggestion = %+v, want retrain_suggested=true", d.Suggestion)
	}
	if !strings.Contains(d.Suggestion.Reason, "max z") {
		t.Fatalf("suggestion reason = %q", d.Suggestion.Reason)
	}
	if !strings.Contains(d.Suggestion.Advisory, "explicit operator decision") {
		t.Fatalf("suggestion advisory missing the operator-decision caveat: %q", d.Suggestion.Advisory)
	}
}

// Drift within the configured band → retrain_suggested:false, still with a reason.
func TestDriftSuggestionBelowBand(t *testing.T) {
	store := storage.NewMem(2000, 2000)
	var tmpl [features.Size]float64
	tmpl[1] = 3 // z = 3: warn band, below the drift band, and maxZ 3 < 6
	seedFlows(store, 40, tmpl)

	h := driftServerWithActive(t, store, "standard")
	rr, d := getDrift(t, h)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if d.Suggestion == nil || d.Suggestion.RetrainSuggested {
		t.Fatalf("suggestion = %+v, want retrain_suggested=false", d.Suggestion)
	}
	if !strings.Contains(d.Suggestion.Reason, "within tolerance") {
		t.Fatalf("reason = %q", d.Suggestion.Reason)
	}
}

// A lower configured feature-count trip fires the suggestion on feature count
// alone.
func TestDriftSuggestionByFeatureCount(t *testing.T) {
	store := storage.NewMem(2000, 2000)
	var tmpl [features.Size]float64
	tmpl[0], tmpl[1] = 5, 5 // two features at z = 5: drift band, maxZ 5 < 6
	seedFlows(store, 40, tmpl)

	h := driftServerWithActive(t, store, "standard", func(c *config.Config) {
		c.Drift.RetrainSuggestFeatures = 2
	})
	_, d := getDrift(t, h)
	if d.Suggestion == nil || !d.Suggestion.RetrainSuggested {
		t.Fatalf("suggestion = %+v, want retrain_suggested=true", d.Suggestion)
	}
	if !strings.Contains(d.Suggestion.Reason, "feature(s) past the drift band") {
		t.Fatalf("reason = %q", d.Suggestion.Reason)
	}
}

func TestDriftNoActiveModel(t *testing.T) {
	store := storage.NewMem(100, 100)
	var tmpl [features.Size]float64
	tmpl[5] = 42
	seedFlows(store, 10, tmpl)

	// A server with no registry at all: still returns the current distribution.
	cfg := config.Default()
	h := New(cfg, events.New(), store, inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	rr, d := getDrift(t, h)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if d.State != "no_baseline" || d.Baseline.Source != "none" {
		t.Fatalf("state=%q baseline=%+v, want no_baseline/none", d.State, d.Baseline)
	}
	if d.Suggestion != nil {
		t.Fatalf("no training baseline → no retraining suggestion, got %+v", d.Suggestion)
	}
	if d.Window.Flows != 10 {
		t.Fatalf("window.flows = %d, want 10", d.Window.Flows)
	}
	var f5 bool
	for _, f := range d.Features {
		if f.Index == 5 {
			f5 = true
			if f.CurrentMean != 42 || f.Z != nil || f.State != "no_baseline" {
				t.Fatalf("feature 5 = %+v", f)
			}
		}
	}
	if !f5 {
		t.Fatalf("feature 5 missing from response")
	}
}

func TestDriftActiveModelNotStandard(t *testing.T) {
	store := storage.NewMem(100, 100)
	seedFlows(store, 5, [features.Size]float64{})

	h := driftServerWithActive(t, store, "identity")
	rr, d := getDrift(t, h)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if d.State != "no_baseline" {
		t.Fatalf("state = %q, want no_baseline (identity normalizer)", d.State)
	}
	if d.BaselineNote == "" {
		t.Fatalf("expected a baseline_note explaining the identity normalizer cannot serve as a baseline")
	}
}

func TestDriftBadTimeBound(t *testing.T) {
	store := storage.NewMem(10, 10)
	h := New(config.Default(), events.New(), store,
		inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/drift?from=nope", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}
