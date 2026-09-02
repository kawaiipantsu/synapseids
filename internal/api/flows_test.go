package api

import (
	"encoding/json"
	"math"
	"net/http"
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
	"github.com/kawaiipantsu/synapseids/internal/modelrun"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// scanVector is the feature vector of a lone unanswered SYN to port 22.
func scanVector(flowID uint64) features.Vector {
	v := features.Vector{FlowID: flowID, Schema: features.SchemaID}
	set := func(name string, val float64) {
		for i, f := range schema.FlowFeaturesV1().Features {
			if f.Name == name {
				v.Values[i] = val
				return
			}
		}
		panic("unknown feature " + name)
	}
	set("protocol_tcp", 1)
	set("tcp_syn_count", 1)
	set("packets_forward", 1)
	set("packets_backward", 0)
	set("tcp_ack_count", 0)
	set("bytes_forward", 60)
	set("packet_size_mean", 60)
	set("destination_port", 22)
	set("flow_duration", 0.001)
	return v
}

// insFlow stores one flow version plus the verdict computed from it, exactly as
// the pipeline does (Classification.TS is stamped from the record's LastSeen).
func insFlow(t *testing.T, st *storage.Mem, rt *inference.Runtime,
	id uint64, snapIdx int, reason string, last time.Time, pkts uint64) features.Vector {
	t.Helper()

	v := scanVector(id)
	rec := storage.FlowRecord{
		ID: id, Proto: "TCP",
		InitiatorIP: "10.0.0.66", InitiatorPort: 40001,
		ResponderIP: "10.10.10.21", ResponderPort: 22,
		FirstSeen: last.Add(-time.Minute), LastSeen: last,
		DurationSec: 0.001, FwdPackets: pkts,
		CloseReason: reason, SnapshotIndex: snapIdx,
		Features: v,
	}
	st.PutFlow(rec)

	res := rt.Score(v)
	st.PutClassification(storage.Classification{
		FlowID: id, TS: last, Sensor: "local", Proto: "TCP",
		InitiatorIP: "10.0.0.66", InitiatorPort: 40001,
		ResponderIP: "10.10.10.21", ResponderPort: 22,
		Result: res,
	})
	return v
}

// inspectorServer wires a heuristic-only daemon with one scan flow (id 1).
func inspectorServer(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Default()
	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	bus := events.New()
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)
	return New(cfg, bus, st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

func TestFlowExplainHeuristicReportsRawAndFiredRules(t *testing.T) {
	h := inspectorServer(t)

	rr := get(t, h, "/api/v1/flows/1/explain")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	got := decode[flowExplain](t, rr)

	if !got.VerdictAvailable || got.Verdict == nil {
		t.Fatal("verdict not reported")
	}
	if got.Verdict.Class != "scan" {
		t.Errorf("verdict class = %q, want scan", got.Verdict.Class)
	}
	if len(got.Models) != 1 {
		t.Fatalf("models = %d, want 1", len(got.Models))
	}
	m := got.Models[0]
	if m.ModelID != "heuristic-v1" || !m.Loaded {
		t.Errorf("model = %q loaded=%v, want heuristic-v1 loaded", m.ModelID, m.Loaded)
	}

	// (1) Normalized inputs: the heuristic reads raw values and must say so,
	// showing no transformation at all.
	if m.Input.Kind != inputRaw {
		t.Errorf("input kind = %q, want %q", m.Input.Kind, inputRaw)
	}
	if len(m.Input.Features) != 0 {
		t.Errorf("heuristic reported %d transformed features, want none", len(m.Input.Features))
	}
	if m.Input.NormalizerID != "" {
		t.Errorf("heuristic reported normalizer %q, want none", m.Input.NormalizerID)
	}
	if !strings.Contains(m.Input.Note, "raw") {
		t.Errorf("input note does not say raw: %q", m.Input.Note)
	}

	// (3) The explanation names the rules and the values they matched on.
	if m.Explanation.Kind != inference.ExplainRules {
		t.Fatalf("explanation kind = %q, want rules", m.Explanation.Kind)
	}
	var found bool
	for _, r := range m.Explanation.Rules {
		if r.Rule == "scan.unanswered_syn" {
			found = true
			for _, f := range r.Features {
				if f.Name == "tcp_syn_count" && f.Value != 1 {
					t.Errorf("tcp_syn_count = %v, want 1", f.Value)
				}
				if f.Name == "packets_backward" && f.Value != 0 {
					t.Errorf("packets_backward = %v, want 0", f.Value)
				}
			}
		}
	}
	if !found {
		t.Errorf("scan.unanswered_syn not in the explanation: %+v", m.Explanation.Rules)
	}

	// (4) With no anomaly model active the anomaly section is a labelled gap
	// with no number, and the behavioural baseline is still a Phase-7 stub.
	if got.Anomaly.Available {
		t.Error("anomaly reported as available with no anomaly model loaded")
	}
	if got.Anomaly.Score != 0 || got.Anomaly.ReconError != 0 || len(got.Anomaly.TopDeltas) != 0 {
		t.Errorf("unavailable anomaly section carries values: %+v", got.Anomaly)
	}
	if !strings.Contains(got.Anomaly.Note, "anomaly model") {
		t.Errorf("anomaly note does not explain the gap: %q", got.Anomaly.Note)
	}
	if got.Baseline.Available {
		t.Error("baseline reported as available")
	}
	if !strings.Contains(got.Baseline.Note, "Phase 7") {
		t.Errorf("baseline stub note does not name Phase 7: %q", got.Baseline.Note)
	}
}

// TestFlowExplainNoFabricatedBaselineOrAnomalyKeys asserts on the raw JSON, so a
// future field cannot smuggle a baseline range or an anomaly number back in.
func TestFlowExplainNoFabricatedBaselineOrAnomalyKeys(t *testing.T) {
	h := inspectorServer(t)
	rr := get(t, h, "/api/v1/flows/1/explain")

	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}

	for _, section := range []string{"anomaly", "baseline"} {
		obj, ok := raw[section].(map[string]any)
		if !ok {
			t.Fatalf("%q is not an object", section)
		}
		if obj["available"] != false {
			t.Errorf("%s.available = %v, want false", section, obj["available"])
		}
		// available + note and nothing else: no score, no range, no min/max.
		if len(obj) != 2 {
			t.Errorf("%s carries extra keys %v — a stub must not hold a value", section, obj)
		}
	}

	body := rr.Body.String()
	for _, banned := range []string{"anomaly_score", "baseline_value", "baseline_range", "training_baseline"} {
		if strings.Contains(body, banned) {
			t.Errorf("response contains %q — this build has no such data", banned)
		}
	}
}

// With a flow-anomaly-v1 autoencoder loaded, the explain anomaly section is
// populated from the stored verdict and carries the recomputed per-feature gaps.
func TestFlowExplainAnomalySectionPopulated(t *testing.T) {
	root := t.TempDir()
	const aeID = "flow-anomaly-v1-test-0001"
	bundleDir := filepath.Join(root, aeID)
	if _, err := modeltest.Write(bundleDir, modeltest.Bundle{Family: "flow-anomaly-v1", ModelID: aeID}); err != nil {
		t.Fatalf("write ae bundle: %v", err)
	}
	b, err := model.Load(bundleDir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	ae, err := modelrun.BuildAnomaly(aeID, b)
	if err != nil {
		t.Fatalf("modelrun.BuildAnomaly: %v", err)
	}

	cfg := config.Default()
	cfg.Models.Directory = root
	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	rt.SetAnomalyModels(ae)
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)

	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))
	if !got.Anomaly.Available {
		t.Fatalf("anomaly section not available: %+v", got.Anomaly)
	}
	if got.Anomaly.ModelID != aeID {
		t.Errorf("anomaly model_id = %q, want %q", got.Anomaly.ModelID, aeID)
	}
	if got.Anomaly.Score <= 0 || got.Anomaly.Score >= 1 {
		t.Errorf("anomaly score = %v, want 0..1", got.Anomaly.Score)
	}
	if len(got.Anomaly.TopDeltas) == 0 {
		t.Error("per-feature reconstruction gaps not recomputed for the loaded model")
	}
	if !strings.Contains(got.Anomaly.Note, "autoencoder") {
		t.Errorf("note = %q", got.Anomaly.Note)
	}

	// The supervised section is untouched: still just the heuristic.
	if len(got.Models) != 1 || got.Models[0].Role == inference.RoleAnomaly {
		t.Fatalf("anomaly model leaked into Models: %+v", got.Models)
	}
}

func TestFlowExplainUnknownFlow404(t *testing.T) {
	h := inspectorServer(t)
	if rr := get(t, h, "/api/v1/flows/424242/explain"); rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if rr := get(t, h, "/api/v1/flows/notanumber/explain"); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestFlowExplainEvictedFlow covers a flow whose record left the ring entirely.
func TestFlowExplainEvictedFlow(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(2, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	base := time.Unix(1700000000, 0)
	for id := uint64(1); id <= 4; id++ {
		insFlow(t, st, rt, id, 0, "fin_rst", base.Add(time.Duration(id)*time.Second), 1)
	}
	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	// Flow 1 was pushed out of the flow ring.
	if rr := get(t, h, "/api/v1/flows/1/explain"); rr.Code != http.StatusNotFound {
		t.Errorf("evicted flow: status = %d, want 404", rr.Code)
	}
	if rr := get(t, h, "/api/v1/flows/1/snapshots"); rr.Code != http.StatusNotFound {
		t.Errorf("evicted flow snapshots: status = %d, want 404", rr.Code)
	}
	// A retained one still explains.
	if rr := get(t, h, "/api/v1/flows/4/explain"); rr.Code != http.StatusOK {
		t.Errorf("retained flow: status = %d, want 200", rr.Code)
	}
}

// TestFlowExplainVerdictEvicted covers the flow record surviving while its
// verdict aged out — the response must say so rather than invent models.
func TestFlowExplainVerdictEvicted(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(100, 2)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	base := time.Unix(1700000000, 0)
	for id := uint64(1); id <= 4; id++ {
		insFlow(t, st, rt, id, 0, "fin_rst", base.Add(time.Duration(id)*time.Second), 1)
	}
	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	rr := get(t, h, "/api/v1/flows/1/explain")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	got := decode[flowExplain](t, rr)
	if got.VerdictAvailable {
		t.Error("verdict_available = true, but the classification ring evicted it")
	}
	if got.Verdict != nil {
		t.Error("a verdict was reported after eviction")
	}
	if len(got.Models) != 0 {
		t.Errorf("models = %d, want none without a stored verdict", len(got.Models))
	}
	if len(got.Notes) == 0 || !strings.Contains(strings.Join(got.Notes, " "), "aged out") {
		t.Errorf("notes do not explain the retention gap: %v", got.Notes)
	}
}

// TestFlowExplainModelNoLongerLoaded covers a verdict from a model that has
// since been swapped out of the runtime.
func TestFlowExplainModelNoLongerLoaded(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)

	// Swap the live model set: the stored verdict still names heuristic-v1.
	rt.SetModels(inference.NewHeuristic("some-other-model", inference.RolePrimary))

	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))

	if len(got.Models) != 1 {
		t.Fatalf("models = %d, want 1", len(got.Models))
	}
	m := got.Models[0]
	if m.Loaded {
		t.Error("loaded = true for a model no longer in the runtime")
	}
	if m.Input.Kind != inputUnknown {
		t.Errorf("input kind = %q, want %q", m.Input.Kind, inputUnknown)
	}
	if m.Explanation.Kind != inference.ExplainUnavailable {
		t.Errorf("explanation kind = %q, want %q", m.Explanation.Kind, inference.ExplainUnavailable)
	}
	if len(m.Explanation.Rules) != 0 {
		t.Error("rules reported for an unloaded model")
	}
	// The stored verdict itself is still reported — it really happened.
	if m.Class != "scan" {
		t.Errorf("class = %q, want the stored scan verdict", m.Class)
	}
}

// ---------------------------------------------------------------------------
// normalized inputs from a real bundle
// ---------------------------------------------------------------------------

// standardScalerBundle writes a gate-passing bundle whose normalizer.json is a
// known standard scaler: mean[i] = i, std[i] = i+1.
func standardScalerBundle(t *testing.T, dir, modelID string) {
	t.Helper()
	if _, err := modeltest.Write(dir, modeltest.Bundle{ModelID: modelID}); err != nil {
		t.Fatalf("modeltest.Write: %v", err)
	}

	per := make([]map[string]any, features.Size)
	for i := range per {
		per[i] = map[string]any{
			"index": i,
			"name":  schema.FeatureName(i),
			"mean":  float64(i),
			"std":   float64(i + 1),
		}
	}
	blob, err := json.MarshalIndent(map[string]any{
		"feature_schema": features.SchemaID,
		"method":         "standard",
		"per_feature":    per,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal normalizer: %v", err)
	}
	// model_hash covers model.onnx only, so replacing normalizer.json keeps the
	// bundle valid.
	if err := os.WriteFile(filepath.Join(dir, "normalizer.json"), blob, 0o644); err != nil {
		t.Fatalf("write normalizer.json: %v", err)
	}
}

func TestFlowExplainNormalizedInputsFromActiveBundle(t *testing.T) {
	const modelID = "flow-classifier-v1-test-0001"

	root := t.TempDir()
	bundleDir := filepath.Join(root, modelID)
	standardScalerBundle(t, bundleDir, modelID)

	cfg := config.Default()
	cfg.Models.Directory = root

	reg := registry.Open(root, func(string, ...any) {})
	b, err := model.Load(bundleDir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("bundle.Validate: %v", err)
	}
	if _, err := reg.Register(b); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := reg.SetStatus(modelID, registry.StatusActive); err != nil {
		t.Fatalf("activate: %v", err)
	}
	cls, err := modelrun.Build(modelID, b)
	if err != nil {
		t.Fatalf("modelrun.Build: %v", err)
	}

	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(cls)
	v := insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)

	h := New(cfg, events.New(), st, rt, reg, audit.New(root, func(string, ...any) {}),
		nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))
	if len(got.Models) != 1 {
		t.Fatalf("models = %d, want 1", len(got.Models))
	}
	m := got.Models[0]
	if !m.Loaded {
		t.Fatalf("model not loaded; note %q", m.Input.Note)
	}
	if m.Input.Kind != inputNormalized {
		t.Fatalf("input kind = %q, want %q (note %q)", m.Input.Kind, inputNormalized, m.Input.Note)
	}
	if m.Input.NormalizerID != "standard" {
		t.Errorf("normalizer_id = %q, want standard", m.Input.NormalizerID)
	}
	if len(m.Input.Features) != features.Size {
		t.Fatalf("features = %d, want %d", len(m.Input.Features), features.Size)
	}

	// The reported normalized values must be exactly (x - mean) / std.
	for _, f := range m.Input.Features {
		wantRaw := v.Values[f.Index]
		if f.Raw != wantRaw {
			t.Errorf("feature %d (%s) raw = %v, want %v", f.Index, f.Name, f.Raw, wantRaw)
		}
		wantNorm := (wantRaw - float64(f.Index)) / float64(f.Index+1)
		if math.Abs(f.Normalized-wantNorm) > 1e-12 {
			t.Errorf("feature %d (%s): normalized = %v, want (%v-%d)/%d = %v",
				f.Index, f.Name, f.Normalized, wantRaw, f.Index, f.Index+1, wantNorm)
		}
		if f.Name != schema.FeatureName(f.Index) {
			t.Errorf("feature %d name = %q, want %q", f.Index, f.Name, schema.FeatureName(f.Index))
		}
	}

	// Spot-check a feature we know the value of, so the loop cannot pass on an
	// all-zero vector.
	var dport normFeature
	for _, f := range m.Input.Features {
		if f.Name == "destination_port" {
			dport = f
		}
	}
	if dport.Raw != 22 {
		t.Fatalf("destination_port raw = %v, want 22", dport.Raw)
	}
	if want := (22.0 - float64(dport.Index)) / float64(dport.Index+1); math.Abs(dport.Normalized-want) > 1e-12 {
		t.Errorf("destination_port normalized = %v, want %v", dport.Normalized, want)
	}

	// A trained model gets no fabricated attribution.
	if m.Explanation.Kind != inference.ExplainUnavailable {
		t.Errorf("explanation kind = %q, want %q for a trained model",
			m.Explanation.Kind, inference.ExplainUnavailable)
	}
	if len(m.Explanation.Rules) != 0 {
		t.Error("rules reported for a trained model")
	}
	if !strings.Contains(m.Explanation.Note, "not implemented") {
		t.Errorf("trained-model note should say attribution is not implemented: %q",
			m.Explanation.Note)
	}
}

// TestFlowExplainNormalizerCachedByContentHash pins that repeated inspector
// requests do not re-read and re-hash model.onnx.
func TestFlowExplainNormalizerCachedByContentHash(t *testing.T) {
	const modelID = "flow-classifier-v1-test-0001"
	root := t.TempDir()
	bundleDir := filepath.Join(root, modelID)
	standardScalerBundle(t, bundleDir, modelID)

	cfg := config.Default()
	cfg.Models.Directory = root
	reg := registry.Open(root, func(string, ...any) {})
	b, err := model.Load(bundleDir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	if _, err := reg.Register(b); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := reg.SetStatus(modelID, registry.StatusActive); err != nil {
		t.Fatalf("activate: %v", err)
	}
	cls, err := modelrun.Build(modelID, b)
	if err != nil {
		t.Fatalf("modelrun.Build: %v", err)
	}

	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(cls)
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)
	srv := New(cfg, events.New(), st, rt, reg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := srv.Handler()

	if rr := get(t, h, "/api/v1/flows/1/explain"); rr.Code != http.StatusOK {
		t.Fatalf("first request: %d", rr.Code)
	}
	if n := len(srv.normCache); n != 1 {
		t.Fatalf("normCache holds %d entries after one request, want 1", n)
	}

	// Delete the bundle from disk: a cached normalizer must still serve.
	if err := os.RemoveAll(bundleDir); err != nil {
		t.Fatalf("remove bundle: %v", err)
	}
	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))
	if got.Models[0].Input.Kind != inputNormalized {
		t.Errorf("second request kind = %q, want %q — the normalizer was not cached",
			got.Models[0].Input.Kind, inputNormalized)
	}
	if n := len(srv.normCache); n != 1 {
		t.Errorf("normCache holds %d entries, want 1", n)
	}
}

// TestFlowExplainNoActiveModelSaysSo covers a trained model scoring while the
// registry has nothing active — the response must decline rather than guess.
func TestFlowExplainNoActiveModelSaysSo(t *testing.T) {
	const modelID = "flow-classifier-v1-test-0001"
	root := t.TempDir()
	bundleDir := filepath.Join(root, modelID)
	standardScalerBundle(t, bundleDir, modelID)

	cfg := config.Default()
	cfg.Models.Directory = root
	reg := registry.Open(root, func(string, ...any) {})
	b, err := model.Load(bundleDir)
	if err != nil {
		t.Fatalf("model.Load: %v", err)
	}
	if _, err := reg.Register(b); err != nil { // registered, never activated
		t.Fatalf("register: %v", err)
	}
	cls, err := modelrun.Build(modelID, b)
	if err != nil {
		t.Fatalf("modelrun.Build: %v", err)
	}

	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(cls)
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)
	h := New(cfg, events.New(), st, rt, reg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))
	m := got.Models[0]
	if m.Input.Kind != inputUnknown {
		t.Errorf("input kind = %q, want %q", m.Input.Kind, inputUnknown)
	}
	if len(m.Input.Features) != 0 {
		t.Error("normalized features reported with no active registry entry")
	}
	if !strings.Contains(m.Input.Note, "no model is active") {
		t.Errorf("note should state no model is active: %q", m.Input.Note)
	}
}

// TestFlowExplainNilRegistry is the heuristic-only daemon's sibling case for a
// non-heuristic model with no registry at all.
func TestFlowExplainNilRegistryForTrainedModel(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(100, 100)
	// constExplainless stands in for any classifier that is neither the
	// heuristic nor registry-resolvable.
	rt := inference.NewRuntime(stubClassifier{id: "mystery", role: inference.RolePrimary})
	insFlow(t, st, rt, 1, 0, "fin_rst", time.Unix(1700000000, 0), 1)
	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	got := decode[flowExplain](t, get(t, h, "/api/v1/flows/1/explain"))
	m := got.Models[0]
	if m.Input.Kind != inputUnknown {
		t.Errorf("input kind = %q, want %q", m.Input.Kind, inputUnknown)
	}
	if !strings.Contains(m.Input.Note, "registry") {
		t.Errorf("note should mention the registry: %q", m.Input.Note)
	}
	if m.Explanation.Kind != inference.ExplainUnavailable {
		t.Errorf("explanation kind = %q, want unavailable", m.Explanation.Kind)
	}
}

type stubClassifier struct {
	id   string
	role inference.Role
}

func (s stubClassifier) ID() string     { return s.id }
func (s stubClassifier) Family() string { return "flow-classifier-v1" }
func (s stubClassifier) Role() inference.Role {
	return s.role
}
func (s stubClassifier) Classify(features.Vector) inference.Scores {
	var sc inference.Scores
	sc[1] = 1
	return sc
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

func TestFlowSnapshotsSingleTerminalRecord(t *testing.T) {
	h := inspectorServer(t)

	rr := get(t, h, "/api/v1/flows/1/snapshots")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	got := decode[flowSnapshots](t, rr)

	if got.Retained != 1 || len(got.Versions) != 1 {
		t.Fatalf("retained = %d / %d versions, want 1", got.Retained, len(got.Versions))
	}
	if got.Snapshotting {
		t.Error("snapshotting = true for a flow that never snapshotted")
	}
	if got.Truncated {
		t.Error("truncated = true for a complete history")
	}
	if got.Cap != storage.FlowHistoryCap {
		t.Errorf("cap = %d, want %d", got.Cap, storage.FlowHistoryCap)
	}
	v := got.Versions[0]
	if !v.Terminal || v.CloseReason != "fin_rst" {
		t.Errorf("version = terminal %v / %q, want true / fin_rst", v.Terminal, v.CloseReason)
	}
	if v.Verdict == nil || v.Verdict.Class != "scan" {
		t.Errorf("verdict = %+v, want scan", v.Verdict)
	}
}

func TestFlowSnapshotsHistoryInOrderWithVerdicts(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	base := time.Unix(1700000000, 0)

	// A long flow: three snapshots then the terminal record. The terminal record
	// inherits the last snapshot's index, as the flow engine really emits it.
	insFlow(t, st, rt, 9, 1, "snapshot", base.Add(1*time.Minute), 10)
	insFlow(t, st, rt, 9, 2, "snapshot", base.Add(2*time.Minute), 20)
	insFlow(t, st, rt, 9, 3, "snapshot", base.Add(3*time.Minute), 30)
	insFlow(t, st, rt, 9, 3, "fin_rst", base.Add(4*time.Minute), 44)

	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	got := decode[flowSnapshots](t, get(t, h, "/api/v1/flows/9/snapshots"))

	if got.Retained != 4 || len(got.Versions) != 4 {
		t.Fatalf("retained = %d / %d versions, want 4", got.Retained, len(got.Versions))
	}
	if !got.Snapshotting {
		t.Error("snapshotting = false for a snapshotting flow")
	}
	if got.Truncated {
		t.Error("truncated = true for a complete history")
	}

	wantPkts := []uint64{10, 20, 30, 44}
	for i, want := range wantPkts {
		if got.Versions[i].FwdPackets != want {
			t.Errorf("version %d fwd_packets = %d, want %d (out of order?)",
				i, got.Versions[i].FwdPackets, want)
		}
		// Every version must carry its own verdict — the evolution is the point.
		if got.Versions[i].Verdict == nil {
			t.Errorf("version %d has no verdict", i)
		}
	}
	for i := range 3 {
		if got.Versions[i].Terminal {
			t.Errorf("version %d marked terminal, want snapshot", i)
		}
	}
	if !got.Versions[3].Terminal {
		t.Error("last version not marked terminal")
	}
	// Timestamps strictly increase, so the timeline renders in order.
	for i := 1; i < len(got.Versions); i++ {
		if !got.Versions[i].LastSeen.After(got.Versions[i-1].LastSeen) {
			t.Errorf("version %d last_seen not after %d", i, i-1)
		}
	}
}

func TestFlowSnapshotsTruncationIsReported(t *testing.T) {
	cfg := config.Default()
	st := storage.NewMem(storage.FlowHistoryCap*4, storage.FlowHistoryCap*4)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	base := time.Unix(1700000000, 0)

	total := storage.FlowHistoryCap + 5
	for i := 1; i <= total; i++ {
		insFlow(t, st, rt, 9, i, "snapshot", base.Add(time.Duration(i)*time.Minute), uint64(i))
	}

	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	got := decode[flowSnapshots](t, get(t, h, "/api/v1/flows/9/snapshots"))

	if got.Retained != storage.FlowHistoryCap {
		t.Fatalf("retained = %d, want the cap %d", got.Retained, storage.FlowHistoryCap)
	}
	if !got.Truncated {
		t.Error("truncated = false after the per-flow cap dropped versions")
	}
	if got.Versions[0].SnapshotIndex != 6 {
		t.Errorf("oldest retained snapshot_index = %d, want 6", got.Versions[0].SnapshotIndex)
	}
	joined := strings.Join(got.Notes, " ")
	if !strings.Contains(joined, "no longer retained") {
		t.Errorf("notes do not report the truncation: %v", got.Notes)
	}
}

func TestFlowSnapshotsMissingVerdictIsReportedNotInvented(t *testing.T) {
	cfg := config.Default()
	// A classification ring too small to keep every snapshot's verdict.
	st := storage.NewMem(100, 2)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	base := time.Unix(1700000000, 0)

	for i := 1; i <= 4; i++ {
		insFlow(t, st, rt, 9, i, "snapshot", base.Add(time.Duration(i)*time.Minute), uint64(i*10))
	}

	h := New(cfg, events.New(), st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
	got := decode[flowSnapshots](t, get(t, h, "/api/v1/flows/9/snapshots"))

	if len(got.Versions) != 4 {
		t.Fatalf("versions = %d, want 4", len(got.Versions))
	}
	// The two oldest verdicts were evicted; those versions must report nil, not
	// a copied-forward verdict.
	nilCount := 0
	for _, v := range got.Versions {
		if v.Verdict == nil {
			nilCount++
		}
	}
	if nilCount != 2 {
		t.Errorf("%d versions without a verdict, want 2", nilCount)
	}
	if !strings.Contains(strings.Join(got.Notes, " "), "retention gap") {
		t.Errorf("notes do not explain the missing verdicts: %v", got.Notes)
	}
}

func TestFlowSnapshotsBadIDAndUnknown(t *testing.T) {
	h := inspectorServer(t)
	if rr := get(t, h, "/api/v1/flows/nope/snapshots"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad id: status = %d, want 400", rr.Code)
	}
	if rr := get(t, h, "/api/v1/flows/98765/snapshots"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown: status = %d, want 404", rr.Code)
	}
}

// TestFlowDetailShapeUnchanged guards the existing route: the two new siblings
// must not have altered GET /api/v1/flows/{id}.
func TestFlowDetailShapeUnchanged(t *testing.T) {
	h := inspectorServer(t)
	rr := get(t, h, "/api/v1/flows/1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, key := range []string{
		"id", "proto", "initiator_ip", "responder_ip", "first_seen", "last_seen",
		"duration_sec", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
		"close_reason", "snapshot_index", "features",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("flow detail lost key %q", key)
		}
	}
	// No new keys leaked into this route.
	if len(raw) != 16 {
		t.Errorf("flow detail has %d keys, want 16 — the route's shape changed: %v",
			len(raw), raw)
	}
}
