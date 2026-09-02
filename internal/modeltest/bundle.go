// Package modeltest builds valid, gate-passing model bundles on disk for tests
// in the registry, api, modelrun and inference packages. The model.onnx it
// writes is a real feed-forward network that internal/nn can load and run — a
// 48 -> 8 -> 7 classifier by default, or a 48 -> 16 -> 8 -> 16 -> 48 autoencoder
// when Family is flow-anomaly-v1 — so a test can exercise the full "register ->
// activate -> score" path without a committed binary fixture.
//
// It takes no dependency on the testing package: callers pass a directory and
// handle the returned error.
package modeltest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kawaiipantsu/synapseids/internal/nn/onnxbuild"
)

// Bundle describes the bundle to write. Every field is optional.
type Bundle struct {
	ModelID     string // default depends on Family
	Name        string // default "modeltest classifier" / "modeltest autoencoder"
	Version     string // default "0.0.1"
	Family      string // "" or "flow-classifier-v1" (default); "flow-anomaly-v1" for an autoencoder
	DerivedFrom string // parent model_id, "" for a lineage root
	Seed        uint64 // weight-generator seed; changes the content hash
}

// Write creates dir (and parents) and writes the five bundle files, returning
// dir. The bundle passes model.Load followed by model.Validate.
func Write(dir string, b Bundle) (string, error) {
	if b.Family == "" {
		b.Family = "flow-classifier-v1"
	}
	anomaly := b.Family == "flow-anomaly-v1"
	if b.ModelID == "" {
		b.ModelID = b.Family + "-test-0001"
	}
	if b.Name == "" {
		if anomaly {
			b.Name = "modeltest autoencoder"
		} else {
			b.Name = "modeltest classifier"
		}
	}
	if b.Version == "" {
		b.Version = "0.0.1"
	}
	if b.Seed == 0 {
		b.Seed = 0x5EED
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("modeltest: mkdir %s: %w", dir, err)
	}

	r := &lcg{state: b.Seed}

	var (
		g          onnxbuild.Graph
		paramCount int
		outSchema  string
		outSize    int
		hidden     []map[string]any
		extraMeta  map[string]any
	)
	if anomaly {
		// 48 -> 16 -> 8 -> 16 -> 48 symmetric autoencoder, no softmax.
		g = onnxbuild.MLP(48, []onnxbuild.Layer{
			{W: r.matrix(16, 48), B: r.vec(16, 0.1), Activation: "Relu"},
			{W: r.matrix(8, 16), B: r.vec(8, 0.1), Activation: "Relu"},
			{W: r.matrix(16, 8), B: r.vec(16, 0.1), Activation: "Relu"},
			{W: r.matrix(48, 16), B: r.vec(48, 0.1)},
		}, false)
		paramCount = (16*48 + 16) + (8*16 + 8) + (16*8 + 16) + (48*16 + 48) // 1880
		outSchema, outSize = "reconstruction-v1", 48
		hidden = []map[string]any{
			{"width": 16, "activation": "relu", "dropout": 0.0, "batchnorm": false, "residual": false},
			{"width": 8, "activation": "relu", "dropout": 0.0, "batchnorm": false, "residual": false},
			{"width": 16, "activation": "relu", "dropout": 0.0, "batchnorm": false, "residual": false},
		}
		extraMeta = map[string]any{
			"anomaly": map[string]any{
				"space":             "normalized",
				"error_percentiles": map[string]any{"p50": 0.02, "p90": 0.08, "p95": 0.12, "p99": 0.25, "max": 0.6},
				"threshold":         0.25,
			},
		}
	} else {
		g = onnxbuild.MLP(48, []onnxbuild.Layer{
			{W: r.matrix(8, 48), B: r.vec(8, 0.1), Activation: "Relu"},
			{W: r.matrix(7, 8), B: r.vec(7, 0.1)},
		}, true)
		paramCount = 8*48 + 8 + 7*8 + 7 // 455
		outSchema, outSize = "traffic-classes-v1", 7
		hidden = []map[string]any{
			{"width": 8, "activation": "relu", "dropout": 0.0, "batchnorm": false, "residual": false},
		}
	}

	onnx := g.Encode()
	sum := sha256.Sum256(onnx)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	meta := map[string]any{
		"model_id":       b.ModelID,
		"name":           b.Name,
		"version":        b.Version,
		"family":         b.Family,
		"feature_schema": "flow-features-v1",
		"input_size":     48,
		"output_schema":  outSchema,
		"output_size":    outSize,
		"architecture": map[string]any{
			"input_size":  48,
			"output_size": outSize,
			"hidden":      hidden,
		},
		"training_dataset_ids": []string{"modeltest-ds-v1"},
		"created_at":           "2026-08-31T12:00:00Z",
		"trainer_version":      "modeltest 0.0.0",
		"parameter_count":      paramCount,
		"model_hash":           hash,
	}
	for k, v := range extraMeta {
		meta[k] = v
	}
	if b.DerivedFrom != "" {
		meta["derived_from"] = b.DerivedFrom
	}

	norm := map[string]any{
		"feature_schema": "flow-features-v1",
		"method":         "identity",
	}

	files := []struct {
		name string
		blob []byte
	}{
		{"model.onnx", onnx},
		{"metadata.json", mustJSON(meta)},
		{"normalizer.json", mustJSON(norm)},
		{"metrics.json", mustJSON(map[string]any{"accuracy": 0.91, "macro_f1": 0.88})},
		{"training-recipe.json", mustJSON(map[string]any{"optimizer": "adam", "seed": 42, "epochs": 5})},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.blob, 0o644); err != nil { //nolint:gosec // test fixture
			return "", fmt.Errorf("modeltest: write %s: %w", f.name, err)
		}
	}
	return dir, nil
}

func mustJSON(v any) []byte {
	blob, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return blob
}

// lcg is the 64-bit LCG used by internal/nn/testdata/gen, copied here so the
// fixture stays independent of math/rand.
type lcg struct{ state uint64 }

func (l *lcg) next() float64 {
	l.state = l.state*6364136223846793005 + 1442695040888963407
	return float64(l.state>>11) / float64(uint64(1)<<53)
}

// weightScale keeps the fixture's random weights small so the untrained network
// produces a sane (non-saturated) output.
const weightScale = 0.25

func (l *lcg) matrix(rows, cols int) [][]float32 {
	m := make([][]float32, rows)
	for i := range m {
		m[i] = l.vec(cols, weightScale)
	}
	return m
}

func (l *lcg) vec(n int, scale float64) []float32 {
	v := make([]float32, n)
	for i := range v {
		v[i] = float32((l.next()*2 - 1) * scale)
	}
	return v
}
