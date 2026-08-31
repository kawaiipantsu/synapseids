// Package modeltest builds valid, gate-passing model bundles on disk for tests
// in the registry, api, modelrun and inference packages. The model.onnx it
// writes is a real 48 -> 8 -> 7 feed-forward classifier that internal/nn can
// load and run, so a test can exercise the full "register -> activate -> score"
// path without a committed binary fixture.
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
	ModelID     string // default "flow-classifier-v1-test-0001"
	Name        string // default "modeltest classifier"
	Version     string // default "0.0.1"
	DerivedFrom string // parent model_id, "" for a lineage root
	Seed        uint64 // weight-generator seed; changes the content hash
}

// Write creates dir (and parents) and writes the five bundle files, returning
// dir. The bundle passes model.Load followed by model.Validate.
func Write(dir string, b Bundle) (string, error) {
	if b.ModelID == "" {
		b.ModelID = "flow-classifier-v1-test-0001"
	}
	if b.Name == "" {
		b.Name = "modeltest classifier"
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
	g := onnxbuild.MLP(48, []onnxbuild.Layer{
		{W: r.matrix(8, 48, 0.25), B: r.vec(8, 0.1), Activation: "Relu"},
		{W: r.matrix(7, 8, 0.25), B: r.vec(7, 0.1)},
	}, true)
	onnx := g.Encode()
	sum := sha256.Sum256(onnx)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	const paramCount = 8*48 + 8 + 7*8 + 7 // 455

	meta := map[string]any{
		"model_id":       b.ModelID,
		"name":           b.Name,
		"version":        b.Version,
		"family":         "flow-classifier-v1",
		"feature_schema": "flow-features-v1",
		"input_size":     48,
		"output_schema":  "traffic-classes-v1",
		"output_size":    7,
		"architecture": map[string]any{
			"input_size":  48,
			"output_size": 7,
			"hidden": []map[string]any{
				{"width": 8, "activation": "relu", "dropout": 0.0, "batchnorm": false, "residual": false},
			},
		},
		"training_dataset_ids": []string{"modeltest-ds-v1"},
		"created_at":           "2026-08-31T12:00:00Z",
		"trainer_version":      "modeltest 0.0.0",
		"parameter_count":      paramCount,
		"model_hash":           hash,
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

func (l *lcg) matrix(rows, cols int, scale float64) [][]float32 {
	m := make([][]float32, rows)
	for i := range m {
		m[i] = l.vec(cols, scale)
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
