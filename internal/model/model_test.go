package model_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/model"
)

const goodBundle = "testdata/good-bundle"

// gate loads dir as a bundle and runs the activation gate, returning the first
// error from either step (Load catches missing files / invalid JSON, Validate
// catches contract violations).
func gate(dir string) error {
	b, err := model.Load(dir)
	if err != nil {
		return err
	}
	return b.Validate()
}

func TestLoadGoodBundle(t *testing.T) {
	b, err := model.Load(goodBundle)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("the good bundle must pass the gate: %v", err)
	}

	m := b.Meta()
	if m.ModelID != "flow-classifier-v1-testfixture-0001" {
		t.Errorf("model_id = %q", m.ModelID)
	}
	if m.Family != "flow-classifier-v1" {
		t.Errorf("family = %q", m.Family)
	}
	if m.InputSize != 48 || m.OutputSize != 7 {
		t.Errorf("sizes = %d/%d", m.InputSize, m.OutputSize)
	}
	if len(m.Architecture.Hidden) != 2 || m.Architecture.Hidden[0].Width != 64 || !m.Architecture.Hidden[0].BatchNorm {
		t.Errorf("architecture.hidden parsed wrong: %+v", m.Architecture.Hidden)
	}
	if m.ParameterCount != 5383 {
		t.Errorf("parameter_count = %d", m.ParameterCount)
	}
	if len(m.TrainingDatasetIDs) != 2 {
		t.Errorf("training_dataset_ids = %v", m.TrainingDatasetIDs)
	}
	if !strings.HasPrefix(b.Hash(), "sha256:") || len(b.Hash()) != 71 {
		t.Errorf("hash = %q", b.Hash())
	}
	if b.Hash() != m.ModelHash {
		t.Errorf("recomputed hash %q != metadata model_hash %q", b.Hash(), m.ModelHash)
	}
	if filepath.Base(b.ONNXPath()) != model.FileModel {
		t.Errorf("ONNXPath = %q", b.ONNXPath())
	}
	if !json.Valid(b.Metrics()) || len(b.Metrics()) == 0 {
		t.Errorf("metrics.json not carried through as valid JSON")
	}
	if !json.Valid(b.Recipe()) || len(b.Recipe()) == 0 {
		t.Errorf("training-recipe.json not carried through as valid JSON")
	}

	n, err := b.Normalizer()
	if err != nil {
		t.Fatalf("Normalizer: %v", err)
	}
	if n.ID() != "standard" {
		t.Errorf("normalizer ID = %q, want standard", n.ID())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(t *testing.T, dir string)
		want string // substring of the expected error; "" means the gate must pass
	}{
		{"good", func(*testing.T, string) {}, ""},
		{"bad-hash", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, model.FileModel), []byte("tampered model bytes"))
		}, "does not match model.onnx"},
		{"hash-missing-prefix", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) {
				m["model_hash"] = strings.TrimPrefix(m["model_hash"].(string), "sha256:")
			})
		}, `missing the "sha256:" prefix`},
		{"wrong-input-size", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["input_size"] = 47 })
		}, "input_size"},
		{"wrong-feature-schema", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["feature_schema"] = "flow-features-v2" })
		}, "feature schema"},
		{"wrong-output-size", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["output_size"] = 9 })
		}, "output_size"},
		{"arch-input-mismatch", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) {
				m["architecture"].(map[string]any)["input_size"] = 40
			})
		}, "architecture.input_size"},
		{"arch-missing", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { delete(m, "architecture") })
		}, "architecture block is missing"},
		{"empty-family", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["family"] = "" })
		}, "family is empty"},
		{"zero-params", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["parameter_count"] = 0 })
		}, "parameter_count"},
		{"bad-created-at", func(t *testing.T, dir string) {
			patchMeta(t, dir, func(m map[string]any) { m["created_at"] = "last thursday" })
		}, "created_at"},
		{"metadata-invalid-json", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, model.FileMetadata), []byte("{not json"))
		}, "invalid JSON"},
		{"missing-normalizer", func(t *testing.T, dir string) {
			rm(t, filepath.Join(dir, model.FileNormalizer))
		}, model.FileNormalizer},
		{"normalizer-bad-schema", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) { m["feature_schema"] = "flow-features-v2" })
		}, "normalizer.json: feature_schema"},
		{"normalizer-short", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) {
				m["per_feature"] = m["per_feature"].([]any)[:40]
			})
		}, "per_feature has 40 entries"},
		{"normalizer-out-of-order", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) {
				pf := m["per_feature"].([]any)
				pf[0], pf[1] = pf[1], pf[0]
			})
		}, "ascending"},
		{"normalizer-std-zero", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) {
				m["per_feature"].([]any)[5].(map[string]any)["std"] = 0
			})
		}, "std 0 must be > 0"},
		{"minmax-ok", func(t *testing.T, dir string) {
			patchNorm(t, dir, toMinMax)
		}, ""},
		{"minmax-inverted", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) {
				toMinMax(m)
				m["per_feature"].([]any)[3].(map[string]any)["max"] = -1.0
			})
		}, "must be < max"},
		{"identity-ok", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) {
				m["method"] = "identity"
				delete(m, "per_feature")
			})
		}, ""},
		{"normalizer-bad-method", func(t *testing.T, dir string) {
			patchNorm(t, dir, func(m map[string]any) { m["method"] = "robust" })
		}, "method \"robust\""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyGoodBundle(t)
			tc.mut(t, dir)
			err := gate(dir)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("gate rejected a bundle it should accept: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("gate accepted a bundle it should reject (wanted %q)", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	cpTree(t, goodBundle, filepath.Join(root, "primary-model"))
	cpTree(t, goodBundle, filepath.Join(root, "broken-model"))
	rm(t, filepath.Join(root, "broken-model", model.FileNormalizer))
	write(t, filepath.Join(root, "not-a-bundle.txt"), []byte("ignore me"))

	var lines []string
	got := model.Scan(root, "primary-model", func(f string, a ...any) {
		lines = append(lines, fmt.Sprintf(f, a...))
	})

	if len(got) != 1 || filepath.Base(got[0].Dir()) != "primary-model" {
		t.Fatalf("Scan returned %d bundles, want just primary-model", len(got))
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		`loaded model "primary-model" (family flow-classifier-v1, 5383 params) — INACTIVE`,
		`rejected model bundle "broken-model"`,
		`model "primary-model" matches models.primary; activation is a separate explicit step (POST /api/v1/models/{id}/activate)`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("scan log missing %q\ngot:\n%s", want, joined)
		}
	}
}

func TestScanMissingDirIsSilent(t *testing.T) {
	var lines []string
	got := model.Scan(filepath.Join(t.TempDir(), "does-not-exist"), "", func(f string, a ...any) {
		lines = append(lines, fmt.Sprintf(f, a...))
	})
	if got != nil || len(lines) != 0 {
		t.Fatalf("missing dir must be silent: bundles=%v lines=%v", got, lines)
	}
	// nil logf must not panic.
	model.Scan(filepath.Join(t.TempDir(), "also-missing"), "", nil)
}

// --- helpers ---

func toMinMax(m map[string]any) {
	m["method"] = "minmax"
	for i, e := range m["per_feature"].([]any) {
		fe := e.(map[string]any)
		delete(fe, "mean")
		delete(fe, "std")
		fe["min"] = 0.0
		fe["max"] = float64(i + 1)
	}
}

func copyGoodBundle(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "bundle")
	cpTree(t, goodBundle, dst)
	return dst
}

func cpTree(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			cpTree(t, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()))
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dst, e.Name()), b)
	}
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func rm(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func patchMeta(t *testing.T, dir string, fn func(map[string]any)) {
	patchJSON(t, filepath.Join(dir, model.FileMetadata), fn)
}

func patchNorm(t *testing.T, dir string, fn func(map[string]any)) {
	patchJSON(t, filepath.Join(dir, model.FileNormalizer), fn)
}

func patchJSON(t *testing.T, path string, fn func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, out)
}
