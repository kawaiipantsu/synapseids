// Package model loads a self-describing model bundle from disk and checks it
// against this daemon's frozen contracts before anything is allowed to run it.
//
// A bundle is a directory produced by the Python trainer (synapse-trainer):
//
//	model-bundle/
//	├── model.onnx           the serialized network (opaque to this package)
//	├── metadata.json        the PROJECT.md §11 descriptor
//	├── normalizer.json      the fitted per-feature input transform
//	├── metrics.json         evaluation metrics (kept, not interpreted here)
//	└── training-recipe.json optimizer / schedule / seed (kept, not interpreted here)
//
// Load reads all five files and returns an inactive *Bundle; it activates
// nothing. Validate is the gate: it refuses a bundle whose feature/output
// contract, declared architecture, metadata or model hash does not match what
// this build can feed and interpret (PROJECT.md §11, §28.6, §28.10).
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

// Bundle file names. A bundle directory must contain exactly these.
const (
	FileModel      = "model.onnx"
	FileMetadata   = "metadata.json"
	FileNormalizer = "normalizer.json"
	FileMetrics    = "metrics.json"
	FileRecipe     = "training-recipe.json"
)

// RequiredFiles lists every file a bundle directory must contain, in a stable
// order. It is the contract shared with synapse-trainer.
func RequiredFiles() []string {
	return []string{FileModel, FileMetadata, FileNormalizer, FileMetrics, FileRecipe}
}

// Bundle is a loaded, inactive model bundle. Nothing about holding one implies
// it may run; see Validate and PROJECT.md §28.10.
type Bundle struct {
	dir      string
	onnxPath string
	hash     string // recomputed lowercase "sha256:<hex>" of the model.onnx bytes
	meta     Metadata
	norm     NormalizerSpec
	metrics  json.RawMessage
	recipe   json.RawMessage
	exec     Executor
}

// Load reads the five bundle files under dir, JSON-parses the four descriptors,
// recomputes the SHA-256 of model.onnx, and returns an inactive *Bundle. It does
// not validate the contract (call Validate) and it activates nothing.
func Load(dir string) (*Bundle, error) {
	b := &Bundle{dir: dir, onnxPath: filepath.Join(dir, FileModel)}

	raw, err := os.ReadFile(b.onnxPath)
	if err != nil {
		return nil, fmt.Errorf("model bundle %s: %w", FileModel, err)
	}
	sum := sha256.Sum256(raw)
	b.hash = hashPrefix + hex.EncodeToString(sum[:])

	if err := readJSON(filepath.Join(dir, FileMetadata), &b.meta); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, FileNormalizer), &b.norm); err != nil {
		return nil, err
	}
	if b.metrics, err = readRawJSON(filepath.Join(dir, FileMetrics)); err != nil {
		return nil, err
	}
	if b.recipe, err = readRawJSON(filepath.Join(dir, FileRecipe)); err != nil {
		return nil, err
	}
	return b, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("model bundle %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("model bundle %s: invalid JSON: %w", filepath.Base(path), err)
	}
	return nil
}

func readRawJSON(path string) (json.RawMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("model bundle %s: %w", filepath.Base(path), err)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("model bundle %s: invalid JSON", filepath.Base(path))
	}
	return json.RawMessage(raw), nil
}

// Dir returns the bundle directory.
func (b *Bundle) Dir() string { return b.dir }

// Meta returns the parsed metadata.json.
func (b *Bundle) Meta() Metadata { return b.meta }

// Metrics returns the raw metrics.json bytes (valid JSON, otherwise uninterpreted).
func (b *Bundle) Metrics() json.RawMessage { return b.metrics }

// Recipe returns the raw training-recipe.json bytes (valid JSON, otherwise
// uninterpreted).
func (b *Bundle) Recipe() json.RawMessage { return b.recipe }

// ONNXPath returns the absolute-or-relative path to model.onnx as given to Load.
func (b *Bundle) ONNXPath() string { return b.onnxPath }

// Hash returns the SHA-256 recomputed over the model.onnx bytes, formatted
// "sha256:<lowercase hex>".
func (b *Bundle) Hash() string { return b.hash }

// Normalizer returns the fitted input transform this bundle's model applies
// before the network: features.Identity for method "identity", a fitted
// features.Affine for "standard" or "minmax". Call Validate first — this returns
// an error only when the spec is structurally unusable.
func (b *Bundle) Normalizer() (features.Normalizer, error) {
	return b.norm.build()
}

// Executor runs one normalized feature vector through a model's network and
// returns raw class scores. Bundle validation does not need it; the
// implementation is supplied by internal/nn (issue #24, feature/onnx-runtime).
type Executor interface {
	Run(input []float32) ([]float32, error)
}

// Bind attaches an execution backend to a loaded bundle. It has no effect on
// Validate and is currently unused — issue #24 wires the ONNX runtime that
// implements Executor.
func (b *Bundle) Bind(e Executor) { b.exec = e }

// Executor returns the backend attached by Bind, or nil.
func (b *Bundle) Executor() Executor { return b.exec }
