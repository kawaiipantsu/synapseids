package model

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

const hashPrefix = "sha256:"

// Validate is the activation gate. It returns a non-nil error — naming the
// offending field — when the bundle is missing a file, carries invalid JSON, or
// declares a feature/output contract, architecture, metadata or model hash that
// this build cannot honour (PROJECT.md §11, §28.6). A nil return means the
// bundle is safe for a later, explicit activation step; Validate itself
// activates nothing (§28.10).
func (b *Bundle) Validate() error {
	for _, f := range RequiredFiles() {
		if _, err := os.Stat(filepath.Join(b.dir, f)); err != nil {
			return fmt.Errorf("model bundle %s: %w", f, err)
		}
	}

	m := b.meta
	if err := schema.ValidateBundle(m.BundleMeta()); err != nil {
		return fmt.Errorf("metadata.json: %w", err)
	}
	if m.Architecture.IsZero() {
		return errors.New("metadata.json: architecture block is missing")
	}
	if err := schema.ValidateArchitectureForFamily(m.Family, m.Architecture); err != nil {
		return fmt.Errorf("metadata.json: %w", err)
	}
	if m.Family == "" {
		return errors.New("metadata.json: family is empty")
	}
	if m.ParameterCount <= 0 {
		return fmt.Errorf("metadata.json: parameter_count %d must be > 0", m.ParameterCount)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("metadata.json: created_at %q is not RFC3339", m.CreatedAt)
	}
	if err := verifyHash(m.ModelHash, b.hash); err != nil {
		return err
	}
	return b.norm.validate()
}

// verifyHash checks metadata's model_hash: it must carry the "sha256:" prefix,
// be 64 lowercase hex digits, and equal the SHA-256 recomputed over the
// model.onnx bytes (got, already in "sha256:<hex>" form).
func verifyHash(field, got string) error {
	if !strings.HasPrefix(field, hashPrefix) {
		return fmt.Errorf("metadata.json: model_hash %q is missing the %q prefix", field, hashPrefix)
	}
	h := strings.TrimPrefix(field, hashPrefix)
	if len(h) != 64 {
		return fmt.Errorf("metadata.json: model_hash has %d hex digits, want 64", len(h))
	}
	if h != strings.ToLower(h) {
		return fmt.Errorf("metadata.json: model_hash %q must be lowercase hex", field)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return fmt.Errorf("metadata.json: model_hash %q is not valid hex", field)
	}
	if field != got {
		return fmt.Errorf("metadata.json: model_hash %s does not match %s (recomputed %s over the file bytes)", field, FileModel, got)
	}
	return nil
}

// validate checks normalizer.json for structural sanity against the frozen
// feature schema (PROJECT.md §8, §11). An "identity" spec only has to name the
// right feature schema; "standard" and "minmax" must carry one well-formed,
// in-order entry per feature.
func (s NormalizerSpec) validate() error {
	switch s.Method {
	case "standard", "minmax", "identity":
	default:
		return fmt.Errorf("normalizer.json: method %q is not one of standard, minmax, identity", s.Method)
	}
	if s.FeatureSchema != features.SchemaID {
		return fmt.Errorf("normalizer.json: feature_schema %q != %q", s.FeatureSchema, features.SchemaID)
	}
	if s.Method == "identity" {
		return nil
	}
	if len(s.PerFeature) != features.Size {
		return fmt.Errorf("normalizer.json: per_feature has %d entries, want %d", len(s.PerFeature), features.Size)
	}
	for i, pf := range s.PerFeature {
		if pf.Index != i {
			return fmt.Errorf("normalizer.json: per_feature[%d] has index %d — entries must be ascending 0..%d with no gaps or duplicates", i, pf.Index, features.Size-1)
		}
		switch s.Method {
		case "standard":
			if pf.Std <= 0 {
				return fmt.Errorf("normalizer.json: per_feature[%d] (%s) std %g must be > 0 for method standard", i, pf.Name, pf.Std)
			}
		case "minmax":
			if pf.Min >= pf.Max {
				return fmt.Errorf("normalizer.json: per_feature[%d] (%s) min %g must be < max %g for method minmax", i, pf.Name, pf.Min, pf.Max)
			}
		}
	}
	return nil
}

// build turns a spec into the features.Normalizer the model applies before the
// net. It assumes validate has already passed.
func (s NormalizerSpec) build() (features.Normalizer, error) {
	switch s.Method {
	case "identity", "":
		return features.Identity{}, nil
	case "standard":
		mean := make([]float64, len(s.PerFeature))
		std := make([]float64, len(s.PerFeature))
		for i, pf := range s.PerFeature {
			mean[i], std[i] = pf.Mean, pf.Std
		}
		return features.NewStandardNormalizer(mean, std)
	case "minmax":
		lo := make([]float64, len(s.PerFeature))
		hi := make([]float64, len(s.PerFeature))
		for i, pf := range s.PerFeature {
			lo[i], hi[i] = pf.Min, pf.Max
		}
		return features.NewMinMaxNormalizer(lo, hi)
	default:
		return nil, fmt.Errorf("normalizer.json: method %q unsupported", s.Method)
	}
}
