package features

import (
	"fmt"
	"math"
)

// Normalizer maps a raw feature vector into model input space. The trained-model
// path will load a z-score Normalizer from a bundle's normalizer.json; Phase 1
// ships only the identity and a log1p-of-counts helper (PROJECT.md §8, §11).
type Normalizer interface {
	Normalize(v Vector) Vector
	ID() string
}

// Identity returns the vector unchanged.
type Identity struct{}

// Normalize returns v unchanged.
func (Identity) Normalize(v Vector) Vector { return v }

// ID identifies the normalizer.
func (Identity) ID() string { return "identity" }

// Log1p applies log1p to the count- and rate-like features named "log1p" in the
// frozen schema and leaves flags and ratios alone. It is deterministic and needs
// no fitted parameters, which makes it a safe default for the heuristic model.
type Log1p struct{}

var log1pIdx = func() map[int]bool {
	// Indices whose schema "norm" is "log1p" (see schemas/features/flow-features-v1.json).
	m := map[int]bool{}
	for _, i := range []int{0, 1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 26, 27, 28, 29, 30, 31, 32, 37} {
		m[i] = true
	}
	return m
}()

// Normalize applies log1p to the log-scaled features of v.
func (Log1p) Normalize(v Vector) Vector {
	out := v
	for i := range out.Values {
		if log1pIdx[i] && out.Values[i] > 0 {
			out.Values[i] = math.Log1p(out.Values[i])
		}
	}
	return out
}

// ID identifies the normalizer.
func (Log1p) ID() string { return "log1p" }

// normEpsilon guards the divisor of an Affine transform so a zero-variance or
// zero-range feature maps to a finite value instead of ±Inf/NaN.
const normEpsilon = 1e-9

// Affine is a fitted per-feature transform of the form (x-offset)/scale, applied
// to every entry of a Vector in the frozen schema order. It is how a trained
// model's normalizer.json (z-score "standard" or "minmax") is applied before the
// net; the heuristic never uses it and the pipeline never installs it — it is a
// per-model concern (PROJECT.md §8, §11). Build one with NewStandardNormalizer
// or NewMinMaxNormalizer.
type Affine struct {
	id     string
	offset [Size]float64
	scale  [Size]float64
}

// Normalize returns a copy of v with each value mapped to (value-offset)/scale.
func (a Affine) Normalize(v Vector) Vector {
	out := v
	for i := range out.Values {
		out.Values[i] = (out.Values[i] - a.offset[i]) / a.scale[i]
	}
	return out
}

// ID identifies the normalizer ("standard" or "minmax").
func (a Affine) ID() string { return a.id }

// NewStandardNormalizer builds a z-score transform: (x-mean)/max(std, 1e-9).
// mean and std must each hold exactly Size values in schema order.
func NewStandardNormalizer(mean, std []float64) (Affine, error) {
	if len(mean) != Size || len(std) != Size {
		return Affine{}, fmt.Errorf("features: standard normalizer needs %d mean and %d std values, got %d and %d", Size, Size, len(mean), len(std))
	}
	a := Affine{id: "standard"}
	for i := 0; i < Size; i++ {
		a.offset[i] = mean[i]
		a.scale[i] = math.Max(std[i], normEpsilon)
	}
	return a, nil
}

// NewMinMaxNormalizer builds a min-max transform: (x-min)/max(max-min, 1e-9).
// min and max must each hold exactly Size values in schema order.
func NewMinMaxNormalizer(minv, maxv []float64) (Affine, error) {
	if len(minv) != Size || len(maxv) != Size {
		return Affine{}, fmt.Errorf("features: minmax normalizer needs %d min and %d max values, got %d and %d", Size, Size, len(minv), len(maxv))
	}
	a := Affine{id: "minmax"}
	for i := 0; i < Size; i++ {
		a.offset[i] = minv[i]
		a.scale[i] = math.Max(maxv[i]-minv[i], normEpsilon)
	}
	return a, nil
}
