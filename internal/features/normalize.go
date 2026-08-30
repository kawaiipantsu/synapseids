package features

import "math"

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
