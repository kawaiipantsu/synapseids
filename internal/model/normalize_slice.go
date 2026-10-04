package model

import "math"

// NormalizeValues applies this bundle's fitted transform to a complete vector.
// Validate must have passed; input is never modified.
func (b *Bundle) NormalizeValues(values []float64) []float32 {
	out := make([]float32, len(values))
	for i, x := range values {
		if b.norm.Transform == "signed_log1p" {
			x = math.Copysign(math.Log1p(math.Abs(x)), x)
		}
		if b.norm.Method != "identity" && i < len(b.norm.PerFeature) {
			f := b.norm.PerFeature[i]
			switch b.norm.Method {
			case "standard":
				x = (x - f.Mean) / f.Std
			case "minmax":
				x = (x - f.Min) / (f.Max - f.Min)
			}
		}
		if math.IsNaN(x) || math.IsInf(x, 0) {
			x = 0
		}
		limit := b.norm.Clip
		if limit <= 0 {
			limit = 1e6
		}
		x = math.Max(-limit, math.Min(limit, x))
		out[i] = float32(x)
	}
	return out
}
