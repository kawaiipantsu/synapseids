package model

import (
	"math"
	"testing"
)

func TestBehaviorNormalizerTransformAndClip(t *testing.T) {
	b := &Bundle{norm: NormalizerSpec{Method: "standard", FeatureSchema: "traffic-behavior-v1", Transform: "signed_log1p", Clip: 8, PerFeature: []NormFeature{{Std: 1}, {Std: 1}, {Std: 1}}}}
	got := b.NormalizeValues([]float64{math.Expm1(2), -math.Expm1(3), math.Expm1(20)})
	for i, w := range []float32{2, -3, 8} {
		if math.Abs(float64(got[i]-w)) > 1e-6 {
			t.Fatal(got)
		}
	}
	b.norm.FeatureSchema = "flow-features-v1"
	if b.norm.validate() == nil {
		t.Fatal("legacy family must reject unsupported transform")
	}
}
