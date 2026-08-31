package features

import (
	"math"
	"testing"
)

func TestIdentityNormalizer(t *testing.T) {
	var v Vector
	v.Values[0] = 3.5
	v.Values[47] = -2
	got := (Identity{}).Normalize(v)
	if got != v {
		t.Fatalf("Identity changed the vector: %+v", got)
	}
	if (Identity{}).ID() != "identity" {
		t.Fatalf("Identity ID = %q", (Identity{}).ID())
	}
}

func TestStandardNormalizer(t *testing.T) {
	mean := make([]float64, Size)
	std := make([]float64, Size)
	for i := range mean {
		mean[i] = 10
		std[i] = 2
	}
	std[5] = 0 // zero variance must not produce Inf/NaN

	n, err := NewStandardNormalizer(mean, std)
	if err != nil {
		t.Fatalf("NewStandardNormalizer: %v", err)
	}
	if n.ID() != "standard" {
		t.Fatalf("ID = %q, want standard", n.ID())
	}

	var v Vector
	for i := range v.Values {
		v.Values[i] = 14
	}
	out := n.Normalize(v)
	if math.Abs(out.Values[0]-2) > 1e-9 {
		t.Fatalf("(14-10)/2 should be 2, got %v", out.Values[0])
	}
	if math.IsInf(out.Values[5], 0) || math.IsNaN(out.Values[5]) {
		t.Fatalf("zero-std feature produced %v", out.Values[5])
	}
	if math.Abs(out.Values[5]-4/normEpsilon) > 1 {
		t.Fatalf("zero-std feature should divide by epsilon, got %v", out.Values[5])
	}
}

func TestMinMaxNormalizer(t *testing.T) {
	minv := make([]float64, Size)
	maxv := make([]float64, Size)
	for i := range minv {
		minv[i] = 0
		maxv[i] = 100
	}
	maxv[9] = 0 // min == max must not produce Inf/NaN

	n, err := NewMinMaxNormalizer(minv, maxv)
	if err != nil {
		t.Fatalf("NewMinMaxNormalizer: %v", err)
	}
	if n.ID() != "minmax" {
		t.Fatalf("ID = %q, want minmax", n.ID())
	}

	var v Vector
	for i := range v.Values {
		v.Values[i] = 25
	}
	out := n.Normalize(v)
	if math.Abs(out.Values[0]-0.25) > 1e-9 {
		t.Fatalf("(25-0)/100 should be 0.25, got %v", out.Values[0])
	}
	if math.IsInf(out.Values[9], 0) || math.IsNaN(out.Values[9]) {
		t.Fatalf("min==max feature produced %v", out.Values[9])
	}
}

func TestNormalizerWrongLength(t *testing.T) {
	if _, err := NewStandardNormalizer(make([]float64, 10), make([]float64, Size)); err == nil {
		t.Fatal("short mean slice accepted")
	}
	if _, err := NewMinMaxNormalizer(make([]float64, Size), make([]float64, 3)); err == nil {
		t.Fatal("short max slice accepted")
	}
}
