package obs

import (
	"math"
	"testing"
)

func TestHistogramObserveAndSnapshot(t *testing.T) {
	h := NewHistogram([]float64{1, 2, 5, 10})
	for _, v := range []float64{0.5, 1, 1.5, 3, 3, 7, 42} {
		h.Observe(v)
	}
	s := h.Snapshot()

	if s.Total != 7 {
		t.Fatalf("total = %d, want 7", s.Total)
	}
	if got, want := s.Sum, 0.5+1+1.5+3+3+7+42.0; math.Abs(got-want) > 1e-9 {
		t.Errorf("sum = %v, want %v", got, want)
	}
	// Per-bucket (non-cumulative): le=1 -> {0.5, 1}; le=2 -> {1.5}; le=5 -> {3,3};
	// le=10 -> {7}; +Inf -> {42}.
	wantCounts := []uint64{2, 1, 2, 1, 1}
	for i, w := range wantCounts {
		if s.Counts[i] != w {
			t.Errorf("bucket %d count = %d, want %d", i, s.Counts[i], w)
		}
	}
	// Cumulative is what the wire format needs: 2, 3, 5, 6, 7.
	wantCum := []uint64{2, 3, 5, 6, 7}
	for i, w := range wantCum {
		if s.Cumulative[i] != w {
			t.Errorf("cumulative %d = %d, want %d", i, s.Cumulative[i], w)
		}
	}
}

func TestHistogramBoundsSortedAndDeduped(t *testing.T) {
	h := NewHistogram([]float64{10, 1, 5, 5, 2})
	s := h.Snapshot()
	want := []float64{1, 2, 5, 10}
	if len(s.Bounds) != len(want) {
		t.Fatalf("bounds = %v, want %v", s.Bounds, want)
	}
	for i, b := range want {
		if s.Bounds[i] != b {
			t.Fatalf("bounds = %v, want %v", s.Bounds, want)
		}
	}
}

func TestHistogramQuantile(t *testing.T) {
	h := NewHistogram([]float64{1, 2, 5, 10})
	for i := 0; i < 100; i++ {
		h.Observe(3) // everything in the (2, 5] bucket
	}
	q := h.Quantile(0.5)
	if q < 2 || q > 5 {
		t.Errorf("q50 = %v, want somewhere in (2,5]", q)
	}
	if h.Quantile(0) != 0 {
		t.Errorf("q0 = %v, want 0", h.Quantile(0))
	}
	// q1 on an all-in-one-finite-bucket histogram is the top of that bucket's
	// range floor; just assert it is finite and >= the largest crossed bound.
	if got := h.Quantile(1); math.IsInf(got, 0) || got < 2 {
		t.Errorf("q100 = %v, want a finite value >= 2", got)
	}
}

func TestHistogramQuantileEmpty(t *testing.T) {
	if got := NewHistogram([]float64{1}).Quantile(0.9); got != 0 {
		t.Errorf("quantile of an empty histogram = %v, want 0", got)
	}
}

func TestNewHistogramRejectsNoBounds(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHistogram(nil) did not panic")
		}
	}()
	NewHistogram(nil)
}

func TestHistogramConcurrentObserve(t *testing.T) {
	h := NewHistogram(DefaultLatencyBounds())
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func() {
			for i := 0; i < 1000; i++ {
				h.Observe(1e-4)
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	close(done)
	if got := h.Snapshot().Total; got != 8000 {
		t.Errorf("total under concurrent Observe = %d, want 8000", got)
	}
}
