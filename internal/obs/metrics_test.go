package obs

import (
	"testing"
	"time"
)

func TestMetricsObserveScore(t *testing.T) {
	m := New()
	m.ObserveScore(1, 2*time.Millisecond) // class index 1 == "scan"
	m.ObserveScore(1, 4*time.Millisecond)
	m.ObserveScore(0, time.Millisecond) // "normal"
	m.IncInferenceFailure()

	s := m.Snapshot()
	if s.InferenceLatency.Total != 3 {
		t.Errorf("latency count = %d, want 3", s.InferenceLatency.Total)
	}
	if s.Classified["scan"] != 2 {
		t.Errorf("scan count = %d, want 2", s.Classified["scan"])
	}
	if s.Classified["normal"] != 1 {
		t.Errorf("normal count = %d, want 1", s.Classified["normal"])
	}
	if s.InferenceFailures != 1 {
		t.Errorf("failures = %d, want 1", s.InferenceFailures)
	}
	// Every traffic-classes-v1 class is present in the map, even at zero, so a
	// scrape has a stable series set.
	if len(s.Classified) != 7 {
		t.Errorf("classified map has %d classes, want 7", len(s.Classified))
	}
}

func TestMetricsOutOfRangeClassIndex(t *testing.T) {
	m := New()
	m.ObserveScore(99, time.Millisecond) // must not panic
	m.ObserveScore(-1, time.Millisecond)
	if s := m.Snapshot(); s.InferenceLatency.Total != 2 {
		t.Errorf("latency still recorded: count = %d, want 2", s.InferenceLatency.Total)
	}
}

func TestMetricsNilSafe(t *testing.T) {
	var m *Metrics
	m.ObserveScore(1, time.Millisecond)
	m.ObserveFeatureExtract(time.Millisecond)
	m.IncInferenceFailure()
	s := m.Snapshot()
	if s.Classified == nil {
		t.Error("nil Metrics Snapshot must return a non-nil Classified map")
	}
	if s.InferenceLatency.Bounds == nil {
		t.Error("nil Metrics Snapshot must return a usable (non-nil) histogram")
	}
	if m.InferenceQuantile(0.9) != 0 {
		t.Error("nil Metrics quantile must be 0")
	}
}
