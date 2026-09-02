package obs

import (
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Metrics is the instrument set the pipeline records into and GET /metrics
// reads. It is the part of PROJECT.md §24 that no other Stats() covers: the
// latency distributions and the per-class verdict tally, both recorded on the
// pipeline goroutine (never the packet loop).
//
// The daemon builds one and shares it: pipeline.Options.Metrics for recording,
// api.New's metricsProvider for exposition. A nil *Metrics is inert — every
// method is nil-safe — so replay-only and embedded callers need not wire one.
type Metrics struct {
	inferenceLatency *Histogram
	featureLatency   *Histogram

	inferenceFailures atomic.Uint64
	// classified is indexed by traffic-classes-v1 class index. A slice of
	// atomics (sized once from the frozen schema, never resized), so recording a
	// verdict is a single atomic add with no allocation and no lock.
	classified []atomic.Uint64
}

// New returns a ready Metrics with the default latency buckets.
func New() *Metrics {
	return &Metrics{
		inferenceLatency: NewHistogram(DefaultLatencyBounds()),
		featureLatency:   NewHistogram(DefaultLatencyBounds()),
		classified:       make([]atomic.Uint64, schema.TrafficClassesV1().OutputSize),
	}
}

// ObserveScore records one model scoring: its wall-clock cost and the class it
// returned. classIndex outside the traffic-classes-v1 range is counted only in
// the latency histogram (it should never happen — the runtime always returns a
// valid class — but a metric must not panic on bad input, §28.11).
func (m *Metrics) ObserveScore(classIndex int, d time.Duration) {
	if m == nil {
		return
	}
	m.inferenceLatency.Observe(d.Seconds())
	if classIndex >= 0 && classIndex < len(m.classified) {
		m.classified[classIndex].Add(1)
	}
}

// ObserveFeatureExtract records one features.Extract call's wall-clock cost.
func (m *Metrics) ObserveFeatureExtract(d time.Duration) {
	if m == nil {
		return
	}
	m.featureLatency.Observe(d.Seconds())
}

// IncInferenceFailure counts a scoring call that could not produce a verdict.
func (m *Metrics) IncInferenceFailure() {
	if m == nil {
		return
	}
	m.inferenceFailures.Add(1)
}

// Snapshot is a consistent read of every instrument, for rendering.
type Snapshot struct {
	InferenceLatency  HistogramSnapshot
	FeatureLatency    HistogramSnapshot
	InferenceFailures uint64
	// Classified maps a traffic-classes-v1 class name to how many verdicts of
	// that class the runtime has produced this process lifetime.
	Classified map[string]uint64
}

// Snapshot copies every instrument. A nil *Metrics returns a zero Snapshot that
// still has the full, stable series set — every traffic-classes-v1 class at
// zero, usable histograms — so a renderer never has to nil-check and a scraper
// never sees a series appear only once the first flow is scored.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		empty := NewHistogram([]float64{1}).Snapshot()
		return Snapshot{InferenceLatency: empty, FeatureLatency: empty, Classified: zeroClasses()}
	}
	byClass := make(map[string]uint64, len(m.classified))
	for i := range m.classified {
		byClass[schema.ClassName(i)] = m.classified[i].Load()
	}
	return Snapshot{
		InferenceLatency:  m.inferenceLatency.Snapshot(),
		FeatureLatency:    m.featureLatency.Snapshot(),
		InferenceFailures: m.inferenceFailures.Load(),
		Classified:        byClass,
	}
}

func zeroClasses() map[string]uint64 {
	n := schema.TrafficClassesV1().OutputSize
	out := make(map[string]uint64, n)
	for i := 0; i < n; i++ {
		out[schema.ClassName(i)] = 0
	}
	return out
}

// InferenceQuantile is the approximate q-quantile (0..1) of scoring latency in
// seconds, for the /api/v1/status convenience view.
func (m *Metrics) InferenceQuantile(q float64) float64 {
	if m == nil {
		return 0
	}
	return m.inferenceLatency.Quantile(q)
}
