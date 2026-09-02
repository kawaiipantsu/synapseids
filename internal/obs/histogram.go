// Package obs is the daemon's observability surface (issue #55, PROJECT.md §24):
// a stdlib-only metric set for the GET /metrics Prometheus endpoint, and the
// structured-logging setup.
//
// It holds only what no subsystem already reports through its own Stats() — the
// latency histograms and per-class counters that have to be recorded where the
// work happens. The /metrics handler in internal/api renders these alongside the
// counters it already gathers for /api/v1/status, so nothing is double-counted.
//
// Zero third-party dependencies (CLAUDE.md): the histogram is hand-rolled, the
// Prometheus text is written by hand, and structured logging is log/slog.
package obs

import (
	"math"
	"sort"
	"sync"
)

// Histogram is a fixed-bucket cumulative histogram, the shape a Prometheus
// histogram takes on the wire: per-bucket counts (cumulative, "less than or
// equal to"), a running sum, and a total count. Observe is safe for concurrent
// callers; it is called once per scored flow on the pipeline goroutine, never on
// the packet loop (PROJECT.md §22).
type Histogram struct {
	bounds []float64 // upper bounds, ascending, without the implicit +Inf

	mu     sync.Mutex
	counts []uint64 // len(bounds)+1; the last cell is the +Inf overflow
	sum    float64
	total  uint64
}

// NewHistogram returns a histogram with the given upper bounds. The bounds are
// sorted and de-duplicated; a nil or empty slice is a programming error and
// panics, because a histogram with no buckets measures nothing.
func NewHistogram(bounds []float64) *Histogram {
	if len(bounds) == 0 {
		panic("obs: NewHistogram needs at least one bucket bound")
	}
	b := append([]float64(nil), bounds...)
	sort.Float64s(b)
	b = dedupeSorted(b)
	return &Histogram{bounds: b, counts: make([]uint64, len(b)+1)}
}

// DefaultLatencyBounds covers sub-microsecond to ~1s in seconds, which is the
// range inference and feature extraction live in: a heuristic score is tens of
// microseconds, an ONNX forward pass single-digit milliseconds, and anything
// past a second is a problem worth a bucket of its own.
func DefaultLatencyBounds() []float64 {
	return []float64{
		1e-6, 5e-6, 1e-5, 5e-5, 1e-4, 5e-4,
		1e-3, 5e-3, 1e-2, 5e-2, 1e-1, 5e-1, 1,
	}
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	i := sort.SearchFloat64s(h.bounds, v)
	// SearchFloat64s returns the first index whose bound is >= v; a value equal
	// to a bound belongs in that bucket ("le"), which is exactly index i.
	h.mu.Lock()
	h.counts[i]++
	h.sum += v
	h.total++
	h.mu.Unlock()
}

// HistogramSnapshot is a consistent copy of a Histogram for rendering.
type HistogramSnapshot struct {
	Bounds     []float64 // upper bounds, ascending (no +Inf)
	Counts     []uint64  // len(Bounds)+1, cumulative-ready per-bucket counts
	Cumulative []uint64  // len(Bounds)+1, running total including the +Inf cell
	Sum        float64
	Total      uint64
}

// Snapshot copies the histogram under its lock.
func (h *Histogram) Snapshot() HistogramSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	counts := append([]uint64(nil), h.counts...)
	cum := make([]uint64, len(counts))
	var run uint64
	for i, c := range counts {
		run += c
		cum[i] = run
	}
	return HistogramSnapshot{
		Bounds:     append([]float64(nil), h.bounds...),
		Counts:     counts,
		Cumulative: cum,
		Sum:        h.sum,
		Total:      h.total,
	}
}

// Quantile is a linear-interpolation estimate of the q-quantile (0..1) from the
// bucket boundaries. It is approximate by construction — the true value is
// somewhere inside a bucket — and is offered for the /api/v1/status convenience
// view; /metrics exposes the raw buckets so a scraper can do better.
func (h *Histogram) Quantile(q float64) float64 {
	s := h.Snapshot()
	if s.Total == 0 {
		return 0
	}
	if q <= 0 {
		return 0
	}
	if q >= 1 {
		// The open-topped last bucket has no finite bound; report the largest
		// finite bound as the floor of "everything at or above it".
		return s.Bounds[len(s.Bounds)-1]
	}
	rank := q * float64(s.Total)
	for i, c := range s.Cumulative {
		if float64(c) < rank {
			continue
		}
		lo := 0.0
		if i > 0 {
			lo = s.Bounds[i-1]
		}
		hi := math.Inf(1)
		if i < len(s.Bounds) {
			hi = s.Bounds[i]
		}
		if math.IsInf(hi, 1) {
			return lo
		}
		prev := 0.0
		if i > 0 {
			prev = float64(s.Cumulative[i-1])
		}
		frac := 0.0
		if in := float64(s.Counts[i]); in > 0 {
			frac = (rank - prev) / in
		}
		return lo + (hi-lo)*frac
	}
	return s.Bounds[len(s.Bounds)-1]
}

func dedupeSorted(s []float64) []float64 {
	out := make([]float64, 0, len(s))
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
