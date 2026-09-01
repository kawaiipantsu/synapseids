package obs

import (
	"strings"
	"testing"
)

func TestWriterCounterAndGauge(t *testing.T) {
	var b strings.Builder
	p := NewWriter(&b)
	p.Counter("synapseids_x_total", "an x counter", 3)
	p.Counter("synapseids_x_total", "an x counter", 7, Label{"src", "a"})
	p.Gauge("synapseids_y", "a y gauge", 1.5)
	if err := p.Err(); err != nil {
		t.Fatalf("write err: %v", err)
	}
	out := b.String()

	// HELP/TYPE header once per family, before any sample.
	if strings.Count(out, "# TYPE synapseids_x_total counter") != 1 {
		t.Errorf("x TYPE header not emitted exactly once:\n%s", out)
	}
	for _, want := range []string{
		"# HELP synapseids_x_total an x counter\n",
		"synapseids_x_total 3\n",
		`synapseids_x_total{src="a"} 7` + "\n",
		"# TYPE synapseids_y gauge\n",
		"synapseids_y 1.5\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWriterHistogram(t *testing.T) {
	h := NewHistogram([]float64{1, 5})
	h.Observe(0.5)
	h.Observe(3)
	h.Observe(9)
	var b strings.Builder
	p := NewWriter(&b)
	p.Histogram("synapseids_lat_seconds", "latency", h.Snapshot())
	out := b.String()

	for _, want := range []string{
		"# TYPE synapseids_lat_seconds histogram\n",
		`synapseids_lat_seconds_bucket{le="1"} 1` + "\n",
		`synapseids_lat_seconds_bucket{le="5"} 2` + "\n",
		`synapseids_lat_seconds_bucket{le="+Inf"} 3` + "\n",
		"synapseids_lat_seconds_sum 12.5\n",
		"synapseids_lat_seconds_count 3\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWriterLabelEscapingAndOrder(t *testing.T) {
	var b strings.Builder
	p := NewWriter(&b)
	p.Gauge("g", "h", 1, Label{"z", "last"}, Label{"a", `a "quote" and \slash`})
	out := b.String()
	// Labels are emitted in name order; the value is escaped.
	want := `g{a="a \"quote\" and \\slash",z="last"} 1` + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("label rendering:\n got %q\nwant contains %q", out, want)
	}
}
