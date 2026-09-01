package obs

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// The Prometheus text exposition format (version 0.0.4) is small enough to write
// by hand, which is what "zero third-party dependencies" requires (CLAUDE.md).
// These helpers are all a /metrics handler needs: a typed metric header and one
// line per sample, with label values and the metric name escaped to the spec.

// Writer accumulates exposition text and tracks which metric families have had
// their HELP/TYPE header emitted, so a caller can stream samples without
// repeating headers or worrying about ordering within a family.
type Writer struct {
	w    io.Writer
	seen map[string]bool
	err  error
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, seen: map[string]bool{}}
}

// Err returns the first write error, if any.
func (p *Writer) Err() error { return p.err }

func (p *Writer) printf(format string, a ...any) {
	if p.err != nil {
		return
	}
	if _, err := fmt.Fprintf(p.w, format, a...); err != nil {
		p.err = err
	}
}

func (p *Writer) header(name, help, typ string) {
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	p.printf("# HELP %s %s\n", name, escapeHelp(help))
	p.printf("# TYPE %s %s\n", name, typ)
}

// Counter writes one counter sample. Call it repeatedly with different labels
// for the same name; the header is written once.
func (p *Writer) Counter(name, help string, value uint64, labels ...Label) {
	p.header(name, help, "counter")
	p.printf("%s%s %d\n", name, formatLabels(labels), value)
}

// Gauge writes one gauge sample.
func (p *Writer) Gauge(name, help string, value float64, labels ...Label) {
	p.header(name, help, "gauge")
	p.printf("%s%s %s\n", name, formatLabels(labels), formatFloat(value))
}

// GaugeInt is a convenience for an integer-valued gauge.
func (p *Writer) GaugeInt(name, help string, value int64, labels ...Label) {
	p.header(name, help, "gauge")
	p.printf("%s%s %d\n", name, formatLabels(labels), value)
}

// Histogram writes the full set of lines for one histogram family: a cumulative
// `_bucket` line per bound plus the `+Inf` bucket, then `_sum` and `_count`.
// extra labels (if any) are attached to every line.
func (p *Writer) Histogram(name, help string, s HistogramSnapshot, extra ...Label) {
	p.header(name, help, "histogram")
	for i, ub := range s.Bounds {
		p.printf("%s_bucket%s %d\n", name, formatLabels(withLabel(extra, "le", formatFloat(ub))), s.Cumulative[i])
	}
	p.printf("%s_bucket%s %d\n", name, formatLabels(withLabel(extra, "le", "+Inf")), s.Total)
	p.printf("%s_sum%s %s\n", name, formatLabels(extra), formatFloat(s.Sum))
	p.printf("%s_count%s %d\n", name, formatLabels(extra), s.Total)
}

// Label is one key/value pair on a sample.
type Label struct{ Name, Value string }

func withLabel(base []Label, name, value string) []Label {
	out := make([]Label, 0, len(base)+1)
	out = append(out, base...)
	out = append(out, Label{name, value})
	return out
}

func formatLabels(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	// Deterministic order so a diff of two scrapes is readable.
	sorted := append([]Label(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.Name)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(l.Value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func formatFloat(v float64) string {
	// -1 precision gives the shortest representation that round-trips.
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
