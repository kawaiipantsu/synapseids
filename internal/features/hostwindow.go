package features

import (
	"hash/fnv"
	"sort"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// HostSample is non-identifying model context derived from one conversation.
// Endpoint identity is used only to group observations, never copied to inputs.
type HostSample struct {
	Sensor, Initiator, Responder, Identity string
	Port                                   uint16
	At, Started                            time.Time
	SYNOnly, OneWay                        bool
	Bytes                                  float64
	Telemetry                              *flow.Telemetry
}
type hostEntry struct {
	sample            HostSample
	names             []uint64
	queries, nxdomain uint64
}
type hostRing struct {
	last time.Time
	rows []hostEntry
}

// HostWindow holds at most 1024 source hosts and 64 conversations per host.
// A pipeline/extractor owns it on one goroutine. Different sensors never mix.
type HostWindow struct{ hosts map[string]*hostRing }

// NewHostWindow creates a bounded flow-context accumulator.
func NewHostWindow() *HostWindow { return &HostWindow{hosts: map[string]*hostRing{}} }

// Apply replaces cumulative snapshots of the same conversation, expires records
// older than 60 seconds, and fills the final sixteen behavior feature slots.
func (h *HostWindow) Apply(v *BehaviorVector, s HostSample) {
	key := s.Sensor + "\x00" + s.Initiator
	r := h.hosts[key]
	if r == nil {
		if len(h.hosts) >= 1024 {
			var oldest string
			var at time.Time
			for k, v := range h.hosts {
				if at.IsZero() || v.last.Before(at) {
					oldest, at = k, v.last
				}
			}
			delete(h.hosts, oldest)
		}
		r = &hostRing{}
		h.hosts[key] = r
	}
	if s.At.After(r.last) {
		r.last = s.At
	}
	e := hostEntry{sample: s}
	if s.Telemetry != nil {
		e.queries = s.Telemetry.DNSQueries
		e.nxdomain = s.Telemetry.NXDomains
		for _, n := range s.Telemetry.QueryNames {
			f := fnv.New64a()
			_, _ = f.Write([]byte(n))
			e.names = append(e.names, f.Sum64())
		}
	}
	e.sample.Telemetry = nil
	rows := r.rows[:0]
	for _, old := range r.rows {
		if old.sample.Identity != s.Identity && old.sample.At.After(r.last.Add(-time.Minute)) {
			rows = append(rows, old)
		}
	}
	rows = append(rows, e)
	if len(rows) > 64 {
		rows = rows[len(rows)-64:]
	}
	r.rows = rows
	selected := []hostEntry{}
	for _, entry := range rows {
		if !entry.sample.At.After(s.At) && entry.sample.At.After(s.At.Add(-time.Minute)) {
			selected = append(selected, entry)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].sample.Started.Before(selected[j].sample.Started) })
	ports := map[uint16]bool{}
	dest := map[string]bool{}
	names := map[uint64]bool{}
	gaps := []float64{}
	syn, one := 0, 0
	sums := v.Values[144:]
	for i := range sums {
		sums[i] = 0
	}
	for i, e := range selected {
		ports[e.sample.Port] = true
		dest[e.sample.Responder] = true
		if e.sample.SYNOnly {
			syn++
		}
		if e.sample.OneWay {
			one++
		}
		sums[9] += float64(e.queries)
		sums[10] += float64(e.nxdomain)
		sums[13] += e.sample.Bytes
		for _, n := range e.names {
			names[n] = true
		}
		if i > 0 {
			gap := e.sample.Started.Sub(selected[i-1].sample.Started).Seconds()
			if gap >= 0 {
				gaps = append(gaps, gap)
			}
		}
	}
	n := len(selected)
	sums[0] = float64(n)
	sums[1] = float64(len(ports))
	sums[2] = float64(len(dest))
	if n > 0 {
		sums[3] = float64(syn) / float64(n)
		sums[4] = float64(one) / float64(n)
		sums[12] = selected[n-1].sample.Started.Sub(selected[0].sample.Started).Seconds()
	}
	mean, std := MeanStd(gaps)
	sums[5] = mean
	if mean > 0 {
		sums[6] = std / mean
	}
	sums[7] = Correlation(gaps, 1)
	sums[8] = Correlation(gaps, 2)
	sums[11] = float64(len(names))
	if len(gaps) >= 8 && mean >= 5 {
		sums[14] = 1 / (1 + sums[6])
	}
	sums[15] = 1
	v.Sanitize()
}
