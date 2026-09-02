package pipeline

import (
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// seqWindows keeps, per conversation key, a bounded ring of the last
// schema.SequenceLenV1 flow-features-v1 vectors — the input a flow-sequence-v1
// temporal model scores (ADR 0040). It lives entirely on the pipeline goroutine
// (populated from publish, which runs on flow-close, never the packet loop), so
// it needs no lock.
//
// The map is capped like the flow table and the insight host map: on overflow
// the least-recently-updated quarter is dropped in one pass. A dropped key just
// loses its history — the next flow on that tuple starts a fresh (left-padded)
// window.
type seqWindows struct {
	m       map[string]*seqRing
	cap     int
	evicted uint64
}

type seqRing struct {
	buf      [schema.SequenceLenV1][features.Size]float64
	next     int // write position
	fill     int // entries written, capped at len(buf)
	lastSeen time.Time
}

func newSeqWindows(capacity int) *seqWindows {
	if capacity < 16 {
		capacity = 16
	}
	return &seqWindows{m: make(map[string]*seqRing, 64), cap: capacity}
}

// push appends v to key's ring and returns the ring's contents oldest-first
// (length 1..SequenceLenV1).
func (s *seqWindows) push(key string, v [features.Size]float64, at time.Time) [][features.Size]float64 {
	r := s.m[key]
	if r == nil {
		if len(s.m) >= s.cap {
			s.prune()
		}
		r = &seqRing{}
		s.m[key] = r
	}
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.fill < len(r.buf) {
		r.fill++
	}
	r.lastSeen = at

	out := make([][features.Size]float64, r.fill)
	// Oldest entry is at (next - fill), wrapping.
	start := (r.next - r.fill + len(r.buf)) % len(r.buf)
	for i := 0; i < r.fill; i++ {
		out[i] = r.buf[(start+i)%len(r.buf)]
	}
	return out
}

// prune drops roughly the least-recently-updated quarter of the map in one pass.
func (s *seqWindows) prune() {
	target := s.cap - s.cap/4
	if target < 1 {
		target = 1
	}
	// Find a lastSeen cutoff: the (cap/4)-th oldest. A partial selection would be
	// tighter, but the map is small and this runs rarely.
	times := make([]time.Time, 0, len(s.m))
	for _, r := range s.m {
		times = append(times, r.lastSeen)
	}
	// simple: sort ascending, cut at index len-target
	for i := 1; i < len(times); i++ {
		for j := i; j > 0 && times[j].Before(times[j-1]); j-- {
			times[j], times[j-1] = times[j-1], times[j]
		}
	}
	cut := times[len(times)-target]
	for k, r := range s.m {
		if r.lastSeen.Before(cut) && len(s.m) > target {
			delete(s.m, k)
			s.evicted++
		}
	}
}

// seqKey is a conversation identity for the ring: the direction-normalised
// 5-tuple, already normalised by the flow engine (InitiatorIP is the initiator).
func seqKey(initiatorIP string, initiatorPort uint16, responderIP string, responderPort uint16, proto string) string {
	return initiatorIP + "\x00" + itoa16(initiatorPort) + "\x00" + responderIP + "\x00" + itoa16(responderPort) + "\x00" + proto
}

func itoa16(n uint16) string {
	if n == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
