package flow

import "time"

// TickEvery is how many observed packets pass between Table.Tick calls when
// capture time is not advancing fast enough to trigger one sooner.
const TickEvery = 512

// tickInterval is the capture-time gap that also forces a Tick, so idle and
// max-lifetime expiry stay responsive on a quiet link.
const tickInterval = time.Second

// Pacer decides when a packet loop should call Table.Tick. It exists so every
// consumer of a Table paces expiry identically: the daemon's pipeline and a
// `flow`/`feature`-mode sensor must draw flow boundaries at the same points, or
// the same capture would classify differently depending on which sensor mode
// carried it (issue #45).
//
// A Pacer is single-goroutine, like the Table it paces. The zero value is ready.
type Pacer struct {
	n    uint64
	last time.Time
}

// Due folds one packet's timestamp in and reports whether Table.Tick(ts) should
// be called now. Call it exactly once per observed packet.
func (p *Pacer) Due(ts time.Time) bool {
	p.n++
	if p.n%TickEvery == 0 || (!p.last.IsZero() && ts.Sub(p.last) >= tickInterval) {
		p.last = ts
		return true
	}
	return false
}
