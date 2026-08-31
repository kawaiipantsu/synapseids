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

	// Seed the clock on the first packet.
	//
	// Without this the capture-time arm below was guarded by !p.last.IsZero()
	// and p.last was only ever set when the COUNT arm fired — so a source that
	// never reached TickEvery packets never ticked at all. Table.Tick is what
	// expires flows on idle and max-lifetime and emits snapshots, so on a quiet
	// link flows were never closed, never classified, and nothing reached
	// storage, the event bus or the detection feed. A sensor on a low-traffic
	// segment looked healthy while producing no output whatsoever (issue #137).
	// File replay hid it because capture-end flushes everything.
	if p.last.IsZero() {
		p.last = ts
		return false
	}

	// A capture whose timestamps go backwards (a re-ordered merge, a clock step
	// on the sensor) must not park the clock in the future and stop ticking:
	// re-seed instead of letting the comparison stay negative forever.
	if ts.Before(p.last) {
		p.last = ts
		return false
	}

	if p.n%TickEvery == 0 || ts.Sub(p.last) >= tickInterval {
		p.last = ts
		return true
	}
	return false
}
