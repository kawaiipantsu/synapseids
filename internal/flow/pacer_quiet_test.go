package flow

import (
	"testing"
	"time"
)

// A quiet link must still tick.
//
// Pacer.Due used to seed p.last only when the COUNT arm fired, while the
// capture-time arm was guarded by !p.last.IsZero(). Below TickEvery packets
// neither arm could ever fire, so Table.Tick was never called: flows were never
// expired, never classified, and nothing reached storage or the detection feed.
// A sensor on a low-traffic segment reported healthy and produced nothing
// (issue #137).
func TestPacerTicksOnAQuietLinkBelowTickEvery(t *testing.T) {
	var p Pacer
	base := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)

	// Ten packets, one every two seconds: far below TickEvery, far above
	// tickInterval. The first seeds the clock; every later one is overdue.
	ticks := 0
	for i := 0; i < 10; i++ {
		if p.Due(base.Add(time.Duration(i) * 2 * time.Second)) {
			ticks++
		}
	}
	if ticks == 0 {
		t.Fatalf("no ticks in 10 packets spanning 18s — expiry is dead below %d packets", TickEvery)
	}
	if want := 9; ticks != want {
		t.Errorf("ticks = %d, want %d (one per packet after the seeding packet)", ticks, want)
	}
}

// The first packet seeds without ticking: there is nothing to expire yet, and a
// tick on packet one would fire before any flow exists.
func TestPacerFirstPacketSeedsWithoutTicking(t *testing.T) {
	var p Pacer
	if p.Due(time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)) {
		t.Error("the first packet caused a tick; it should only seed the clock")
	}
}

// A packet burst inside one tickInterval must still tick on the count arm, so a
// busy link does not defer expiry indefinitely.
func TestPacerStillTicksOnCountDuringABurst(t *testing.T) {
	var p Pacer
	ts := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	ticks := 0
	for i := 0; i < TickEvery+1; i++ {
		if p.Due(ts) { // identical timestamps: the capture clock never advances
			ticks++
		}
	}
	if ticks == 0 {
		t.Errorf("no tick in %d packets at a standstill clock — the count arm is dead", TickEvery+1)
	}
}

// Backwards timestamps must not park the clock in the future and silence the
// capture-time arm for the rest of the run.
func TestPacerRecoversFromBackwardsTimestamps(t *testing.T) {
	var p Pacer
	base := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	p.Due(base)                 // seed
	p.Due(base.Add(-time.Hour)) // a clock step backwards
	if !p.Due(base.Add(-time.Hour + 2*time.Second)) {
		t.Error("no tick after a backwards step; the capture-time arm stayed dead")
	}
}
