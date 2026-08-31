package capture

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func TestParseSpeed(t *testing.T) {
	cases := map[string]Speed{"": 1, "1": 1, "1x": 1, "0.5": 0.5, "2": 2, "10": 10, "max": SpeedMax, "0": SpeedMax}
	for in, want := range cases {
		got, err := ParseSpeed(in)
		if err != nil || got != want {
			t.Errorf("ParseSpeed(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSpeed("fast"); err == nil {
		t.Errorf("ParseSpeed(\"fast\") should error")
	}
	if _, err := ParseSpeed("-2"); err == nil {
		t.Errorf("negative speed should error")
	}
}

func TestSpeedString(t *testing.T) {
	if SpeedMax.String() != "max" || Speed(2).String() != "2x" {
		t.Fatalf("Speed.String: %q %q", SpeedMax, Speed(2))
	}
}

// countingSource is a synthetic Source that emits n packets. Packet i is stamped
// TS = time.Unix(0, i) so a consumer can assert exact ordering by index. buf
// sizes the delivery channel: buf == 0 hands packets over one at a time; a large
// buf lets the source run ahead so its reader never has to park waiting on it,
// which is what the SpeedMax scheduler test wants.
type countingSource struct {
	n     int
	buf   int
	stats Stats
}

func (s *countingSource) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, s.buf)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for i := 0; i < s.n; i++ {
			select {
			case out <- packet.Packet{TS: time.Unix(0, int64(i))}:
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()
	return out, errc
}

func (s *countingSource) Stats() Stats { return s.stats }
func (s *countingSource) Close() error { return nil }

// TestSpeedMaxDeliversAllInOrder is the correctness guard: with the cooperative
// yield in place, SpeedMax must still deliver every packet exactly once, in
// order.
func TestSpeedMaxDeliversAllInOrder(t *testing.T) {
	const n = 5000
	out, errc := NewReplay(&countingSource{n: n}, SpeedMax).Packets(context.Background())

	got := 0
	for pk := range out {
		if want := int64(got); pk.TS.UnixNano() != want {
			t.Fatalf("packet %d arrived out of order: TS=%d, want %d", got, pk.TS.UnixNano(), want)
		}
		got++
	}
	if err := <-errc; err != nil {
		t.Fatalf("replay reported error: %v", err)
	}
	if got != n {
		t.Fatalf("received %d packets, want %d", got, n)
	}
}

// TestSpeedMaxYieldsScheduler is the regression guard for issue #71: at
// --speed max the emit loop has no timer to block on, so without the cooperative
// runtime.Gosched() every yieldEvery packets it can dominate a single-P
// scheduler and stall unrelated goroutines (the HTTP API handler in production).
//
// With GOMAXPROCS pinned to 1, a bystander goroutine ticks a counter in a tight
// loop while the replay producer and a fast consumer trade a few thousand
// packets. The consumer does no per-packet work, so a mid-run window of packets
// drains in far less than the ~10ms async-preemption backstop: if the replay
// never yields the P by hand, the bystander cannot advance during that window
// and the test fails. The deadline is generous so a slow box only makes the
// test slower, not flaky.
func TestSpeedMaxYieldsScheduler(t *testing.T) {
	// Pin the scheduler to a single P to model a 1-CPU host; restore on exit.
	// Process-global state, so this test must not run in parallel.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	const (
		n        = 4000
		windowLo = 500  // start measuring once the replay is well under way
		windowHi = 1500 // ... and stop before it drains
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := &countingSource{n: n, buf: n} // whole capture queued ahead of the reader
	out, errc := NewReplay(src, SpeedMax).Packets(ctx)

	// Bystander: ticks a counter in a tight loop, no yield of its own, so the
	// only thing that can advance it is another goroutine handing back the P.
	// It is stopped as soon as the measurement window closes so it does not
	// slow the rest of the drain.
	var ticks int64
	bctx, stopBystander := context.WithCancel(context.Background())
	var bwg sync.WaitGroup
	bwg.Add(1)
	go func() {
		defer bwg.Done()
		for bctx.Err() == nil {
			atomic.AddInt64(&ticks, 1)
		}
	}()
	defer bwg.Wait()
	defer stopBystander()

	// Generous watchdog: if the replay stalls, cancel it so the range unblocks
	// and the assertions report a clear failure instead of a test timeout.
	watchdog := time.AfterFunc(20*time.Second, cancel)
	defer watchdog.Stop()

	// Drain the replay as fast as possible and measure how far the bystander
	// gets across a mid-run window.
	var base, mid int64
	next := 0
	for pk := range out {
		if want := int64(next); pk.TS.UnixNano() != want {
			t.Fatalf("packet %d arrived out of order: TS=%d, want %d", next, pk.TS.UnixNano(), want)
		}
		next++
		switch next {
		case windowLo:
			base = atomic.LoadInt64(&ticks)
		case windowHi:
			mid = atomic.LoadInt64(&ticks)
			stopBystander()
		}
	}

	if err := <-errc; err != nil {
		t.Fatalf("replay reported error (watchdog fired?): %v", err)
	}
	if next != n {
		t.Fatalf("received %d/%d packets — SpeedMax replay stalled", next, n)
	}
	t.Logf("bystander ticks across packets %d..%d: %d", windowLo, windowHi, mid-base)
	if mid-base <= 0 {
		t.Fatalf("bystander goroutine got no CPU while replay produced packets %d..%d — "+
			"SpeedMax is not yielding the P (issue #71)", windowLo, windowHi)
	}
}
