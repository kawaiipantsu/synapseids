package capture

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// fakeSource is a synthetic Source for Manager tests: it emits total packets
// (each tagged on SrcPort so a consumer can attribute them), optionally fails
// after errAfter packets, and reports live progress through Stats.
type fakeSource struct {
	total    int
	errAfter int // >0: send a terminal error on errc after this many packets
	delay    time.Duration
	tag      uint16

	emitted atomic.Uint64
	bytes   atomic.Uint64
	closed  atomic.Bool
}

func (f *fakeSource) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for i := 0; i < f.total; i++ {
			if f.errAfter > 0 && i == f.errAfter {
				errc <- fmt.Errorf("fakeSource %d: synthetic failure after %d packets", f.tag, i)
				return
			}
			if f.delay > 0 {
				select {
				case <-time.After(f.delay):
				case <-ctx.Done():
					errc <- ctx.Err()
					return
				}
			}
			pk := packet.Packet{TS: time.Unix(0, int64(i)), SrcPort: f.tag, TotalLen: 100}
			select {
			case out <- pk:
				f.emitted.Add(1)
				f.bytes.Add(100)
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()
	return out, errc
}

func (f *fakeSource) Stats() Stats {
	return Stats{Packets: f.emitted.Load(), Decoded: f.emitted.Load(), Bytes: f.bytes.Load()}
}

func (f *fakeSource) Close() error { f.closed.Store(true); return nil }

func mustAdd(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// waitForTimeout is generous on purpose: CI runs `make test` and `make race`
// back to back on one runner, so a tight deadline flakes (see issue #96).
const waitForTimeout = 5 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitForTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", what, waitForTimeout)
}

// TestManagerFanIn: N sources merge into one stream and every packet arrives once.
func TestManagerFanIn(t *testing.T) {
	m := newManager(64, 50*time.Millisecond)
	a := &fakeSource{total: 100, tag: 1}
	b := &fakeSource{total: 100, tag: 2}
	c := &fakeSource{total: 100, tag: 3}
	mustAdd(t, m.Add("a", a, SourceMeta{Kind: "nic"}))
	mustAdd(t, m.Add("b", b, SourceMeta{Kind: "nic"}))
	mustAdd(t, m.Add("c", c, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()

	perTag := map[uint16]int{}
	timeout := time.After(10 * time.Second)
	for total := 0; total < 300; total++ {
		select {
		case pk, ok := <-out:
			if !ok {
				t.Fatalf("stream closed after %d packets", total)
			}
			perTag[pk.SrcPort]++
		case <-timeout:
			t.Fatalf("only received %d/300 packets (per tag %v)", total, perTag)
		}
	}
	for tag := uint16(1); tag <= 3; tag++ {
		if perTag[tag] != 100 {
			t.Fatalf("source %d delivered %d/100 packets", tag, perTag[tag])
		}
	}
}

// TestManagerIsolatesErroringSource: a source that fails is marked "error" and
// the others keep flowing to completion.
func TestManagerIsolatesErroringSource(t *testing.T) {
	m := newManager(8, 30*time.Millisecond)
	bad := &fakeSource{total: 1000, errAfter: 50, tag: 1}
	good := &fakeSource{total: 200, tag: 2}
	mustAdd(t, m.Add("bad", bad, SourceMeta{Kind: "nic"}))
	mustAdd(t, m.Add("good", good, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()

	goodSeen := 0
	deadline := time.After(10 * time.Second)
	for goodSeen < 200 {
		select {
		case pk, ok := <-out:
			if !ok {
				t.Fatalf("stream closed early: good=%d", goodSeen)
			}
			if pk.SrcPort == 2 {
				goodSeen++
			}
		case <-deadline:
			t.Fatalf("good source stalled at %d/200 — a bad source killed the fan-in", goodSeen)
		}
	}

	// Keep draining while we wait for the state to settle. The bad source may
	// still have packets in flight, and a forwarder blocked in "m.out <- p" is
	// correct backpressure — it just cannot reach its error case until someone
	// reads. Stopping the reader here would deadlock that forwarder (issue #96).
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range out { //nolint:revive // intentional drain for the rest of the test
		}
	}()
	t.Cleanup(func() { <-drained })

	waitFor(t, "bad source in error state", func() bool {
		st, _ := m.Get("bad")
		return st.State == StateError && st.Error != ""
	})
	if st, _ := m.Get("good"); st.State == StateError {
		t.Fatalf("good source should not be in error state: %+v", st)
	}
}

// TestManagerComputesRates: PPS/BPS are sampled off the packet path and non-zero
// while a source is producing.
func TestManagerComputesRates(t *testing.T) {
	m := newManager(64, 20*time.Millisecond)
	s := &fakeSource{total: 1 << 20, delay: 150 * time.Microsecond, tag: 1}
	mustAdd(t, m.Add("s", s, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()
	go func() {
		for range out { //nolint:revive // background drain
		}
	}()

	waitFor(t, "non-zero pps/bps", func() bool {
		st, _ := m.Get("s")
		return st.PPS > 0 && st.BPS > 0
	})
}

// TestManagerListReflectsState: List/Get track the lifecycle from stopped →
// running → stopped and carry the descriptive metadata.
func TestManagerListReflectsState(t *testing.T) {
	m := newManager(64, 20*time.Millisecond)
	s := &fakeSource{total: 10, tag: 1}
	mustAdd(t, m.Add("s", s, SourceMeta{Kind: "nic", Filter: "(all)"}))

	if l := m.List(); len(l) != 1 || l[0].Name != "s" || l[0].State != StateStopped {
		t.Fatalf("pre-start list = %+v", l)
	}

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()
	for i := 0; i < 10; i++ {
		if _, ok := <-out; !ok {
			t.Fatalf("stream closed after %d packets", i)
		}
	}

	waitFor(t, "source stopped after exhaustion", func() bool {
		st, _ := m.Get("s")
		return st.State == StateStopped && st.Packets == 10
	})
	l := m.List()
	if len(l) != 1 || l[0].Kind != "nic" || l[0].Filter != "(all)" {
		t.Fatalf("list = %+v", l)
	}
}

// TestManagerDynamicAddAfterStart: a source added after Packets() is running
// has its forwarder spun up against the live merged stream; its packets arrive
// and the pre-existing source is undisturbed. This is the POST /api/v1/captures
// path (issue #32).
func TestManagerDynamicAddAfterStart(t *testing.T) {
	m := newManager(64, 20*time.Millisecond)
	a := &fakeSource{total: 400, delay: 100 * time.Microsecond, tag: 1}
	mustAdd(t, m.Add("a", a, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()

	perTag := map[uint16]int{}
	// Drain a few of A's packets so the manager is demonstrably running.
	for i := 0; i < 20; i++ {
		pk := <-out
		perTag[pk.SrcPort]++
	}

	b := &fakeSource{total: 150, tag: 2}
	mustAdd(t, m.Add("b", b, SourceMeta{Kind: "nic"}))

	deadline := time.After(10 * time.Second)
	for perTag[2] < 150 || perTag[1] < 400 {
		select {
		case pk, ok := <-out:
			if !ok {
				t.Fatalf("stream closed early: %v", perTag)
			}
			perTag[pk.SrcPort]++
		case <-deadline:
			t.Fatalf("did not see all packets: %v", perTag)
		}
	}
	if st, ok := m.Get("b"); !ok || st.Packets != 150 {
		t.Fatalf("runtime-added source status = %+v ok=%t", st, ok)
	}
}

// TestManagerRemoveStopsSourceAndGoroutine: Remove closes the source, joins its
// forwarder (no goroutine left behind) and drops the row, while a sibling source
// keeps flowing.
func TestManagerRemoveStopsSourceAndGoroutine(t *testing.T) {
	m := newManager(64, 20*time.Millisecond)
	keep := &fakeSource{total: 1 << 20, delay: 200 * time.Microsecond, tag: 1}
	drop := &fakeSource{total: 1 << 20, delay: 200 * time.Microsecond, tag: 2}
	mustAdd(t, m.Add("keep", keep, SourceMeta{Kind: "nic"}))
	mustAdd(t, m.Add("drop", drop, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()

	stop := make(chan struct{})
	keepSeen := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			case pk, ok := <-out:
				if !ok {
					return
				}
				if pk.SrcPort == 1 {
					select {
					case keepSeen <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	waitFor(t, "drop source running", func() bool {
		st, ok := m.Get("drop")
		return ok && st.State == StateRunning
	})

	base := runtime.NumGoroutine()
	if !m.Remove("drop") {
		t.Fatal("Remove(drop) returned false")
	}
	if _, ok := m.Get("drop"); ok {
		t.Fatal("drop still present after Remove")
	}
	if !drop.closed.Load() {
		t.Fatal("drop source not Closed by Remove")
	}
	// The forwarder goroutine is joined synchronously by Remove, so the count
	// must not have grown (a small slack absorbs unrelated scheduler churn).
	if n := runtime.NumGoroutine(); n > base+1 {
		t.Fatalf("goroutine count grew after Remove: base=%d now=%d", base, n)
	}

	// keep still delivers.
	<-keepSeen
	select {
	case keepSeen <- struct{}{}:
	default:
	}
	waitFor(t, "keep still flowing", func() bool {
		select {
		case <-keepSeen:
			return true
		default:
			return false
		}
	})
	close(stop)

	if st, ok := m.Get("keep"); !ok || st.State != StateRunning {
		t.Fatalf("keep source disturbed: %+v ok=%t", st, ok)
	}
}

// TestManagerDuplicateName is a guard on Add.
func TestManagerDuplicateName(t *testing.T) {
	m := NewManager()
	mustAdd(t, m.Add("x", &fakeSource{total: 1}, SourceMeta{Kind: "nic"}))
	if err := m.Add("x", &fakeSource{total: 1}, SourceMeta{Kind: "nic"}); err == nil {
		t.Fatal("expected a duplicate-name error")
	}
	if err := m.Add("", &fakeSource{total: 1}, SourceMeta{Kind: "nic"}); err == nil {
		t.Fatal("expected an empty-name error")
	}
}

// TestManagerAggregateStats sums per-source counters.
func TestManagerAggregateStats(t *testing.T) {
	m := newManager(64, 20*time.Millisecond)
	a := &fakeSource{total: 30, tag: 1}
	b := &fakeSource{total: 70, tag: 2}
	mustAdd(t, m.Add("a", a, SourceMeta{Kind: "nic"}))
	mustAdd(t, m.Add("b", b, SourceMeta{Kind: "nic"}))

	out, _ := m.Packets(context.Background())
	defer func() { _ = m.Close() }()
	for i := 0; i < 100; i++ {
		<-out
	}
	waitFor(t, "aggregate stats", func() bool {
		return m.Stats().Packets == 100
	})
}
