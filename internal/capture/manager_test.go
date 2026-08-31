package capture

import (
	"context"
	"fmt"
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

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", what, d)
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

	waitFor(t, 5*time.Second, "bad source in error state", func() bool {
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

	waitFor(t, 5*time.Second, "non-zero pps/bps", func() bool {
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

	waitFor(t, 5*time.Second, "source stopped after exhaustion", func() bool {
		st, _ := m.Get("s")
		return st.State == StateStopped && st.Packets == 10
	})
	l := m.List()
	if len(l) != 1 || l[0].Kind != "nic" || l[0].Filter != "(all)" {
		t.Fatalf("list = %+v", l)
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
	waitFor(t, 5*time.Second, "aggregate stats", func() bool {
		return m.Stats().Packets == 100
	})
}
