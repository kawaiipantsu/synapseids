package storage

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

func flowAt(id uint64, last time.Time) FlowRecord {
	return FlowRecord{ID: id, FirstSeen: last.Add(-time.Second), LastSeen: last, Features: features.Vector{}}
}

func clsAt(id uint64, ts time.Time) Classification {
	return Classification{FlowID: id, TS: ts}
}

func TestPurgeBeforeDropsOldFlowsKeepsRecent(t *testing.T) {
	m := NewMem(50, 50)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		m.PutFlow(flowAt(uint64(i+1), now.Add(-time.Duration(i)*time.Hour))) // i hours old
	}
	// Keep only the last 4 hours.
	flows, cls := m.PurgeBefore(now.Add(-4*time.Hour), time.Time{})
	if cls != 0 {
		t.Errorf("classifications purged = %d, want 0 (zero cutoff)", cls)
	}
	if flows != 5 { // 5h..9h old
		t.Fatalf("flows purged = %d, want 5", flows)
	}
	got := m.RecentFlows(0)
	if len(got) != 5 {
		t.Fatalf("retained %d flows, want 5", len(got))
	}
	for _, f := range got {
		if f.LastSeen.Before(now.Add(-4 * time.Hour)) {
			t.Errorf("kept a flow older than the window: %s", f.LastSeen)
		}
	}
	if st := m.Stats(); st.FlowsExpired != 5 || st.Flows != 5 {
		t.Errorf("stats after purge = %+v, want FlowsExpired 5 / Flows 5", st)
	}
	// History for a purged flow is gone; for a kept flow it is intact.
	if _, ok := m.Flow(10); ok {
		t.Error("flow 10 (9h old) still resolvable after purge")
	}
	if _, ok := m.Flow(1); !ok {
		t.Error("flow 1 (fresh) lost after purge")
	}
}

func TestPurgeBeforeKeepsRecentSnapshotsOfALongFlow(t *testing.T) {
	m := NewMem(50, 50)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	// One flow, five snapshot versions spanning 5 hours.
	for i := 4; i >= 0; i-- {
		m.PutFlow(flowAt(7, now.Add(-time.Duration(i)*time.Hour)))
	}
	flows, _ := m.PurgeBefore(now.Add(-2*time.Hour-30*time.Minute), time.Time{})
	if flows != 2 { // the 3h and 4h versions
		t.Fatalf("purged %d versions, want 2", flows)
	}
	hist := m.FlowHistory(7)
	if len(hist) != 3 {
		t.Fatalf("history len = %d, want 3 (0h, 1h, 2h versions)", len(hist))
	}
	if hist[0].LastSeen.Before(now.Add(-2*time.Hour - 30*time.Minute)) {
		t.Errorf("oldest retained version %s is before the window", hist[0].LastSeen)
	}
}

func TestPurgeBeforeDropsOldClassifications(t *testing.T) {
	m := NewMem(50, 50)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	// Stored in time order, the way a running daemon writes them.
	for i := 7; i >= 0; i-- {
		m.PutClassification(clsAt(uint64(i+1), now.Add(-time.Duration(i)*time.Hour)))
	}
	// TS at exactly the cutoff is kept (Before is strict), so 4h..7h old go.
	_, cls := m.PurgeBefore(time.Time{}, now.Add(-3*time.Hour))
	if cls != 4 {
		t.Fatalf("classifications purged = %d, want 4", cls)
	}
	got := m.RecentClassifications(0)
	if len(got) != 4 {
		t.Fatalf("retained %d, want 4", len(got))
	}
	// Newest-first order preserved.
	for i := 1; i < len(got); i++ {
		if !got[i-1].TS.After(got[i].TS) {
			t.Errorf("order not newest-first after compaction at %d", i)
		}
	}
	if m.Stats().ClassExpired != 4 {
		t.Errorf("ClassExpired = %d, want 4", m.Stats().ClassExpired)
	}
}

func TestPurgeBeforeNoOpWhenNothingOld(t *testing.T) {
	m := NewMem(10, 10)
	now := time.Now()
	m.PutFlow(flowAt(1, now))
	m.PutClassification(clsAt(1, now))
	f, c := m.PurgeBefore(now.Add(-time.Hour), now.Add(-time.Hour))
	if f != 0 || c != 0 {
		t.Errorf("purged %d/%d, want 0/0", f, c)
	}
	if m.Stats().Flows != 1 || m.Stats().Classifications != 1 {
		t.Error("a no-op purge changed the retained counts")
	}
}

// After a purge the ring must still accept new records and evict in order.
func TestPurgeThenPutStillEvictsOldestFirst(t *testing.T) {
	m := NewMem(4, 4)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	m.PutFlow(flowAt(1, now.Add(-10*time.Hour)))
	m.PutFlow(flowAt(2, now.Add(-1*time.Hour)))
	m.PutFlow(flowAt(3, now.Add(-30*time.Minute)))
	m.PurgeBefore(now.Add(-2*time.Hour), time.Time{}) // drops flow 1
	m.PutFlow(flowAt(4, now))
	m.PutFlow(flowAt(5, now))
	m.PutFlow(flowAt(6, now)) // ring cap 4: 2,3,4,5,6 -> evict 2
	ids := map[uint64]bool{}
	for _, f := range m.RecentFlows(0) {
		ids[f.ID] = true
	}
	if ids[2] {
		t.Errorf("flow 2 should have been evicted after the ring refilled: %v", ids)
	}
	if !ids[3] || !ids[6] {
		t.Errorf("expected 3..6 retained, got %v", ids)
	}
}
