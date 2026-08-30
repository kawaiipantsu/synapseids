package storage

import "testing"

func TestMemRingEvictsOldest(t *testing.T) {
	m := NewMem(3, 3)
	for i := uint64(1); i <= 5; i++ {
		m.PutFlow(FlowRecord{ID: i})
	}
	if s := m.Stats(); s.Flows != 3 || s.FlowsEvicted != 2 {
		t.Fatalf("stats after overflow: %+v", s)
	}
	recent := m.RecentFlows(10)
	if len(recent) != 3 || recent[0].ID != 5 || recent[2].ID != 3 {
		t.Fatalf("recent order wrong: %+v", recent)
	}
	if _, ok := m.Flow(1); ok {
		t.Fatalf("flow 1 should have been evicted")
	}
	if r, ok := m.Flow(5); !ok || r.ID != 5 {
		t.Fatalf("flow 5 missing")
	}
}

func TestMemClassificationsNewestFirst(t *testing.T) {
	m := NewMem(10, 10)
	for i := uint64(1); i <= 4; i++ {
		m.PutClassification(Classification{FlowID: i})
	}
	got := m.RecentClassifications(2)
	if len(got) != 2 || got[0].FlowID != 4 || got[1].FlowID != 3 {
		t.Fatalf("newest-first violated: %+v", got)
	}
}
