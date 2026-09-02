// Package storagetest holds the contract every storage.Store implementation must
// satisfy, as one reusable test helper. internal/storage runs it against Mem;
// a durable backend (SQLite #53, ClickHouse #51) runs the same function against
// its own Store, so "passes the conformance suite" is a single, shared bar
// rather than a re-derivation per backend (EPIC Phase 8, #8).
package storagetest

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Factory builds a fresh, empty Store with the given ring capacities. A backend
// that is not ring-bounded may ignore the sizes, but must then skip or adapt the
// eviction case (see RunConformance).
type Factory func(flowCap, classCap int) storage.Store

// flowRec builds a distinguishable terminal FlowRecord for id.
func flowRec(id uint64, snap int, reason string, pkts uint64) storage.FlowRecord {
	return storage.FlowRecord{
		ID:            id,
		Proto:         "TCP",
		InitiatorIP:   "10.0.0.1",
		InitiatorPort: 1000 + uint16(id%1000),
		ResponderIP:   "10.0.0.2",
		ResponderPort: 443,
		FirstSeen:     time.Unix(1_700_000_000, 0).UTC(),
		LastSeen:      time.Unix(1_700_000_000, 0).Add(time.Duration(snap) * time.Minute).UTC(),
		FwdPackets:    pkts,
		CloseReason:   reason,
		SnapshotIndex: snap,
		Features:      features.Vector{FlowID: id, Schema: features.SchemaID},
	}
}

func classFor(id uint64, ts time.Time) storage.Classification {
	return storage.Classification{
		FlowID:      id,
		TS:          ts,
		Proto:       "TCP",
		InitiatorIP: "10.0.0.1",
		ResponderIP: "10.0.0.2",
		Result:      inference.Result{FlowID: id, Class: "normal", Score: 0.9},
	}
}

// RunConformance exercises the storage.Store contract against newStore. Call it
// from a Test* function in the backend's own package:
//
//	func TestMemConformance(t *testing.T) {
//	    storagetest.RunConformance(t, func(fc, cc int) storage.Store { return storage.NewMem(fc, cc) })
//	}
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()
	t.Run("FlowRoundTrip", func(t *testing.T) { testFlowRoundTrip(t, newStore) })
	t.Run("FlowHistoryOrdering", func(t *testing.T) { testFlowHistoryOrdering(t, newStore) })
	t.Run("FlowHistoryIsACopy", func(t *testing.T) { testFlowHistoryIsACopy(t, newStore) })
	t.Run("RecentNewestFirstAndLimit", func(t *testing.T) { testRecentNewestFirstAndLimit(t, newStore) })
	t.Run("EvictionCountersAndBound", func(t *testing.T) { testEvictionCountersAndBound(t, newStore) })
	t.Run("StatsDriverNamed", func(t *testing.T) { testStatsDriverNamed(t, newStore) })
	t.Run("CloseIsIdempotent", func(t *testing.T) { testCloseIsIdempotent(t, newStore) })
}

func testFlowRoundTrip(t *testing.T, newStore Factory) {
	s := newStore(16, 16)
	defer func() { _ = s.Close() }()

	if _, ok := s.Flow(42); ok {
		t.Fatal("Flow on an empty store returned ok=true")
	}
	s.PutFlow(flowRec(42, 0, "fin", 7))
	got, ok := s.Flow(42)
	if !ok {
		t.Fatal("Flow did not find a record that was just put")
	}
	if got.ID != 42 || got.FwdPackets != 7 || got.CloseReason != "fin" {
		t.Fatalf("round-tripped record differs: %+v", got)
	}
	if _, ok := s.Flow(43); ok {
		t.Fatal("Flow returned ok=true for an id that was never put")
	}
}

func testFlowHistoryOrdering(t *testing.T, newStore Factory) {
	s := newStore(64, 16)
	defer func() { _ = s.Close() }()

	if h := s.FlowHistory(9); h != nil {
		t.Fatalf("FlowHistory of an unknown flow = %v, want nil", h)
	}
	s.PutFlow(flowRec(9, 0, "snapshot", 1))
	s.PutFlow(flowRec(9, 1, "snapshot", 2))
	s.PutFlow(flowRec(9, 2, "fin", 3))

	h := s.FlowHistory(9)
	if len(h) != 3 {
		t.Fatalf("FlowHistory len = %d, want 3", len(h))
	}
	for i := range h {
		if h[i].SnapshotIndex != i {
			t.Fatalf("version %d out of order: SnapshotIndex=%d", i, h[i].SnapshotIndex)
		}
	}
	if h[2].CloseReason != "fin" {
		t.Fatalf("last version CloseReason = %q, want fin", h[2].CloseReason)
	}
	// Flow() returns the most recent version.
	if cur, _ := s.Flow(9); cur.SnapshotIndex != 2 {
		t.Fatalf("Flow returned version %d, want the newest (2)", cur.SnapshotIndex)
	}
}

func testFlowHistoryIsACopy(t *testing.T, newStore Factory) {
	s := newStore(64, 16)
	defer func() { _ = s.Close() }()

	s.PutFlow(flowRec(1, 0, "fin", 5))
	h := s.FlowHistory(1)
	h[0].FwdPackets = 999999
	h[0].CloseReason = "mutated"

	again := s.FlowHistory(1)
	if again[0].FwdPackets != 5 || again[0].CloseReason != "fin" {
		t.Fatalf("mutating a returned FlowHistory slice changed stored state: %+v", again[0])
	}
}

func testRecentNewestFirstAndLimit(t *testing.T, newStore Factory) {
	s := newStore(64, 64)
	defer func() { _ = s.Close() }()

	base := time.Unix(1_700_000_000, 0).UTC()
	for i := uint64(1); i <= 5; i++ {
		s.PutFlow(flowRec(i, 0, "fin", i))
		s.PutClassification(classFor(i, base.Add(time.Duration(i)*time.Second)))
	}

	rf := s.RecentFlows(3)
	if len(rf) != 3 || rf[0].ID != 5 || rf[2].ID != 3 {
		t.Fatalf("RecentFlows(3) = %v, want ids [5 4 3]", ids(rf))
	}
	if all := s.RecentFlows(0); len(all) != 5 {
		t.Fatalf("RecentFlows(0) returned %d, want all 5", len(all))
	}
	if all := s.RecentFlows(-1); len(all) != 5 {
		t.Fatalf("RecentFlows(-1) returned %d, want all 5", len(all))
	}
	if over := s.RecentFlows(100); len(over) != 5 {
		t.Fatalf("RecentFlows(100) returned %d, want 5 (not padded)", len(over))
	}

	rc := s.RecentClassifications(2)
	if len(rc) != 2 || rc[0].FlowID != 5 || rc[1].FlowID != 4 {
		t.Fatalf("RecentClassifications(2) flow ids = %v, want [5 4]", classIDs(rc))
	}
}

func testEvictionCountersAndBound(t *testing.T, newStore Factory) {
	const cap = 8
	s := newStore(cap, cap)
	defer func() { _ = s.Close() }()

	base := time.Unix(1_700_000_000, 0).UTC()
	for i := uint64(1); i <= cap*3; i++ {
		s.PutFlow(flowRec(i, 0, "fin", i))
		s.PutClassification(classFor(i, base.Add(time.Duration(i)*time.Second)))
	}

	st := s.Stats()
	if st.Flows > cap || st.Classifications > cap {
		t.Fatalf("store exceeded its capacity: flows=%d classifications=%d cap=%d", st.Flows, st.Classifications, cap)
	}
	if st.FlowsEvicted == 0 || st.ClassEvicted == 0 {
		t.Fatalf("no eviction counted after writing %d into a %d-slot store: %+v", cap*3, cap, st)
	}
	// The newest record must survive; the oldest must be gone.
	if _, ok := s.Flow(uint64(cap * 3)); !ok {
		t.Fatal("the most recent flow was evicted")
	}
	if _, ok := s.Flow(1); ok {
		t.Fatal("the oldest flow should have been evicted")
	}
	// RecentFlows is still newest-first and bounded.
	rf := s.RecentFlows(cap * 2)
	if len(rf) != cap || rf[0].ID != uint64(cap*3) {
		t.Fatalf("RecentFlows after eviction = %v, want %d ids newest-first", ids(rf), cap)
	}
}

func testStatsDriverNamed(t *testing.T, newStore Factory) {
	s := newStore(4, 4)
	defer func() { _ = s.Close() }()
	if s.Stats().Driver == "" {
		t.Fatal("Stats().Driver is empty; a backend must name itself")
	}
}

func testCloseIsIdempotent(t *testing.T, newStore Factory) {
	s := newStore(4, 4)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func ids(rs []storage.FlowRecord) []uint64 {
	out := make([]uint64, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}

func classIDs(cs []storage.Classification) []uint64 {
	out := make([]uint64, len(cs))
	for i, c := range cs {
		out[i] = c.FlowID
	}
	return out
}
