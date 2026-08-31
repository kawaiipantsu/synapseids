package storage

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

// ver builds a flow version: one PutFlow-able record for flow id at a snapshot
// index, with a close reason and distinguishable counters.
func ver(id uint64, snapIdx int, reason string, pkts uint64) FlowRecord {
	return FlowRecord{
		ID:            id,
		Proto:         "TCP",
		InitiatorIP:   "10.0.0.1",
		ResponderIP:   "10.0.0.2",
		LastSeen:      time.Unix(1700000000, 0).Add(time.Duration(snapIdx) * time.Minute),
		CloseReason:   reason,
		SnapshotIndex: snapIdx,
		FwdPackets:    pkts,
		Features:      features.Vector{FlowID: id, Schema: features.SchemaID},
	}
}

func TestFlowHistoryRetainsSnapshotsInOrder(t *testing.T) {
	m := NewMem(100, 100)

	// A long-lived flow: three periodic snapshots, then the terminal record.
	m.PutFlow(ver(7, 1, "snapshot", 10))
	m.PutFlow(ver(7, 2, "snapshot", 20))
	m.PutFlow(ver(7, 3, "snapshot", 30))
	m.PutFlow(ver(7, 3, "fin_rst", 42))

	h := m.FlowHistory(7)
	if len(h) != 4 {
		t.Fatalf("FlowHistory len = %d, want 4", len(h))
	}
	wantPkts := []uint64{10, 20, 30, 42}
	for i, want := range wantPkts {
		if h[i].FwdPackets != want {
			t.Errorf("version %d FwdPackets = %d, want %d (history out of order?)",
				i, h[i].FwdPackets, want)
		}
	}
	if h[3].CloseReason != "fin_rst" {
		t.Errorf("last version close reason = %q, want fin_rst", h[3].CloseReason)
	}

	// Flow() must still be the newest version.
	got, ok := m.Flow(7)
	if !ok {
		t.Fatal("Flow(7) not found")
	}
	if got.FwdPackets != 42 || got.CloseReason != "fin_rst" {
		t.Errorf("Flow(7) = %d pkts / %q, want 42 / fin_rst", got.FwdPackets, got.CloseReason)
	}
}

func TestFlowHistoryNoSnapshotsBehavesAsBefore(t *testing.T) {
	m := NewMem(100, 100)
	m.PutFlow(ver(3, 0, "fin_rst", 5))

	h := m.FlowHistory(3)
	if len(h) != 1 {
		t.Fatalf("FlowHistory len = %d, want 1", len(h))
	}
	if h[0].FwdPackets != 5 {
		t.Errorf("FwdPackets = %d, want 5", h[0].FwdPackets)
	}
	got, ok := m.Flow(3)
	if !ok || got.FwdPackets != 5 {
		t.Errorf("Flow(3) = %+v / %v, want the single record", got.FwdPackets, ok)
	}
	if n := m.Stats().FlowVersionsDropped; n != 0 {
		t.Errorf("FlowVersionsDropped = %d, want 0", n)
	}
}

func TestFlowHistoryUnknownFlow(t *testing.T) {
	m := NewMem(10, 10)
	if h := m.FlowHistory(999); h != nil {
		t.Errorf("FlowHistory(999) = %v, want nil", h)
	}
	if _, ok := m.Flow(999); ok {
		t.Error("Flow(999) reported found")
	}
}

func TestFlowHistoryPerFlowCapEvictsOldest(t *testing.T) {
	// A ring big enough that the global bound never fires, so only the per-flow
	// cap can drop anything.
	m := NewMem(FlowHistoryCap*4, 10)

	total := FlowHistoryCap + 10
	for i := 1; i <= total; i++ {
		m.PutFlow(ver(1, i, "snapshot", uint64(i)))
	}

	h := m.FlowHistory(1)
	if len(h) != FlowHistoryCap {
		t.Fatalf("FlowHistory len = %d, want the cap %d", len(h), FlowHistoryCap)
	}
	// The oldest were dropped, so the retained window is the newest cap versions.
	wantFirst := total - FlowHistoryCap + 1
	if h[0].SnapshotIndex != wantFirst {
		t.Errorf("oldest retained snapshot_index = %d, want %d", h[0].SnapshotIndex, wantFirst)
	}
	if h[len(h)-1].SnapshotIndex != total {
		t.Errorf("newest retained snapshot_index = %d, want %d", h[len(h)-1].SnapshotIndex, total)
	}
	// Strictly ascending, no duplicates or gaps in the retained window.
	for i := 1; i < len(h); i++ {
		if h[i].SnapshotIndex != h[i-1].SnapshotIndex+1 {
			t.Fatalf("retained window not contiguous at %d: %d then %d",
				i, h[i-1].SnapshotIndex, h[i].SnapshotIndex)
		}
	}
	if got, want := m.Stats().FlowVersionsDropped, uint64(10); got != want {
		t.Errorf("FlowVersionsDropped = %d, want %d", got, want)
	}
}

func TestFlowHistoryRingEvictionDropsOldestVersion(t *testing.T) {
	m := NewMem(3, 10)

	m.PutFlow(ver(1, 1, "snapshot", 10))
	m.PutFlow(ver(1, 2, "snapshot", 20))
	m.PutFlow(ver(1, 3, "fin_rst", 30))
	if len(m.FlowHistory(1)) != 3 {
		t.Fatalf("setup: history len = %d, want 3", len(m.FlowHistory(1)))
	}

	// A fourth record overwrites the ring's oldest slot, which held version 1.
	m.PutFlow(ver(2, 0, "fin_rst", 1))

	h := m.FlowHistory(1)
	if len(h) != 2 {
		t.Fatalf("history len after ring eviction = %d, want 2", len(h))
	}
	if h[0].SnapshotIndex != 2 {
		t.Errorf("oldest retained snapshot_index = %d, want 2", h[0].SnapshotIndex)
	}
	if got := m.Stats().FlowsEvicted; got != 1 {
		t.Errorf("FlowsEvicted = %d, want 1", got)
	}
	// The per-flow cap dropped nothing here — the ring did.
	if got := m.Stats().FlowVersionsDropped; got != 0 {
		t.Errorf("FlowVersionsDropped = %d, want 0", got)
	}
}

// TestFlowHistoryEvictionKeepsCurrentVersion is a regression test.
//
// flow.Table increments SnapshotIndex on the live entry, so a long flow's
// terminal record inherits the last snapshot's index. The previous byID
// bookkeeping identified a version by (flow id, SnapshotIndex) and therefore
// deleted the map entry for a flow whose *older* duplicate-index snapshot left
// the ring — making Flow(id) report "not found" for a flow whose terminal record
// was still retained, i.e. a spurious 404 from GET /api/v1/flows/{id}.
func TestFlowHistoryEvictionKeepsCurrentVersion(t *testing.T) {
	m := NewMem(2, 10)

	// Both versions carry snapshot index 3, as the flow engine really emits them.
	m.PutFlow(ver(1, 3, "snapshot", 30))
	m.PutFlow(ver(1, 3, "fin_rst", 44))

	// Evict the ring's oldest slot: the snapshot, not the terminal record.
	m.PutFlow(ver(2, 0, "fin_rst", 1))

	got, ok := m.Flow(1)
	if !ok {
		t.Fatal("Flow(1) not found — the terminal record is still in the ring")
	}
	if got.FwdPackets != 44 || got.CloseReason != "fin_rst" {
		t.Errorf("Flow(1) = %d pkts / %q, want the terminal 44 / fin_rst",
			got.FwdPackets, got.CloseReason)
	}
	if h := m.FlowHistory(1); len(h) != 1 || h[0].CloseReason != "fin_rst" {
		t.Errorf("FlowHistory(1) = %d versions, want just the terminal one", len(h))
	}
}

func TestFlowHistoryFullyEvictedFlowIsGone(t *testing.T) {
	m := NewMem(2, 10)
	m.PutFlow(ver(1, 0, "fin_rst", 1))
	m.PutFlow(ver(2, 0, "fin_rst", 2))
	m.PutFlow(ver(3, 0, "fin_rst", 3))
	m.PutFlow(ver(4, 0, "fin_rst", 4))

	if _, ok := m.Flow(1); ok {
		t.Error("Flow(1) still found after being pushed out of the ring")
	}
	if h := m.FlowHistory(1); h != nil {
		t.Errorf("FlowHistory(1) = %v, want nil", h)
	}
	// And the map did not leak the evicted ids.
	if n := len(m.hist); n != 2 {
		t.Errorf("history map holds %d flows, want 2 (ring capacity)", n)
	}
}

// TestFlowHistoryTotalVersionsBoundedByRing pins the memory argument: every
// retained version corresponds to exactly one live ring slot, so no mix of flows
// and snapshots can grow the history beyond the ring capacity.
func TestFlowHistoryTotalVersionsBoundedByRing(t *testing.T) {
	const cap = 8
	m := NewMem(cap, 10)

	for i := range 40 {
		// Three interleaved flows, each snapshotting repeatedly.
		id := uint64(i%3 + 1)
		m.PutFlow(ver(id, i, "snapshot", uint64(i)))
	}

	total := 0
	for id := uint64(1); id <= 3; id++ {
		total += len(m.FlowHistory(id))
	}
	if total > cap {
		t.Errorf("retained versions = %d, must not exceed ring capacity %d", total, cap)
	}
	if total != cap {
		t.Errorf("retained versions = %d, want the ring to be full at %d", total, cap)
	}
}

func TestFlowHistoryReturnedSliceIsACopy(t *testing.T) {
	m := NewMem(10, 10)
	m.PutFlow(ver(1, 1, "snapshot", 10))
	m.PutFlow(ver(1, 2, "fin_rst", 20))

	h := m.FlowHistory(1)
	h[0].FwdPackets = 99999

	again := m.FlowHistory(1)
	if again[0].FwdPackets != 10 {
		t.Errorf("mutating the returned slice changed the store: %d", again[0].FwdPackets)
	}
}
