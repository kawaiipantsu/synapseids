package main

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// Issue #125: /api/v1/status read the replay controller's flow table, which on a
// sensor-fed daemon is a table that never ran — so the counters were zero while
// hundreds of flows were being built by the capture pipeline's table. The hub
// reports every table the daemon owns.
func TestFlowStatsHubReportsTheCapturePipeline(t *testing.T) {
	h := newFlowStatsHub(200000)

	// Nothing reported yet: zeroes and the configured cap, which is what an
	// API-only daemon should say.
	if got := h.FlowStats(); got.Active != 0 || got.Started != 0 || got.Max != 200000 {
		t.Fatalf("empty hub = %+v, want zeroes with max 200000", got)
	}

	// The capture pipeline — the one serving sensor packets — reports in.
	h.Reporter("capture")(flow.Stats{Active: 12, Started: 421, Closed: 409, Snapshots: 3, Evicted: 1})
	got := h.FlowStats()
	if got.Active != 12 || got.Started != 421 || got.Closed != 409 || got.Snapshots != 3 || got.Evicted != 1 {
		t.Fatalf("capture counters = %+v, want the reported snapshot", got)
	}
	if got.Max != 200000 {
		t.Errorf("max = %d, want the configured per-table cap", got.Max)
	}

	// A replay running alongside adds to the picture rather than replacing it.
	h.Reporter(replayStatsName)(flow.Stats{Active: 5, Started: 30, Closed: 25})
	got = h.FlowStats()
	if got.Active != 17 || got.Started != 451 || got.Closed != 434 {
		t.Fatalf("summed counters = %+v, want active 17 / started 451 / closed 434", got)
	}

	// A new replay builds a new table from zero; the finished run's totals must
	// not keep being added in.
	h.Reset(replayStatsName)
	got = h.FlowStats()
	if got.Active != 12 || got.Started != 421 {
		t.Fatalf("after reset = %+v, want only the capture pipeline's counters", got)
	}

	// The latest snapshot from one pipeline replaces its previous one — the
	// counters are cumulative in the table, not in the hub.
	h.Reporter("capture")(flow.Stats{Active: 0, Started: 500, Closed: 500})
	if got := h.FlowStats(); got.Started != 500 || got.Active != 0 {
		t.Fatalf("latest snapshot = %+v, want started 500 / active 0", got)
	}
}
