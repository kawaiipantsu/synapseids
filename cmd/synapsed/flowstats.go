package main

import (
	"sort"
	"sync"

	"github.com/kawaiipantsu/synapseids/internal/api"
	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// flowStatsHub collects the flow-table counters of every pipeline the daemon
// runs and reports their sum on /api/v1/status.
//
// The daemon runs two pipelines — one draining the merged capture stream (live
// NICs, and every `raw`-mode SYNPOIP sensor) and one for PCAP replay — and each
// owns its own flow.Table. Reading only the replay controller's table was
// issue #125: a sensor-fed daemon classified hundreds of flows while
// /api/v1/status reported `{"active":0,"started":0,...}`, because the table
// doing the work was the other one. Summing them is the honest answer to
// "what is the daemon's flow state", and it is the only view that stays correct
// when a replay runs alongside live capture.
//
// Every write arrives from a pipeline's OnStats hook, which fires on the flow
// table's tick cadence (~1/s) and once more after the final flush — never per
// packet, so /api/v1/status costs the packet path nothing (PROJECT.md §22, §24).
type flowStatsHub struct {
	// max is the configured per-table cap (capture.max_flows). It is reported as
	// given rather than multiplied by the number of tables: it is the limit each
	// table enforces, and inventing a total nobody enforces would be worse than
	// stating the one that is real.
	max int

	mu     sync.Mutex
	tables map[string]flow.Stats
}

func newFlowStatsHub(max int) *flowStatsHub {
	return &flowStatsHub{max: max, tables: map[string]flow.Stats{}}
}

// Reporter returns the OnStats hook for the named pipeline. Passing it to
// pipeline.Options.OnStats is the whole of the wiring.
func (h *flowStatsHub) Reporter(name string) func(flow.Stats) {
	return func(s flow.Stats) {
		h.mu.Lock()
		h.tables[name] = s
		h.mu.Unlock()
	}
}

// Reset drops a pipeline's counters, for a table that is about to be rebuilt
// from scratch (a new replay run). Without it the finished run's totals would
// keep being added to the live ones.
func (h *flowStatsHub) Reset(name string) {
	h.mu.Lock()
	delete(h.tables, name)
	h.mu.Unlock()
}

// FlowStats sums every known table, satisfying api.FlowStatsProvider.
func (h *flowStatsHub) FlowStats() api.FlowStats {
	h.mu.Lock()
	names := make([]string, 0, len(h.tables))
	for n := range h.tables {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic accumulation order
	out := api.FlowStats{Max: h.max}
	for _, n := range names {
		s := h.tables[n]
		out.Active += s.Active
		out.Started += s.Started
		out.Closed += s.Closed
		out.Snapshots += s.Snapshots
		out.Evicted += s.Evicted
	}
	h.mu.Unlock()
	return out
}
