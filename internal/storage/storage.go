// Package storage persists flows and classifications behind a small interface so
// the backend can change without touching the rest of the daemon. Phase 1 ships
// an in-memory ring buffer; SQLite and later ClickHouse are tracked separately
// (PROJECT.md §20).
package storage

import (
	"net/netip"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
)

// FlowRecord is a stored flow: its identity and accumulators plus the raw
// feature vector that was extracted from it.
type FlowRecord struct {
	ID            uint64          `json:"id"`
	Proto         string          `json:"proto"`
	InitiatorIP   string          `json:"initiator_ip"`
	InitiatorPort uint16          `json:"initiator_port"`
	ResponderIP   string          `json:"responder_ip"`
	ResponderPort uint16          `json:"responder_port"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	DurationSec   float64         `json:"duration_sec"`
	FwdPackets    uint64          `json:"fwd_packets"`
	BwdPackets    uint64          `json:"bwd_packets"`
	FwdBytes      uint64          `json:"fwd_bytes"`
	BwdBytes      uint64          `json:"bwd_bytes"`
	CloseReason   string          `json:"close_reason"`
	SnapshotIndex int             `json:"snapshot_index"`
	Features      features.Vector `json:"features"`

	// Sensor is the observation point this flow was built at: the id of the
	// sensor whose traffic produced it, or the daemon's own configured sensor
	// name ("local" by default) for traffic it captured itself.
	//
	// It always equals the Sensor on this flow's Classification — the pipeline
	// stamps both from the same resolved value — so `sensor=` selects the same
	// rows on /api/v1/flows as on /api/v1/classifications (issue #126).
	Sensor string `json:"sensor,omitempty"`
	// SensorMode records how this row reached the daemon: "" for a record built
	// locally from packets (the `raw` path, and every local capture), "flow" for a
	// remotely-aggregated flow record, "feature" for a record whose 48 values were
	// computed on the sensor and whose packet content never crossed the wire
	// (issue #45, PROJECT.md §5.3).
	//
	// It is provenance, not decoration: a `feature`-mode row carries no
	// packet-level detail beyond what flow-features-v1 encodes, and this field is
	// how a consumer knows that before reading the counters.
	SensorMode string `json:"sensor_mode,omitempty"`
	// SensorFlowID is the flow id the sensor assigned. The daemon remaps ID
	// through its own allocator so ids stay globally unique across its lifetime
	// (CLAUDE.md); this keeps the remote id for correlation with the sensor's own
	// logs. 0 for a locally-built record.
	SensorFlowID uint64 `json:"sensor_flow_id,omitempty"`
}

// Classification is a stored ensemble verdict for a flow, denormalized with just
// enough of the tuple to render the rolling log without a join.
type Classification struct {
	FlowID        uint64           `json:"flow_id"`
	TS            time.Time        `json:"ts"`
	Sensor        string           `json:"sensor"`
	Proto         string           `json:"proto"`
	InitiatorIP   string           `json:"initiator_ip"`
	InitiatorPort uint16           `json:"initiator_port"`
	ResponderIP   string           `json:"responder_ip"`
	ResponderPort uint16           `json:"responder_port"`
	Result        inference.Result `json:"result"`
}

// Stats is a persistence-layer counter snapshot.
type Stats struct {
	Flows           int    `json:"flows"`
	Classifications int    `json:"classifications"`
	FlowsEvicted    uint64 `json:"flows_evicted"`
	ClassEvicted    uint64 `json:"classifications_evicted"`
	// FlowVersionsDropped counts snapshot versions dropped because a single flow
	// exceeded FlowHistoryCap — a long-lived flow losing its *earliest*
	// snapshots while still retaining the most recent ones. Distinct from
	// FlowsEvicted, which is the global ring overwriting its oldest slot.
	FlowVersionsDropped uint64 `json:"flow_versions_dropped"`
	// Disagreements is the cumulative number of stored classifications whose
	// ensemble Result.Disagreement was set (PROJECT.md §12, §24: model
	// disagreement is an instrumented signal). It counts every disagreeing
	// verdict ever put, not just those still retained in the ring.
	Disagreements uint64 `json:"disagreements"`
	Driver        string `json:"driver"`
}

// Store is the persistence contract.
type Store interface {
	PutFlow(FlowRecord)
	PutClassification(Classification)
	Flow(id uint64) (FlowRecord, bool)
	// FlowHistory returns every retained version of one flow — the periodic
	// ReasonSnapshot records a long-lived flow emits as it runs, followed by its
	// terminal record — oldest first. It is how the Flow Inspector shows a
	// flow's counters and verdict evolving (PROJECT.md §19.3). A flow that never
	// snapshotted returns exactly one element; an unknown or fully evicted flow
	// returns nil.
	FlowHistory(id uint64) []FlowRecord
	RecentClassifications(limit int) []Classification
	RecentFlows(limit int) []FlowRecord
	Stats() Stats
	Close() error
}

// FlowRecordFrom builds a stored FlowRecord from a flow record and its features.
// Sensor comes from the record's observation scope (flow.Key.Sensor) and is "" for
// a record the daemon built from its own capture; the pipeline resolves that to
// the daemon's configured sensor name before storing.
func FlowRecordFrom(r flow.Record, fv features.Vector) FlowRecord {
	return FlowRecord{
		ID:            r.ID,
		Sensor:        r.Sensor(),
		Proto:         r.Proto.String(),
		InitiatorIP:   ipString(r.InitiatorIP),
		InitiatorPort: r.InitiatorPort,
		ResponderIP:   ipString(r.ResponderIP),
		ResponderPort: r.ResponderPort,
		FirstSeen:     r.FirstSeen,
		LastSeen:      r.LastSeen,
		DurationSec:   r.Duration().Seconds(),
		FwdPackets:    r.FwdPackets,
		BwdPackets:    r.BwdPackets,
		FwdBytes:      r.FwdBytes,
		BwdBytes:      r.BwdBytes,
		CloseReason:   string(r.Reason),
		SnapshotIndex: r.SnapshotIndex,
		Features:      fv,
	}
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
