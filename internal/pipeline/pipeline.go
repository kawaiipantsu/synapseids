// Package pipeline wires the data plane together: packets from a capture.Source
// become flows, flows become flow-features-v1 vectors, vectors are scored by the
// inference runtime, and the results are stored and published as events. This is
// the single path both live capture and PCAP replay run through, so the UI
// behaves identically for each (PROJECT.md §6, §26).
package pipeline

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// evictLogEvery throttles the flow-table eviction warning: it is logged on the
// first eviction of a run and then once per this many evictions, so sustained
// packet-path pressure stays visible without flooding the log (PROJECT.md §24).
const evictLogEvery = 1000

// Observer receives every classified flow record. It exists so read models that
// are not the system of record — the host/timeline aggregates behind
// Investigation mode (PROJECT.md §19.4-6) — can be fed from the one place that
// has both the record and its verdict, without the pipeline importing them.
//
// An implementation MUST NOT block, allocate heavily or take a lock a reader can
// hold: it is called from the packet-processing goroutine (PROJECT.md §22).
// internal/insight satisfies it with a single non-blocking channel send. The
// arguments are only valid for the duration of the call.
type Observer interface {
	Observe(fr *storage.FlowRecord, cl *storage.Classification)
}

// Options configure a pipeline run.
type Options struct {
	Flow   flow.Options
	Sensor string
	// Observer, when non-nil, is handed every flow record and its verdict. See
	// Observer for the contract it must honour.
	Observer Observer
	// IDGen, when set, allocates globally-unique flow IDs so records from
	// different runs never collide (the daemon shares one allocator).
	IDGen func() uint64
	// Records, when non-nil, is the second input to this pipeline: flow and
	// feature records from remote sensors running in `flow` / `feature` mode
	// (issue #45, PROJECT.md §5.3).
	//
	// They are drained by the *same* goroutine that drains the packet channel, so
	// the single-goroutine flow.Table invariant holds and nothing new has to be
	// made concurrency-safe (PROJECT.md §22, CLAUDE.md). A record enters the data
	// plane further along than a packet does: a flow record skips the flow table,
	// a feature record skips the flow table and feature extraction too.
	Records <-chan pcapoverip.SensorRecord
	// OnStats, when non-nil, receives a snapshot of the flow-table counters on
	// the table's tick cadence (roughly once a second) and once more after the
	// final flush. It is never called per packet, so a supervisor can surface
	// flow-table size and eviction pressure without adding work to the packet
	// path (PROJECT.md §22, §24).
	OnStats func(flow.Stats)
}

// Stats summarizes a completed (or in-progress) run.
type Stats struct {
	Packets         uint64 `json:"packets"`
	Flows           uint64 `json:"flows"`
	Classifications uint64 `json:"classifications"`
	Snapshots       uint64 `json:"snapshots"`
	Evicted         uint64 `json:"flows_evicted"`
	// FlowRecords and FeatureRecords count records that entered downstream of the
	// packet path, from `flow`- and `feature`-mode sensors respectively.
	FlowRecords    uint64 `json:"sensor_flow_records"`
	FeatureRecords uint64 `json:"sensor_feature_records"`
	// RecordsRejected counts records dropped before classification: an unknown
	// schema, or a record whose mode does not match its payload. Counted and
	// skipped, never fatal (PROJECT.md §28.11).
	RecordsRejected uint64        `json:"sensor_records_rejected"`
	Elapsed         time.Duration `json:"-"`
	ElapsedMS       int64         `json:"elapsed_ms"`
}

// Run consumes src to completion (or until ctx is cancelled), feeding every
// resulting flow through features -> inference -> storage/events. It returns the
// terminal error from the source, if any.
func Run(
	ctx context.Context,
	src capture.Source,
	rt *inference.Runtime,
	bus *events.Bus,
	store storage.Store,
	opt Options,
) (Stats, error) {
	var st Stats
	start := time.Now()

	// evicted counts oldest-idle evictions seen this run; it drives the
	// throttled capacity warning below.
	var evicted uint64

	// publish is the tail of the data plane, shared by every way a record can get
	// here: store it, announce it, score it, store and announce the verdict.
	//
	// Feature vectors are handed to the runtime raw. Normalization is a per-model
	// concern: a trained model applies the normalizer.json from its own bundle;
	// the heuristic model reads raw values (PROJECT.md §11).
	publish := func(fr storage.FlowRecord, sensor string) {
		store.PutFlow(fr)
		st.Flows++
		if fr.CloseReason == string(flow.ReasonSnapshot) {
			st.Snapshots++
			bus.Publish(events.FlowUpdated, fr)
		} else {
			bus.Publish(events.FlowClosed, fr)
		}
		bus.Publish(events.FeaturesGenerated, fr.Features)

		res := rt.Score(fr.Features)
		cl := storage.Classification{
			FlowID:        fr.ID,
			TS:            fr.LastSeen,
			Sensor:        sensor,
			Proto:         fr.Proto,
			InitiatorIP:   fr.InitiatorIP,
			InitiatorPort: fr.InitiatorPort,
			ResponderIP:   fr.ResponderIP,
			ResponderPort: fr.ResponderPort,
			Result:        res,
		}
		store.PutClassification(cl)
		st.Classifications++
		bus.Publish(events.ClassificationCreated, cl)
		if res.Disagreement {
			bus.Publish(events.ModelDisagreementDetected, cl)
		}
		if opt.Observer != nil {
			opt.Observer.Observe(&fr, &cl)
		}
	}

	onFlow := func(r flow.Record) {
		if r.Reason == flow.ReasonEvicted {
			evicted++
			if evicted == 1 || evicted%evictLogEvery == 0 {
				log.Printf("pipeline: flow table full at cap %d — evicted %d oldest-idle flow(s) this run; raise capture.max_flows / SYNAPSE_MAX_FLOWS if this persists (PROJECT.md §22)",
					opt.Flow.MaxFlows, evicted)
			}
		}
		publish(storage.FlowRecordFrom(r, features.Extract(r)), opt.Sensor)
	}

	fopt := opt.Flow
	if opt.IDGen != nil {
		fopt.IDGen = opt.IDGen
	}
	tbl := flow.NewTable(fopt, onFlow)

	// nextID mints a daemon-local flow id for a remote record. A sensor's ids are
	// its own counter and would collide across sensors and restarts, so every
	// arriving record is remapped and the original kept as provenance (CLAUDE.md:
	// flow ids must be globally unique across the daemon's lifetime).
	nextID := opt.IDGen
	if nextID == nil {
		var local uint64
		nextID = func() uint64 { local++; return local }
	}

	onRecord := func(rec pcapoverip.SensorRecord) {
		sensor := rec.Sensor
		if sensor == "" {
			sensor = opt.Sensor
		}
		switch {
		case rec.Flow != nil:
			// `flow` mode joins here: the sensor already ran the flow engine, so
			// the daemon must NOT re-run its table over this record. Extract
			// features from it and classify.
			r := *rec.Flow
			sensorFlowID := r.ID
			r.ID = nextID()
			fr := storage.FlowRecordFrom(r, features.Extract(r))
			fr.SensorMode = pcapoverip.ModeFlow.String()
			fr.SensorFlowID = sensorFlowID
			st.FlowRecords++
			publish(fr, sensor)

		case rec.Feature != nil:
			// `feature` mode joins here: flow aggregation *and* feature extraction
			// already happened on the sensor. The daemon only classifies and
			// stores. Nothing about the packets is available, or claimed.
			fv := rec.Feature
			id := nextID()
			c := fv.Vector(id).Counts()
			fr := storage.FlowRecord{
				ID:            id,
				Proto:         fv.Proto.String(),
				InitiatorIP:   ipText(fv.InitiatorIP),
				InitiatorPort: fv.InitiatorPort,
				ResponderIP:   ipText(fv.ResponderIP),
				ResponderPort: fv.ResponderPort,
				FirstSeen:     fv.FirstSeen,
				LastSeen:      fv.LastSeen,
				DurationSec:   c.DurationSec,
				FwdPackets:    c.FwdPackets,
				BwdPackets:    c.BwdPackets,
				FwdBytes:      c.FwdBytes,
				BwdBytes:      c.BwdBytes,
				CloseReason:   string(fv.Reason),
				SnapshotIndex: fv.SnapshotIndex,
				Features:      fv.Vector(id),
				SensorMode:    pcapoverip.ModeFeature.String(),
				SensorFlowID:  fv.SensorFlowID,
			}
			st.FeatureRecords++
			publish(fr, sensor)

		default:
			st.RecordsRejected++
		}
	}

	pkts, errc := src.Packets(ctx)
	// The tick cadence is flow.Pacer's, not the pipeline's, so a flow-mode sensor
	// running its own Table expires flows at exactly the same points (issue #45).
	var pacer flow.Pacer

	var termErr error
loop:
	for {
		select {
		case <-ctx.Done():
			termErr = ctx.Err()
			break loop
		case err := <-errc:
			if err != nil {
				termErr = err
				break loop
			}
		case rec, ok := <-opt.Records:
			// A nil Records channel blocks forever, which is exactly the right
			// behaviour for a select arm that should never fire.
			if !ok {
				// The record input closed. Keep draining packets: a collector
				// shutting down must not stop local capture.
				opt.Records = nil
				continue
			}
			onRecord(rec)
		case p, ok := <-pkts:
			if !ok {
				break loop
			}
			st.Packets++
			tbl.Observe(p)
			if pacer.Due(p.TS) {
				tbl.Tick(p.TS)
				if opt.OnStats != nil {
					opt.OnStats(tbl.Stats())
				}
			}
		}
	}

	// A record already accepted from a sensor is a measurement, not a queue
	// entry to discard: drain whatever is buffered before shutting down. The
	// default arm bounds the loop, so a collector still producing cannot hold
	// shutdown open.
	if opt.Records != nil {
	drain:
		for {
			select {
			case rec, ok := <-opt.Records:
				if !ok {
					break drain
				}
				onRecord(rec)
			default:
				break drain
			}
		}
	}

	tbl.Flush()
	ts := tbl.Stats()
	st.Evicted = ts.Evicted
	if opt.OnStats != nil {
		opt.OnStats(ts)
	}
	st.Elapsed = time.Since(start)
	st.ElapsedMS = st.Elapsed.Milliseconds()
	return st, termErr
}

// ipText renders an address for a stored record, matching what
// storage.FlowRecordFrom does for a locally-built one.
func ipText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
