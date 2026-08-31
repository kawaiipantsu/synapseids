// Package pipeline wires the data plane together: packets from a capture.Source
// become flows, flows become flow-features-v1 vectors, vectors are scored by the
// inference runtime, and the results are stored and published as events. This is
// the single path both live capture and PCAP replay run through, so the UI
// behaves identically for each (PROJECT.md §6, §26).
package pipeline

import (
	"context"
	"log"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
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
	// OnStats, when non-nil, receives a snapshot of the flow-table counters on
	// the table's tick cadence (roughly once a second) and once more after the
	// final flush. It is never called per packet, so a supervisor can surface
	// flow-table size and eviction pressure without adding work to the packet
	// path (PROJECT.md §22, §24).
	OnStats func(flow.Stats)
}

// Stats summarizes a completed (or in-progress) run.
type Stats struct {
	Packets         uint64        `json:"packets"`
	Flows           uint64        `json:"flows"`
	Classifications uint64        `json:"classifications"`
	Snapshots       uint64        `json:"snapshots"`
	Evicted         uint64        `json:"flows_evicted"`
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

	// Feature vectors are handed to the runtime raw. Normalization is a
	// per-model concern: a trained model applies the normalizer.json from its
	// own bundle; the heuristic model reads raw values (PROJECT.md §11).
	onFlow := func(r flow.Record) {
		if r.Reason == flow.ReasonEvicted {
			evicted++
			if evicted == 1 || evicted%evictLogEvery == 0 {
				log.Printf("pipeline: flow table full at cap %d — evicted %d oldest-idle flow(s) this run; raise capture.max_flows / SYNAPSE_MAX_FLOWS if this persists (PROJECT.md §22)",
					opt.Flow.MaxFlows, evicted)
			}
		}

		fv := features.Extract(r)

		fr := storage.FlowRecordFrom(r, fv)
		store.PutFlow(fr)
		st.Flows++
		if r.Reason == flow.ReasonSnapshot {
			st.Snapshots++
			bus.Publish(events.FlowUpdated, fr)
		} else {
			bus.Publish(events.FlowClosed, fr)
		}
		bus.Publish(events.FeaturesGenerated, fv)

		res := rt.Score(fv)
		cl := storage.Classification{
			FlowID:        r.ID,
			TS:            r.LastSeen,
			Sensor:        opt.Sensor,
			Proto:         r.Proto.String(),
			InitiatorIP:   fr.InitiatorIP,
			InitiatorPort: r.InitiatorPort,
			ResponderIP:   fr.ResponderIP,
			ResponderPort: r.ResponderPort,
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

	fopt := opt.Flow
	if opt.IDGen != nil {
		fopt.IDGen = opt.IDGen
	}
	tbl := flow.NewTable(fopt, onFlow)

	pkts, errc := src.Packets(ctx)
	var lastTick time.Time
	const tickEvery = 512

	var termErr error
	var n uint64
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
		case p, ok := <-pkts:
			if !ok {
				break loop
			}
			n++
			st.Packets++
			tbl.Observe(p)
			if n%tickEvery == 0 || (!lastTick.IsZero() && p.TS.Sub(lastTick) >= time.Second) {
				tbl.Tick(p.TS)
				lastTick = p.TS
				if opt.OnStats != nil {
					opt.OnStats(tbl.Stats())
				}
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
