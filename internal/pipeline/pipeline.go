// Package pipeline wires the data plane together: packets from a capture.Source
// become flows, flows become flow-features-v1 vectors, vectors are scored by the
// inference runtime, and the results are stored and published as events. This is
// the single path both live capture and PCAP replay run through, so the UI
// behaves identically for each (PROJECT.md §6, §26).
package pipeline

import (
	"context"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Options configure a pipeline run.
type Options struct {
	Flow   flow.Options
	Sensor string
	// IDGen, when set, allocates globally-unique flow IDs so records from
	// different runs never collide (the daemon shares one allocator).
	IDGen func() uint64
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

	// Feature vectors are handed to the runtime raw. Normalization is a
	// per-model concern: a trained model applies the normalizer.json from its
	// own bundle; the heuristic model reads raw values (PROJECT.md §11).
	onFlow := func(r flow.Record) {
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
			}
		}
	}

	tbl.Flush()
	ts := tbl.Stats()
	st.Evicted = ts.Evicted
	st.Elapsed = time.Since(start)
	st.ElapsedMS = st.Elapsed.Milliseconds()
	return st, termErr
}
