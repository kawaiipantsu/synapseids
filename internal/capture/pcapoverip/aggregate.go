package pcapoverip

import (
	"context"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Frame is one already-encoded record frame ready for the wire. The record modes
// produce these instead of raw packets, so the server loop writes them without
// knowing anything about flows or features.
type Frame struct {
	Type    FrameType
	Payload []byte
}

// FrameStreamFunc opens a fresh encoded-frame stream for one connected client,
// mirroring StreamFunc's contract: the server consumes the channels until the
// frame channel closes, the error channel yields a terminal error, or ctx is
// cancelled.
type FrameStreamFunc func(ctx context.Context) (<-chan Frame, <-chan error)

// AggregateConfig configures the sensor-side flow/feature aggregation stage.
type AggregateConfig struct {
	// Mode must be ModeFlow or ModeFeature.
	Mode Mode
	// LinkType is the libpcap DLT of the raw records, used to decode them.
	LinkType uint32
	// Flow is the flow-table lifecycle configuration. It should match the
	// daemon's so the same capture produces the same flows in every mode.
	Flow flow.Options
	// Logf, if set, receives one line per terminal condition. Never per packet.
	Logf func(string, ...any)
}

// Aggregate wraps a raw packet stream in the sensor-side flow engine and,
// for ModeFeature, feature extraction — reusing internal/flow and
// internal/features unchanged rather than reimplementing them (PROJECT.md §5.3).
//
// One goroutine per connection owns one flow.Table, which keeps the table's
// single-goroutine invariant intact (PROJECT.md §22, CLAUDE.md). Records are
// emitted as flows snapshot and close, and a final Flush at end of capture emits
// the still-open ones with reason capture_end — exactly what the daemon's own
// pipeline would have done with the same packets.
//
// Nothing about the raw frame survives this stage: in ModeFeature the packet
// bytes are decoded, folded into counters, reduced to the 48 flow-features-v1
// values and discarded. That is the mode's privacy property, and it is enforced
// here by construction — the encoder is never handed the frame.
func Aggregate(cfg AggregateConfig, raw StreamFunc) FrameStreamFunc {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	link := packet.LinkType(cfg.LinkType)

	return func(ctx context.Context) (<-chan Frame, <-chan error) {
		out := make(chan Frame, 64)
		errc := make(chan error, 1)

		go func() {
			defer close(out)
			defer close(errc)

			// stopped latches once ctx is cancelled or the consumer is gone, so a
			// record emitted from inside Table.Observe / Flush is dropped instead
			// of blocking the aggregation goroutine forever.
			stopped := false
			emit := func(f Frame) {
				if stopped {
					return
				}
				select {
				case out <- f:
				case <-ctx.Done():
					stopped = true
				}
			}

			var encoded, dropped uint64
			onFlow := func(r flow.Record) {
				var f Frame
				switch cfg.Mode {
				case ModeFlow:
					f = Frame{Type: FrameFlowRecord, Payload: EncodeFlowRecord(r)}
				case ModeFeature:
					fv := features.Extract(r)
					f = Frame{Type: FrameFeatureRecord, Payload: EncodeFeatureRecord(FeatureRecord{
						SensorFlowID:  r.ID,
						Proto:         r.Proto,
						Reason:        r.Reason,
						SnapshotIndex: r.SnapshotIndex,
						InitiatorIP:   r.InitiatorIP,
						InitiatorPort: r.InitiatorPort,
						ResponderIP:   r.ResponderIP,
						ResponderPort: r.ResponderPort,
						FirstSeen:     r.FirstSeen,
						LastSeen:      r.LastSeen,
						Values:        fv.Values,
					})}
				default:
					return
				}
				if len(f.Payload) > MaxFramePayload {
					dropped++ // cannot happen with the fixed layouts; counted, never fatal
					return
				}
				encoded++
				emit(f)
			}

			tbl := flow.NewTable(cfg.Flow, onFlow)
			var pacer flow.Pacer

			records, rerrc := raw(ctx)
			var termErr error
			var decodeErr uint64

		loop:
			for {
				select {
				case <-ctx.Done():
					stopped = true
					break loop
				case err := <-rerrc:
					if err != nil {
						termErr = err
						break loop
					}
				case rec, ok := <-records:
					if !ok {
						break loop
					}
					pk, derr := packet.Decode(link, rec.TS, rec.Raw)
					if derr != nil {
						decodeErr++ // malformed input is counted and skipped (§28.11)
						continue
					}
					tbl.Observe(pk)
					if pacer.Due(pk.TS) {
						tbl.Tick(pk.TS)
					}
				}
			}

			// Flush even on a terminal source error: the flows observed so far are
			// real measurements and the daemon should see them.
			tbl.Flush()

			st := tbl.Stats()
			logf("pcapoverip: %s-mode aggregation ended: %d record(s) encoded, %d flow(s) closed, %d snapshot(s), %d decode error(s), %d over-cap drop(s)",
				cfg.Mode, encoded, st.Closed, st.Snapshots, decodeErr, dropped)
			if termErr != nil {
				errc <- termErr
			}
		}()

		return out, errc
	}
}
