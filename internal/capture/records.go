package capture

import (
	"context"
	"sync/atomic"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
)

// recordRoute is the daemon-side destination for SYNPOIP v2 record frames. Both
// postures — the dialled PCAPOverIP source and a collector-accepted
// sessionSource — embed one, so a `flow`/`feature` sensor is handled the same way
// whichever end opened the socket (issue #45).
//
// A nil channel means this daemon cannot receive records; such a source offers
// only SYNPOIP v1 in its ClientHello, which makes a flow/feature sensor answer
// with a clean RejectMode instead of streaming into a void.
type recordRoute struct {
	ch       chan<- pcapoverip.SensorRecord
	mode     pcapoverip.Mode
	sensor   string
	location string
}

// wantsRecords reports whether this route can accept 0x04 / 0x05 frames, which
// is what drives the max_version capability the source advertises.
func (r recordRoute) wantsRecords() bool { return r.ch != nil }

// helloCeiling is the max_version to advertise: v2 when the daemon has somewhere
// to put records, v1 otherwise.
func (r recordRoute) helloCeiling() uint16 {
	if r.wantsRecords() {
		return pcapoverip.VersionMax
	}
	return pcapoverip.Version1
}

// recordCounters are the per-source record-mode counters, kept beside the packet
// counters rather than folded into them (see Stats).
type recordCounters struct {
	records     uint64
	recordBytes uint64
	decodeErr   uint64
}

// deliver decodes one record frame and forwards it. It returns gone=true when
// the consumer is finished, which the read loop treats as a clean stream end. A
// malformed record increments decodeErr and is skipped — never fatal, never a
// panic (PROJECT.md §28.11).
//
// The send blocks (bounded by ctx) rather than dropping: a flow record is one
// per flow, not one per packet, and stalling the TLS read applies TCP
// backpressure to the sensor, which is the right way to shed load here.
func (r recordRoute) deliver(ctx context.Context, c *recordCounters,
	ft pcapoverip.FrameType, payload []byte) (gone bool) {

	rec := pcapoverip.SensorRecord{
		Sensor: r.sensor, Location: r.location, Mode: r.mode, WireBytes: len(payload),
	}

	switch ft {
	case pcapoverip.FrameFlowRecord:
		if r.mode != pcapoverip.ModeFlow {
			atomic.AddUint64(&c.decodeErr, 1)
			return false
		}
		fr, err := pcapoverip.DecodeFlowRecord(payload)
		if err != nil {
			atomic.AddUint64(&c.decodeErr, 1)
			return false
		}
		rec.Flow = &fr

	case pcapoverip.FrameFeatureRecord:
		if r.mode != pcapoverip.ModeFeature {
			atomic.AddUint64(&c.decodeErr, 1)
			return false
		}
		fv, err := pcapoverip.DecodeFeatureRecord(payload)
		if err != nil {
			atomic.AddUint64(&c.decodeErr, 1)
			return false
		}
		rec.Feature = &fv

	default:
		return false
	}

	atomic.AddUint64(&c.records, 1)
	atomic.AddUint64(&c.recordBytes, uint64(len(payload)))
	select {
	case r.ch <- rec:
		return false
	case <-ctx.Done():
		return true
	}
}

func (c *recordCounters) snapshot(st Stats) Stats {
	st.Records = atomic.LoadUint64(&c.records)
	st.RecordBytes = atomic.LoadUint64(&c.recordBytes)
	st.DecodeErr += atomic.LoadUint64(&c.decodeErr)
	return st
}
