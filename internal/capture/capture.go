// Package capture turns a traffic source — a PCAP file today, a live NIC or a
// remote sensor later — into a stream of decoded packets. Every transport is an
// adapter behind the Source interface; nothing downstream knows which one it is
// (PROJECT.md §2.10, §6).
package capture

import (
	"context"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Stats is a point-in-time counter snapshot for a Source.
type Stats struct {
	Packets   uint64
	Decoded   uint64
	DecodeErr uint64
	Bytes     uint64
	LastTS    time.Time
	// Drops counts packets the kernel discarded before this process could read
	// them (AF_PACKET PACKET_STATISTICS tp_drops). It is a live-capture concern:
	// file-backed sources leave it 0 (PROJECT.md §22, §24).
	Drops uint64

	// Records and RecordBytes belong to a `flow`- or `feature`-mode sensor
	// (issue #45): the number of flow / feature records received and the encoded
	// payload bytes they arrived as.
	//
	// They are deliberately *separate* counters rather than a reinterpretation of
	// Packets and Bytes. A record-mode sensor ships no frames at all, so Packets,
	// Bytes and the rates derived from them stay 0 — that is the truth, not a
	// missing measurement, and SourceStatus.Mode says why.
	Records     uint64
	RecordBytes uint64
}

// Source is a packet producer. Packets runs until the context is cancelled or the
// source is exhausted, then closes the channel. Errors that do not stop the
// stream (a single malformed frame) are counted in Stats, not sent on the error
// channel; the error channel carries the terminal error, if any.
type Source interface {
	Packets(ctx context.Context) (<-chan packet.Packet, <-chan error)
	Stats() Stats
	Close() error
}
