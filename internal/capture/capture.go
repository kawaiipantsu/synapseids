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
