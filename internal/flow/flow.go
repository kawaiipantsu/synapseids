// Package flow turns a stream of packets into bidirectional flow records keyed on
// a normalized 5-tuple. It owns flow lifetime: a flow closes on FIN/RST, an idle
// timeout, a maximum lifetime, or capture end, and long-lived flows emit periodic
// snapshots so classification does not wait forever (PROJECT.md §7).
package flow

import (
	"math"
	"net/netip"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Key is the direction-normalized 5-tuple that identifies a bidirectional flow.
// The lower (ip, port) endpoint is always stored first so both directions of a
// conversation map to the same Key.
type Key struct {
	A, B  netip.Addr
	PortA uint16
	PortB uint16
	Proto packet.Proto
}

// KeyOf normalizes a packet's endpoints into a Key and reports whether the packet
// travels from A to B (forwardFromA).
func KeyOf(p packet.Packet) (k Key, forwardFromA bool) {
	return KeyOfEndpoints(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Proto)
}

// KeyOfEndpoints normalizes one directed endpoint pair into a Key and reports
// whether (sa,pa) is the A side. It is the single place the normalization rule
// lives, so a Key rebuilt from a record's initiator/responder endpoints — for
// example a flow record received from a remote sensor — is byte-identical to the
// Key the local table would have derived from the same packets.
func KeyOfEndpoints(sa netip.Addr, pa uint16, sb netip.Addr, pb uint16, proto packet.Proto) (k Key, forwardFromA bool) {
	// Order by IP bytes, then port.
	less := false
	switch sa.Compare(sb) {
	case -1:
		less = true
	case 1:
		less = false
	default:
		less = pa <= pb
	}
	if less {
		return Key{A: sa, B: sb, PortA: pa, PortB: pb, Proto: proto}, true
	}
	return Key{A: sb, B: sa, PortA: pb, PortB: pa, Proto: proto}, false
}

// CloseReason explains why a flow record was emitted.
type CloseReason string

// Close reasons.
const (
	ReasonSnapshot CloseReason = "snapshot"
	ReasonFINRST   CloseReason = "fin_rst"
	ReasonIdle     CloseReason = "idle"
	ReasonMaxLife  CloseReason = "max_lifetime"
	ReasonCapEnd   CloseReason = "capture_end"
	ReasonEvicted  CloseReason = "evicted"
)

// Record is an immutable snapshot of a flow handed to feature extraction and
// storage. Rates are left to the feature layer; Record carries raw accumulators.
type Record struct {
	ID            uint64
	Key           Key
	Reason        CloseReason
	SnapshotIndex int

	InitiatorIP   netip.Addr
	InitiatorPort uint16
	ResponderIP   netip.Addr
	ResponderPort uint16
	Proto         packet.Proto

	FirstSeen time.Time
	LastSeen  time.Time

	FwdPackets, BwdPackets uint64
	FwdBytes, BwdBytes     uint64 // IP total length
	FwdPayload, BwdPayload uint64 // L4 payload length

	PktSizeMin, PktSizeMax   int
	pktSizeSum, pktSizeSumSq float64
	fwdSizeSum, bwdSizeSum   float64
	SmallPkts, LargePkts     uint64

	SynCount, AckCount, FinCount uint64
	RstCount, PshCount, UrgCount uint64

	InitialWindow uint32
	windowSum     float64
	windowCount   uint64

	// Inter-arrival accumulators (seconds).
	iatSum, iatSumSq         float64
	iatMin, iatMax           float64
	iatCount                 uint64
	fwdIATSum, bwdIATSum     float64
	fwdIATCount, bwdIATCount uint64
}

// Duration returns the wall-clock span of the flow.
func (r Record) Duration() time.Duration { return r.LastSeen.Sub(r.FirstSeen) }

// PktSizeMean returns the mean total packet size.
func (r Record) PktSizeMean() float64 {
	n := r.FwdPackets + r.BwdPackets
	if n == 0 {
		return 0
	}
	return r.pktSizeSum / float64(n)
}

// PktSizeStdDev returns the population standard deviation of packet size.
func (r Record) PktSizeStdDev() float64 {
	n := float64(r.FwdPackets + r.BwdPackets)
	if n < 2 {
		return 0
	}
	mean := r.pktSizeSum / n
	v := r.pktSizeSumSq/n - mean*mean
	if v < 0 {
		v = 0
	}
	return math.Sqrt(v)
}

// FwdSizeMean / BwdSizeMean return per-direction mean packet size.
func (r Record) FwdSizeMean() float64 {
	if r.FwdPackets == 0 {
		return 0
	}
	return r.fwdSizeSum / float64(r.FwdPackets)
}

// BwdSizeMean returns the mean backward packet size.
func (r Record) BwdSizeMean() float64 {
	if r.BwdPackets == 0 {
		return 0
	}
	return r.bwdSizeSum / float64(r.BwdPackets)
}

// AvgWindow returns the mean advertised TCP window.
func (r Record) AvgWindow() float64 {
	if r.windowCount == 0 {
		return 0
	}
	return r.windowSum / float64(r.windowCount)
}

// IATMean returns the mean inter-arrival gap in seconds.
func (r Record) IATMean() float64 {
	if r.iatCount == 0 {
		return 0
	}
	return r.iatSum / float64(r.iatCount)
}

// IATStdDev returns the population standard deviation of inter-arrival gaps.
func (r Record) IATStdDev() float64 {
	n := float64(r.iatCount)
	if n < 2 {
		return 0
	}
	mean := r.iatSum / n
	v := r.iatSumSq/n - mean*mean
	if v < 0 {
		v = 0
	}
	return math.Sqrt(v)
}

// IATMinS / IATMaxS return the extreme inter-arrival gaps in seconds.
func (r Record) IATMinS() float64 {
	if r.iatCount == 0 {
		return 0
	}
	return r.iatMin
}

// IATMaxS returns the largest inter-arrival gap in seconds.
func (r Record) IATMaxS() float64 { return r.iatMax }

// FwdIATMean / BwdIATMean return per-direction mean inter-arrival gaps.
func (r Record) FwdIATMean() float64 {
	if r.fwdIATCount == 0 {
		return 0
	}
	return r.fwdIATSum / float64(r.fwdIATCount)
}

// BwdIATMean returns the mean backward inter-arrival gap in seconds.
func (r Record) BwdIATMean() float64 {
	if r.bwdIATCount == 0 {
		return 0
	}
	return r.bwdIATSum / float64(r.bwdIATCount)
}
