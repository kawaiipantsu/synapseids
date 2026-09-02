package capture

import (
	"context"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// This file is the platform-neutral front door to live NIC capture. There are
// two kernel interfaces behind it — AF_PACKET on Linux and /dev/bpf on
// FreeBSD — and callers that only want "capture on this interface" should ask
// for NewLive rather than picking one (PROJECT.md §6 "Local network
// interface"). Callers that specifically want AF_PACKET or BPF semantics still
// construct NewAFPacket / NewBPFDevice directly; internal/capturewire does,
// because its config kinds are explicit.

// RawFrame is one captured link-layer frame that has *not* been decoded. It
// exists for the sensor path: synapse-sensor forwards records to a remote
// synapsed over SYNPOIP, which does its own packet.Decode at the far end
// (PROJECT.md §5.3, internal/capture/pcapoverip/PROTOCOL.md §3.1). Data is
// owned by the receiver — the producer copies it out of its read buffer.
type RawFrame struct {
	TS   time.Time
	Data []byte
}

// LiveSource is a Source backed by a kernel capture interface on a local NIC.
// Beyond Source it can report the link type it negotiated and stream raw,
// undecoded frames. Exactly one of Packets and RawPackets may be started on a
// given instance: both drive the same single read loop and the same fd.
type LiveSource interface {
	Source

	// LinkType is the libpcap DLT the interface delivers.
	LinkType() packet.LinkType

	// RawPackets streams undecoded link-layer frames.
	RawPackets(ctx context.Context) (<-chan RawFrame, <-chan error)
}

// LiveConfig configures a live NIC capture, in terms every platform shares.
// Fields a platform cannot honour are rejected at construction rather than
// silently ignored.
type LiveConfig struct {
	// Interface is the local NIC name. Required.
	Interface string

	// Promiscuous puts the interface into promiscuous mode. On Linux this
	// needs CAP_NET_ADMIN; on FreeBSD it is BIOCPROMISC on an already-open
	// device.
	Promiscuous bool

	// Snaplen bounds how many bytes of each frame are captured. 0 means
	// DefaultSnaplen.
	Snaplen int

	// Filter names a built-in cBPF preset (see BuiltinFilters); "" captures
	// everything.
	Filter string

	// Direction selects received-only ("in"), transmitted-only ("out") or both
	// ("" / "inout"). FreeBSD implements it with BIOCSDIRECTION; Linux
	// AF_PACKET has no equivalent and rejects anything but the default.
	Direction string

	// Device names an explicit capture device. FreeBSD only ("/dev/bpf7");
	// Linux rejects a non-empty value.
	Device string

	// BufferLen is the FreeBSD BPF store-buffer request in bytes (BIOCSBLEN).
	// 0 means the default. The kernel clamps it to net.bpf.maxbufsize and the
	// granted size is logged at open (issue #128). Linux rejects a non-zero
	// value: AF_PACKET's ring is sized differently and is not this knob.
	BufferLen int

	// Ring opts the Linux AF_PACKET source into the TPACKET_V3 mmap RX ring
	// (issue #163). Off by default (PROJECT.md §22/§26). FreeBSD rejects a
	// true value: /dev/bpf has its own store buffer (BufferLen).
	Ring bool

	// Logf, when set, receives the open-time buffer report (requested vs
	// granted, and the sysctl remedy when the kernel clamped it). FreeBSD only;
	// nil discards it.
	Logf func(string, ...any)
}
