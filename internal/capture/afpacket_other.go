//go:build !linux

package capture

import (
	"context"
	"fmt"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// errAFPacketUnsupported is returned by NewAFPacket off Linux. All four
// SynapseIDS release targets are linux/* (PROJECT.md §27); FreeBSD hosts use
// the /dev/bpf source instead (bpf_freebsd.go), and this stub exists so the
// tree builds and tests on any other developer machine.
var errAFPacketUnsupported = fmt.Errorf("afpacket: live NIC capture requires Linux (AF_PACKET); "+
	"FreeBSD hosts use /dev/bpf: %w", errUnsupportedPlatform)

// AFPacket is the non-Linux placeholder. Its methods are unreachable in practice
// because NewAFPacket always fails here.
type AFPacket struct{}

// NewAFPacket always fails on non-Linux platforms.
func NewAFPacket(AFPacketConfig) (*AFPacket, error) { return nil, errAFPacketUnsupported }

// LinkType reports Ethernet; the value is never used because the socket cannot
// be opened.
func (*AFPacket) LinkType() packet.LinkType { return packet.LinkEthernet }

// Packets returns an immediately-closed stream carrying errAFPacketUnsupported.
func (*AFPacket) Packets(context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet)
	errc := make(chan error, 1)
	errc <- errAFPacketUnsupported
	close(out)
	close(errc)
	return out, errc
}

// RawPackets returns an immediately-closed stream carrying
// errAFPacketUnsupported.
func (*AFPacket) RawPackets(context.Context) (<-chan RawFrame, <-chan error) {
	out := make(chan RawFrame)
	errc := make(chan error, 1)
	errc <- errAFPacketUnsupported
	close(out)
	close(errc)
	return out, errc
}

// Stats returns a zero snapshot.
func (*AFPacket) Stats() Stats { return Stats{} }

// Close is a no-op.
func (*AFPacket) Close() error { return nil }
