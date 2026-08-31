//go:build !linux

package capture

import (
	"context"
	"errors"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// errUnsupportedPlatform is returned by NewAFPacket off Linux. Every SynapseIDS
// release target is linux/* (PROJECT.md §27); this stub exists only so the tree
// builds and tests on a non-Linux developer machine.
var errUnsupportedPlatform = errors.New("afpacket: live NIC capture requires Linux (AF_PACKET)")

// AFPacket is the non-Linux placeholder. Its methods are unreachable in practice
// because NewAFPacket always fails here.
type AFPacket struct{}

// NewAFPacket always fails on non-Linux platforms.
func NewAFPacket(AFPacketConfig) (*AFPacket, error) { return nil, errUnsupportedPlatform }

// Packets returns an immediately-closed stream carrying errUnsupportedPlatform.
func (*AFPacket) Packets(context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet)
	errc := make(chan error, 1)
	errc <- errUnsupportedPlatform
	close(out)
	close(errc)
	return out, errc
}

// Stats returns a zero snapshot.
func (*AFPacket) Stats() Stats { return Stats{} }

// Close is a no-op.
func (*AFPacket) Close() error { return nil }
