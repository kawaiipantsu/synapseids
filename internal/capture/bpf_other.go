//go:build !freebsd

package capture

import (
	"context"
	"fmt"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// errBPFUnsupported explains that /dev/bpf is a BSD interface. Linux hosts use
// AF_PACKET instead (afpacket_linux.go); this stub exists so the tree builds
// and tests everywhere, and so the chunk parser and ioctl derivation in
// bpfchunk.go / bpfioctl.go stay unit-tested on the Linux CI machine.
var errBPFUnsupported = fmt.Errorf("bpf: /dev/bpf capture requires FreeBSD (Linux hosts use AF_PACKET): %w",
	errUnsupportedPlatform)

// BPFDevice is the non-FreeBSD placeholder. Its methods are unreachable in
// practice because NewBPFDevice always fails here.
type BPFDevice struct{}

// NewBPFDevice always fails on non-FreeBSD platforms.
func NewBPFDevice(BPFConfig) (*BPFDevice, error) { return nil, errBPFUnsupported }

// LinkType reports Ethernet; the value is never used because the device cannot
// be opened.
func (*BPFDevice) LinkType() packet.LinkType { return packet.LinkEthernet }

// Device returns an empty path.
func (*BPFDevice) Device() string { return "" }

// BufferLen returns 0; the device cannot be opened here.
func (*BPFDevice) BufferLen() int { return 0 }

// BufferLenRequested returns 0; the device cannot be opened here.
func (*BPFDevice) BufferLenRequested() int { return 0 }

// Packets returns an immediately-closed stream carrying errBPFUnsupported.
func (*BPFDevice) Packets(context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet)
	errc := make(chan error, 1)
	errc <- errBPFUnsupported
	close(out)
	close(errc)
	return out, errc
}

// RawPackets returns an immediately-closed stream carrying errBPFUnsupported.
func (*BPFDevice) RawPackets(context.Context) (<-chan RawFrame, <-chan error) {
	out := make(chan RawFrame)
	errc := make(chan error, 1)
	errc <- errBPFUnsupported
	close(out)
	close(errc)
	return out, errc
}

// Stats returns a zero snapshot.
func (*BPFDevice) Stats() Stats { return Stats{} }

// Close is a no-op.
func (*BPFDevice) Close() error { return nil }
