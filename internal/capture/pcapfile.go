package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Classic-pcap magic numbers. A file that starts with the pcapng Section Header
// Block type instead is handled by the minimal reader in pcapng.go.
const (
	magicMicroLE = 0xa1b2c3d4
	magicMicroBE = 0xd4c3b2a1
	magicNanoLE  = 0xa1b23c4d
	magicNanoBE  = 0x4d3cb2a1

	maxSnapLen = 262144 // refuse absurd per-record lengths from a crafted file
)

// ErrNotPCAP is returned when the file is neither a classic pcap nor a pcapng
// capture (both are read; see pcapng.go for the pcapng features that still need
// `editcap -F pcap` first).
var ErrNotPCAP = errors.New("capture: not a pcap file (need a classic pcap or pcapng capture)")

// PCAPFile is a Source that reads a classic .pcap or a minimal .pcapng file.
// streamStats stays first so its uint64s are 8-byte aligned for atomics on 386.
type PCAPFile struct {
	st   streamStats
	path string
	link packet.LinkType
}

// OpenPCAPFile opens path and validates its global header without reading packets.
func OpenPCAPFile(path string) (*PCAPFile, error) {
	f, err := os.Open(path) //nolint:gosec // the operator names the capture to replay
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	defer func() { _ = f.Close() }()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, ErrNotPCAP
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	if binary.BigEndian.Uint32(magic[:]) == ngBlockSHB {
		z, err := newPCAPNGReader(bufio.NewReaderSize(f, 1<<16))
		if err != nil {
			return nil, err
		}
		if err := z.primeInterfaces(); err != nil {
			return nil, err
		}
		return &PCAPFile{path: path, link: z.ifaces[0].link}, nil
	}

	var hdr [24]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, ErrNotPCAP
	}
	m := binary.LittleEndian.Uint32(hdr[0:4])
	var link uint32
	switch m {
	case magicMicroLE, magicNanoLE:
		link = binary.LittleEndian.Uint32(hdr[20:24])
	case magicMicroBE, magicNanoBE:
		link = binary.BigEndian.Uint32(hdr[20:24])
	default:
		return nil, ErrNotPCAP
	}
	lt := packet.LinkType(link)
	if lt != packet.LinkEthernet && lt != packet.LinkRaw {
		return nil, fmt.Errorf("capture: unsupported pcap link type %d (want %d ethernet or %d raw)", link, packet.LinkEthernet, packet.LinkRaw)
	}
	return &PCAPFile{path: path, link: lt}, nil
}

// LinkType reports the capture's link layer.
func (p *PCAPFile) LinkType() packet.LinkType { return p.link }

// Packets streams decoded packets from the file. The classic/pcapng decode is
// the shared decodePCAPStream engine (also used by the tcpdump/ssh subprocess
// sources), so Stats() semantics are identical across every pcap-stream input.
func (p *PCAPFile) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, 256)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		f, err := os.Open(p.path) //nolint:gosec // path was validated by OpenPCAPFile
		if err != nil {
			errc <- fmt.Errorf("capture: %w", err)
			return
		}
		defer func() { _ = f.Close() }()

		decodePCAPStream(ctx, bufio.NewReaderSize(f, 1<<16), out, errc, &p.st)
	}()

	return out, errc
}

// Stats returns a counter snapshot.
func (p *PCAPFile) Stats() Stats { return p.st.snapshot() }

// Close is a no-op; the file handle lives only for the duration of Packets.
func (p *PCAPFile) Close() error { return nil }
