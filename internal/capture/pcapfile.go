package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

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
type PCAPFile struct {
	path   string
	link   packet.LinkType
	pcapng bool
	stats  struct {
		packets, decoded, decodeErr, bytes uint64
		lastUnixNano                       int64
	}
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
		return &PCAPFile{path: path, link: z.ifaces[0].link, pcapng: true}, nil
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

// Packets streams decoded packets from the file.
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

		r := bufio.NewReaderSize(f, 1<<16)

		if p.pcapng {
			p.streamPCAPNG(ctx, r, out, errc)
			return
		}

		var g [24]byte
		if _, err := io.ReadFull(r, g[:]); err != nil {
			errc <- ErrNotPCAP
			return
		}
		magic := binary.LittleEndian.Uint32(g[0:4])
		var bo binary.ByteOrder = binary.LittleEndian
		nano := false
		switch magic {
		case magicMicroLE:
		case magicNanoLE:
			nano = true
		case magicMicroBE:
			bo = binary.BigEndian
		case magicNanoBE:
			bo, nano = binary.BigEndian, true
		default:
			errc <- ErrNotPCAP
			return
		}

		var rec [16]byte
		buf := make([]byte, 0, 2048)
		for {
			if ctx.Err() != nil {
				errc <- ctx.Err()
				return
			}
			if _, err := io.ReadFull(r, rec[:]); err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					return // clean end of capture
				}
				errc <- fmt.Errorf("capture: reading record header: %w", err)
				return
			}
			tsSec := bo.Uint32(rec[0:4])
			tsFrac := bo.Uint32(rec[4:8])
			inclLen := bo.Uint32(rec[8:12])
			if inclLen == 0 || inclLen > maxSnapLen {
				errc <- fmt.Errorf("capture: record length %d out of range", inclLen)
				return
			}
			if cap(buf) < int(inclLen) {
				buf = make([]byte, inclLen)
			}
			buf = buf[:inclLen]
			if _, err := io.ReadFull(r, buf); err != nil {
				errc <- fmt.Errorf("capture: short packet body: %w", err)
				return
			}
			atomic.AddUint64(&p.stats.packets, 1)
			atomic.AddUint64(&p.stats.bytes, uint64(inclLen))

			nsec := int64(tsFrac) * 1000
			if nano {
				nsec = int64(tsFrac)
			}
			ts := time.Unix(int64(tsSec), nsec).UTC()
			atomic.StoreInt64(&p.stats.lastUnixNano, ts.UnixNano())

			pk, derr := packet.Decode(p.link, ts, buf)
			if derr != nil {
				atomic.AddUint64(&p.stats.decodeErr, 1)
				continue
			}
			atomic.AddUint64(&p.stats.decoded, 1)
			select {
			case out <- pk:
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()

	return out, errc
}

// streamPCAPNG drives the pcapng reader, feeding the same counters and channels
// as the classic path so Stats() semantics are identical.
func (p *PCAPFile) streamPCAPNG(ctx context.Context, r *bufio.Reader, out chan<- packet.Packet, errc chan<- error) {
	z, err := newPCAPNGReader(r)
	if err != nil {
		errc <- err
		return
	}
	for {
		if ctx.Err() != nil {
			errc <- ctx.Err()
			return
		}
		rec, ok, err := z.next()
		if err != nil {
			errc <- err
			return
		}
		if !ok {
			return // clean end of section
		}
		atomic.AddUint64(&p.stats.packets, 1)
		atomic.AddUint64(&p.stats.bytes, uint64(len(rec.data)))
		if !rec.ts.IsZero() {
			atomic.StoreInt64(&p.stats.lastUnixNano, rec.ts.UnixNano())
		}

		pk, derr := packet.Decode(rec.link, rec.ts, rec.data)
		if derr != nil {
			atomic.AddUint64(&p.stats.decodeErr, 1)
			continue
		}
		atomic.AddUint64(&p.stats.decoded, 1)
		select {
		case out <- pk:
		case <-ctx.Done():
			errc <- ctx.Err()
			return
		}
	}
}

// Stats returns a counter snapshot.
func (p *PCAPFile) Stats() Stats {
	last := atomic.LoadInt64(&p.stats.lastUnixNano)
	var lt time.Time
	if last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return Stats{
		Packets:   atomic.LoadUint64(&p.stats.packets),
		Decoded:   atomic.LoadUint64(&p.stats.decoded),
		DecodeErr: atomic.LoadUint64(&p.stats.decodeErr),
		Bytes:     atomic.LoadUint64(&p.stats.bytes),
		LastTS:    lt,
	}
}

// Close is a no-op; the file handle lives only for the duration of Packets.
func (p *PCAPFile) Close() error { return nil }
