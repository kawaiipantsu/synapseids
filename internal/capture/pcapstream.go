package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// streamStats is the shared counter block every pcap-byte-stream source keeps:
// PCAPFile (a file), TcpdumpStream and SSHTcpdump (a subprocess), and later
// PCAP-over-IP. Its uint64s come first so the block is 8-byte aligned for the
// atomic ops on 386/arm; embed it as the first field of the owning struct.
type streamStats struct {
	packets      uint64
	decoded      uint64
	decodeErr    uint64
	bytes        uint64
	lastUnixNano int64
}

// countPacket records one record lifted off the wire (before decode).
func (s *streamStats) countPacket(n uint64, ts time.Time) {
	atomic.AddUint64(&s.packets, 1)
	atomic.AddUint64(&s.bytes, n)
	if !ts.IsZero() {
		atomic.StoreInt64(&s.lastUnixNano, ts.UnixNano())
	}
}

func (s *streamStats) countDecoded()   { atomic.AddUint64(&s.decoded, 1) }
func (s *streamStats) countDecodeErr() { atomic.AddUint64(&s.decodeErr, 1) }

// snapshot converts the counters into a Stats value. Drops stays 0: a
// file-backed source has none, and a tcpdump/ssh subprocess only learns its
// kernel-drop count from a stderr line at teardown (see ADR 0011).
func (s *streamStats) snapshot() Stats {
	var lt time.Time
	if last := atomic.LoadInt64(&s.lastUnixNano); last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return Stats{
		Packets:   atomic.LoadUint64(&s.packets),
		Decoded:   atomic.LoadUint64(&s.decoded),
		DecodeErr: atomic.LoadUint64(&s.decodeErr),
		Bytes:     atomic.LoadUint64(&s.bytes),
		LastTS:    lt,
	}
}

// decodePCAPStream is the shared pcap-byte-stream engine. It reads the global
// header from r, sniffs classic pcap (µs/ns, LE/BE) or pcapng (0x0A0D0D0A),
// decodes every record with packet.Decode, folds the counts into st, and sends
// each decoded packet on out. It returns when r is exhausted (clean end), when
// ctx is cancelled, or on a malformed stream; a terminal error is sent on errc,
// and a clean EOF sends nothing. A single malformed frame is counted in st,
// never sent on errc (§28.11).
//
// PCAPFile.Packets, TcpdumpStream and SSHTcpdump all drive their byte stream
// through here so Stats() semantics and decode behaviour stay identical.
func decodePCAPStream(ctx context.Context, r io.Reader, out chan<- packet.Packet, errc chan<- error, st *streamStats) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 1<<16)
	}

	magic, err := br.Peek(4)
	if err != nil {
		errc <- ErrNotPCAP
		return
	}
	// 0x0A0D0D0A is byte-order independent, so a big-endian read is safe.
	if binary.BigEndian.Uint32(magic) == ngBlockSHB {
		streamPCAPNGRecords(ctx, br, out, errc, st)
		return
	}
	decodeClassicPCAPStream(ctx, br, out, errc, st)
}

// decodeClassicPCAPStream handles a classic .pcap byte stream: the 24-byte
// global header, then a sequence of 16-byte record headers each followed by its
// packet bytes. Lifted from the old PCAPFile.Packets loop so the file path is
// byte-for-byte unchanged.
func decodeClassicPCAPStream(ctx context.Context, r *bufio.Reader, out chan<- packet.Packet, errc chan<- error, st *streamStats) {
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

	link := bo.Uint32(g[20:24])
	lt := packet.LinkType(link)
	if lt != packet.LinkEthernet && lt != packet.LinkRaw {
		errc <- fmt.Errorf("capture: unsupported pcap link type %d (want %d ethernet or %d raw)", link, packet.LinkEthernet, packet.LinkRaw)
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
				return // clean end of stream
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

		nsec := int64(tsFrac) * 1000
		if nano {
			nsec = int64(tsFrac)
		}
		ts := time.Unix(int64(tsSec), nsec).UTC()
		st.countPacket(uint64(inclLen), ts)

		pk, derr := packet.Decode(lt, ts, buf)
		if derr != nil {
			st.countDecodeErr()
			continue
		}
		st.countDecoded()
		select {
		case out <- pk:
		case <-ctx.Done():
			errc <- ctx.Err()
			return
		}
	}
}

// streamPCAPNGRecords drives the minimal pcapng reader over an already-open
// bufio.Reader, feeding the same counters and channels as the classic path.
// Lifted from the old PCAPFile.streamPCAPNG.
func streamPCAPNGRecords(ctx context.Context, r *bufio.Reader, out chan<- packet.Packet, errc chan<- error, st *streamStats) {
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
		st.countPacket(uint64(len(rec.data)), rec.ts)

		pk, derr := packet.Decode(rec.link, rec.ts, rec.data)
		if derr != nil {
			st.countDecodeErr()
			continue
		}
		st.countDecoded()
		select {
		case out <- pk:
		case <-ctx.Done():
			errc <- ctx.Err()
			return
		}
	}
}
