package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Minimal read-only pcapng support (GitHub issue #73). The format is a stream of
// length-delimited blocks (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html).
// We read only what the pipeline needs — one section, Ethernet or RAW link types,
// Enhanced/Simple Packet Blocks — and skip every other block by its total length.
// Anything outside that envelope (multiple sections, mixed endianness, exotic
// link types) is refused with the same actionable hint the classic path gives.
const (
	ngBlockSHB = 0x0A0D0D0A // Section Header Block (byte-order independent)
	ngBlockIDB = 0x00000001 // Interface Description Block
	ngBlockSPB = 0x00000003 // Simple Packet Block
	ngBlockEPB = 0x00000006 // Enhanced Packet Block

	ngByteOrderMagic = 0x1A2B3C4D // SHB magic, read in the section's byte order
	ngOptEnd         = 0          // opt_endofopt
	ngOptIfTsresol   = 9          // if_tsresol: timestamp resolution

	// A block body is capped like a classic record: snap length plus slack for
	// options. Defends against a crafted multi-gigabyte total_length.
	ngMaxBlockLen   = maxSnapLen + 0x10000
	ngMaxInterfaces = 256 // a crafted file cannot make us allocate unbounded IDBs
)

// errMultiSection is returned when a second Section Header Block appears. Multiple
// sections (and the mid-file endianness change they allow) are deliberately not
// implemented; editcap flattens them.
var errMultiSection = errors.New("capture: pcapng file has multiple sections (not supported — try: editcap -F pcap in.pcapng out.pcap)")

// ngIface is the decoded state of one Interface Description Block.
type ngIface struct {
	link        packet.LinkType
	unitsPerSec uint64 // timestamp ticks per second (if_tsresol), default 1e6
}

// ngRecord is one packet lifted out of an Enhanced or Simple Packet Block. data
// aliases the reader's block buffer and is only valid until the next call.
type ngRecord struct {
	data []byte
	link packet.LinkType
	ts   time.Time // zero for a Simple Packet Block, which carries no timestamp
}

// pcapngReader parses a single pcapng section from r. Construction consumes the
// Section Header Block and fixes the byte order; next() then walks the blocks.
type pcapngReader struct {
	r      *bufio.Reader
	bo     binary.ByteOrder
	ifaces []ngIface
	body   []byte // reused block-body scratch
}

// newPCAPNGReader reads and validates the leading Section Header Block.
func newPCAPNGReader(r *bufio.Reader) (*pcapngReader, error) {
	z := &pcapngReader{r: r}

	var h [12]byte // block type, total length, byte-order magic
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, ErrNotPCAP
	}
	// 0x0A0D0D0A is symmetric, so it reads identically in either byte order.
	if binary.BigEndian.Uint32(h[0:4]) != ngBlockSHB {
		return nil, ErrNotPCAP
	}
	switch {
	case binary.LittleEndian.Uint32(h[8:12]) == ngByteOrderMagic:
		z.bo = binary.LittleEndian
	case binary.BigEndian.Uint32(h[8:12]) == ngByteOrderMagic:
		z.bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("capture: pcapng section header has a bad byte-order magic %#08x", binary.BigEndian.Uint32(h[8:12]))
	}

	total := z.bo.Uint32(h[4:8])
	if total < 28 || total%4 != 0 || total > ngMaxBlockLen {
		return nil, fmt.Errorf("capture: pcapng section header length %d invalid", total)
	}
	// Consume the rest of the block: version (4) + section length (8) + options,
	// then the trailing total_length (4). We already read 12 bytes.
	rest := make([]byte, int(total)-12)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("capture: pcapng section header truncated: %w", err)
	}
	if z.bo.Uint32(rest[len(rest)-4:]) != total {
		return nil, errors.New("capture: pcapng section header trailing length mismatch")
	}
	return z, nil
}

// readBlock reads one whole block after the section header and returns its type
// and body (the bytes between the two length fields). It returns io.EOF at a
// clean section end.
func (z *pcapngReader) readBlock() (uint32, []byte, error) {
	var h [8]byte
	if _, err := io.ReadFull(z.r, h[:]); err != nil {
		if err == io.EOF {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("capture: pcapng truncated block header: %w", err)
	}
	typ := z.bo.Uint32(h[0:4])
	total := z.bo.Uint32(h[4:8])
	if total < 12 || total%4 != 0 || total > ngMaxBlockLen {
		return 0, nil, fmt.Errorf("capture: pcapng block length %d out of range", total)
	}
	n := int(total) - 8 // body + trailing length
	if cap(z.body) < n {
		z.body = make([]byte, n)
	}
	b := z.body[:n]
	if _, err := io.ReadFull(z.r, b); err != nil {
		return 0, nil, fmt.Errorf("capture: pcapng truncated block: %w", err)
	}
	if z.bo.Uint32(b[n-4:]) != total {
		return 0, nil, errors.New("capture: pcapng block trailing length mismatch")
	}
	return typ, b[:n-4], nil
}

// next returns the following packet record, ok=false at a clean section end.
// Interface Description Blocks update state; unknown blocks are skipped.
func (z *pcapngReader) next() (ngRecord, bool, error) {
	for {
		typ, body, err := z.readBlock()
		if err == io.EOF {
			return ngRecord{}, false, nil
		}
		if err != nil {
			return ngRecord{}, false, err
		}
		switch typ {
		case ngBlockSHB:
			return ngRecord{}, false, errMultiSection
		case ngBlockIDB:
			if err := z.addInterface(body); err != nil {
				return ngRecord{}, false, err
			}
		case ngBlockEPB:
			rec, err := z.parseEPB(body)
			return rec, err == nil, err
		case ngBlockSPB:
			rec, err := z.parseSPB(body)
			return rec, err == nil, err
		default:
			// Name Resolution, Interface Statistics, obsolete Packet Block,
			// custom blocks: pcapng readers must skip what they do not model.
		}
	}
}

// primeInterfaces reads forward to the first packet block (or section end),
// recording and validating every interface. Used by OpenPCAPFile to check the
// header without streaming packets.
func (z *pcapngReader) primeInterfaces() error {
	for {
		typ, body, err := z.readBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch typ {
		case ngBlockSHB:
			return errMultiSection
		case ngBlockIDB:
			if err := z.addInterface(body); err != nil {
				return err
			}
		case ngBlockEPB, ngBlockSPB:
			if len(z.ifaces) == 0 {
				return errors.New("capture: pcapng packet block before any interface description")
			}
			return nil
		default:
		}
	}
	if len(z.ifaces) == 0 {
		return errors.New("capture: pcapng file has no interface description block")
	}
	return nil
}

// addInterface decodes an Interface Description Block: link type, then the
// if_tsresol option for this interface's timestamp scale.
func (z *pcapngReader) addInterface(b []byte) error {
	if len(b) < 8 {
		return errors.New("capture: pcapng interface description block too short")
	}
	if len(z.ifaces) >= ngMaxInterfaces {
		return errors.New("capture: pcapng file declares too many interfaces")
	}
	linkCode := z.bo.Uint16(b[0:2])
	lt := packet.LinkType(linkCode)
	if lt != packet.LinkEthernet && lt != packet.LinkRaw {
		return fmt.Errorf("capture: unsupported pcapng link type %d (want %d ethernet or %d raw — try: editcap -F pcap in.pcapng out.pcap)", linkCode, packet.LinkEthernet, packet.LinkRaw)
	}

	units := uint64(1_000_000) // if_tsresol default: microseconds
	for off := 8; off+4 <= len(b); {
		code := z.bo.Uint16(b[off : off+2])
		olen := int(z.bo.Uint16(b[off+2 : off+4]))
		off += 4
		if code == ngOptEnd {
			break
		}
		if off+olen > len(b) {
			break // malformed option run: keep what parsed, stop
		}
		if code == ngOptIfTsresol && olen >= 1 {
			u, err := tsUnitsPerSec(b[off])
			if err != nil {
				return err
			}
			units = u
		}
		off += (olen + 3) &^ 3 // options are padded to 32 bits
	}

	z.ifaces = append(z.ifaces, ngIface{link: lt, unitsPerSec: units})
	return nil
}

// tsUnitsPerSec turns an if_tsresol byte into ticks-per-second: 10^-n when the
// high bit is clear, 2^-n when it is set.
func tsUnitsPerSec(v byte) (uint64, error) {
	n := v & 0x7f
	if v&0x80 == 0 {
		if n > 19 { // 10^20 overflows uint64
			return 0, fmt.Errorf("capture: pcapng if_tsresol 10^-%d out of range", n)
		}
		u := uint64(1)
		for i := byte(0); i < n; i++ {
			u *= 10
		}
		return u, nil
	}
	if n > 63 {
		return 0, fmt.Errorf("capture: pcapng if_tsresol 2^-%d out of range", n)
	}
	return uint64(1) << n, nil
}

// parseEPB decodes an Enhanced Packet Block.
func (z *pcapngReader) parseEPB(b []byte) (ngRecord, error) {
	if len(b) < 20 {
		return ngRecord{}, errors.New("capture: pcapng enhanced packet block too short")
	}
	ifID := z.bo.Uint32(b[0:4])
	tsHigh := z.bo.Uint32(b[4:8])
	tsLow := z.bo.Uint32(b[8:12])
	capLen := z.bo.Uint32(b[12:16])
	if capLen > maxSnapLen {
		return ngRecord{}, fmt.Errorf("capture: pcapng captured length %d out of range", capLen)
	}
	if 20+int(capLen) > len(b) {
		return ngRecord{}, errors.New("capture: pcapng packet data exceeds its block")
	}
	if int(ifID) >= len(z.ifaces) {
		return ngRecord{}, fmt.Errorf("capture: pcapng packet references undefined interface %d", ifID)
	}
	ifc := z.ifaces[ifID]
	ts64 := uint64(tsHigh)<<32 | uint64(tsLow)
	return ngRecord{data: b[20 : 20+capLen], link: ifc.link, ts: scaleNGTime(ts64, ifc.unitsPerSec)}, nil
}

// parseSPB decodes a Simple Packet Block: no interface id (interface 0), no
// timestamp, captured length derived from the block body.
func (z *pcapngReader) parseSPB(b []byte) (ngRecord, error) {
	if len(z.ifaces) == 0 {
		return ngRecord{}, errors.New("capture: pcapng simple packet block before any interface description")
	}
	if len(b) < 4 {
		return ngRecord{}, errors.New("capture: pcapng simple packet block too short")
	}
	origLen := z.bo.Uint32(b[0:4])
	n := int(origLen)
	if avail := len(b) - 4; n > avail {
		n = avail // snaplen unknown here; the block body is the hard bound
	}
	if n > maxSnapLen {
		return ngRecord{}, fmt.Errorf("capture: pcapng simple packet length %d out of range", origLen)
	}
	return ngRecord{data: b[4 : 4+n], link: z.ifaces[0].link}, nil
}

// scaleNGTime converts a pcapng tick count to a UTC time given ticks-per-second.
func scaleNGTime(ticks, unitsPerSec uint64) time.Time {
	if unitsPerSec == 0 {
		unitsPerSec = 1_000_000
	}
	secs := ticks / unitsPerSec
	rem := ticks % unitsPerSec
	hi, lo := bits.Mul64(rem, 1_000_000_000)
	nanos, _ := bits.Div64(hi, lo, unitsPerSec) // rem < unitsPerSec ⇒ quotient < 1e9
	return time.Unix(int64(secs), int64(nanos)).UTC()
}
