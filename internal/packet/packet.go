// Package packet decodes raw link-layer frames into a small, allocation-light
// normalized representation. Everything downstream (flows, features, inference)
// works from packet.Packet and never sees raw bytes again (PROJECT.md §5, §19).
//
// All decoders are bounds-checked. Malformed input yields ErrShortPacket or
// ErrUnsupported and is counted by the caller; a decoder never panics on
// attacker-controlled bytes (PROJECT.md §28.11).
package packet

import (
	"errors"
	"net/netip"
	"time"
)

// Errors returned by Decode.
var (
	ErrShortPacket = errors.New("packet: truncated")
	ErrUnsupported = errors.New("packet: unsupported link type or protocol")
)

// LinkType identifies the link layer of a capture (libpcap DLT values).
type LinkType int

// Supported link types.
const (
	LinkEthernet LinkType = 1   // DLT_EN10MB
	LinkRaw      LinkType = 101 // DLT_RAW: the frame starts at the IP header
)

// Proto is an IP transport protocol number.
type Proto uint8

// Transport protocols of interest.
const (
	ProtoICMP   Proto = 1
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMPv6 Proto = 58
)

func (p Proto) String() string {
	switch p {
	case ProtoICMP:
		return "ICMP"
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMPv6:
		return "ICMPv6"
	default:
		return "IP"
	}
}

// TCP flag bits.
const (
	FlagFIN = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
)

// Packet is one decoded packet reduced to what the flow engine needs.
type Packet struct {
	TS         time.Time
	SrcIP      netip.Addr
	DstIP      netip.Addr
	Proto      Proto
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   uint8
	TCPWindow  uint16
	IPVersion  uint8
	TotalLen   int // total captured L2-agnostic length: IP header + everything after
	PayloadLen int // L4 payload length (after the TCP/UDP header)

	// Sensor identifies the *observation point* this packet was captured at: the
	// id of the remote sensor whose SYNPOIP session delivered it, or "" for a
	// packet the daemon captured itself (a local NIC, a PCAP file, a replay).
	//
	// Decode never sets it — nothing in a frame can be trusted to say where it was
	// seen (§28.11). It is stamped by capture.Manager from the identity the source
	// reported at registration, which is the only place that knows it, and it is
	// carried through flow.Key so two sensors observing the same 5-tuple keep two
	// separate flows instead of merging into one with doubled counters
	// (docs/adr/0030, issue #126).
	//
	// It is provenance, not signal: it never reaches flow-features-v1, which is
	// frozen at 48 values and carries no identity of any kind (PROJECT.md §8).
	// The string is shared by every packet from one source, so the copy here is a
	// header copy — no allocation on the packet path (§22).
	Sensor string
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88A8
)

// Decode turns a raw frame into a Packet. link selects the link layer.
func Decode(link LinkType, ts time.Time, frame []byte) (Packet, error) {
	switch link {
	case LinkEthernet:
		return decodeEthernet(ts, frame)
	case LinkRaw:
		return decodeIP(ts, frame)
	default:
		return Packet{}, ErrUnsupported
	}
}

func decodeEthernet(ts time.Time, b []byte) (Packet, error) {
	if len(b) < 14 {
		return Packet{}, ErrShortPacket
	}
	et := uint16(b[12])<<8 | uint16(b[13])
	off := 14
	// Walk up to two stacked VLAN tags.
	for i := 0; i < 2 && (et == etherTypeVLAN || et == etherTypeQinQ); i++ {
		if len(b) < off+4 {
			return Packet{}, ErrShortPacket
		}
		et = uint16(b[off+2])<<8 | uint16(b[off+3])
		off += 4
	}
	switch et {
	case etherTypeIPv4, etherTypeIPv6:
		return decodeIP(ts, b[off:])
	default:
		return Packet{}, ErrUnsupported
	}
}

func decodeIP(ts time.Time, b []byte) (Packet, error) {
	if len(b) < 1 {
		return Packet{}, ErrShortPacket
	}
	switch b[0] >> 4 {
	case 4:
		return decodeIPv4(ts, b)
	case 6:
		return decodeIPv6(ts, b)
	default:
		return Packet{}, ErrUnsupported
	}
}

func decodeIPv4(ts time.Time, b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, ErrShortPacket
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, ErrShortPacket
	}
	total := int(uint16(b[2])<<8 | uint16(b[3]))
	if total < ihl {
		total = len(b) // captured length is the best we have
	}
	if total > len(b) {
		total = len(b)
	}
	p := Packet{
		TS:        ts,
		Proto:     Proto(b[9]),
		IPVersion: 4,
		TotalLen:  total,
	}
	p.SrcIP, _ = netip.AddrFromSlice(b[12:16])
	p.DstIP, _ = netip.AddrFromSlice(b[16:20])
	// Fragmented packets past the first carry no usable L4 header.
	fragOff := (uint16(b[6])<<8 | uint16(b[7])) & 0x1fff
	if fragOff != 0 {
		return p, nil
	}
	return decodeL4(p, b[ihl:total])
}

func decodeIPv6(ts time.Time, b []byte) (Packet, error) {
	if len(b) < 40 {
		return Packet{}, ErrShortPacket
	}
	payLen := int(uint16(b[4])<<8 | uint16(b[5]))
	total := 40 + payLen
	if total > len(b) || total < 40 {
		total = len(b)
	}
	p := Packet{
		TS:        ts,
		Proto:     Proto(b[6]),
		IPVersion: 6,
		TotalLen:  total,
	}
	p.SrcIP, _ = netip.AddrFromSlice(b[8:24])
	p.DstIP, _ = netip.AddrFromSlice(b[24:40])

	// Skip a bounded chain of well-known extension headers.
	rest := b[40:total]
	next := p.Proto
	for hops := 0; hops < 8; hops++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return p, nil
			}
			hdrLen := (int(rest[1]) + 1) * 8
			if len(rest) < hdrLen {
				return p, nil
			}
			next = Proto(rest[0])
			rest = rest[hdrLen:]
		case 44: // fragment header
			if len(rest) < 8 {
				return p, nil
			}
			fragOff := (uint16(rest[2])<<8 | uint16(rest[3])) &^ 0x0007
			nh := Proto(rest[0])
			rest = rest[8:]
			next = nh
			if fragOff != 0 {
				p.Proto = next
				return p, nil
			}
		default:
			p.Proto = next
			return decodeL4(p, rest)
		}
	}
	p.Proto = next
	return p, nil
}

func decodeL4(p Packet, l4 []byte) (Packet, error) {
	switch p.Proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return Packet{}, ErrShortPacket
		}
		dataOff := int(l4[12]>>4) * 4
		if dataOff < 20 {
			dataOff = 20
		}
		if dataOff > len(l4) {
			dataOff = len(l4)
		}
		p.SrcPort = uint16(l4[0])<<8 | uint16(l4[1])
		p.DstPort = uint16(l4[2])<<8 | uint16(l4[3])
		p.TCPWindow = uint16(l4[14])<<8 | uint16(l4[15])
		p.TCPFlags = l4[13] & 0x3f
		p.PayloadLen = len(l4) - dataOff
	case ProtoUDP:
		if len(l4) < 8 {
			return Packet{}, ErrShortPacket
		}
		p.SrcPort = uint16(l4[0])<<8 | uint16(l4[1])
		p.DstPort = uint16(l4[2])<<8 | uint16(l4[3])
		p.PayloadLen = len(l4) - 8
	case ProtoICMP, ProtoICMPv6:
		p.PayloadLen = len(l4)
	default:
		p.PayloadLen = len(l4)
	}
	if p.PayloadLen < 0 {
		p.PayloadLen = 0
	}
	return p, nil
}
