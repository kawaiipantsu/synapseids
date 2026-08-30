package packet

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func eth(et uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	b[12] = byte(et >> 8)
	b[13] = byte(et)
	copy(b[14:], payload)
	return b
}

func ip4(proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(payload)))
	b[9] = proto
	copy(b[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(b[16:20], net.IPv4(10, 0, 0, 2).To4())
	copy(b[20:], payload)
	return b
}

func tcpSeg(sport, dport uint16, flags byte, win uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], win)
	copy(b[20:], payload)
	return b
}

func TestDecodeTCPOverEthernet(t *testing.T) {
	frame := eth(0x0800, ip4(6, tcpSeg(1234, 80, FlagSYN|FlagACK, 64240, []byte("hi"))))
	p, err := Decode(LinkEthernet, time.Unix(1, 0), frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Proto != ProtoTCP || p.SrcPort != 1234 || p.DstPort != 80 {
		t.Fatalf("ports/proto wrong: %+v", p)
	}
	if p.TCPFlags&FlagSYN == 0 || p.TCPFlags&FlagACK == 0 {
		t.Fatalf("flags not decoded: %08b", p.TCPFlags)
	}
	if p.TCPWindow != 64240 {
		t.Fatalf("window: %d", p.TCPWindow)
	}
	if p.PayloadLen != 2 {
		t.Fatalf("payload len: %d", p.PayloadLen)
	}
	if p.SrcIP.String() != "10.0.0.1" || p.DstIP.String() != "10.0.0.2" {
		t.Fatalf("addrs: %s -> %s", p.SrcIP, p.DstIP)
	}
}

func TestDecodeUDPAndRaw(t *testing.T) {
	udp := make([]byte, 8+4)
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	p, err := Decode(LinkRaw, time.Unix(2, 0), ip4(17, udp))
	if err != nil {
		t.Fatalf("Decode raw/udp: %v", err)
	}
	if p.Proto != ProtoUDP || p.SrcPort != 5353 || p.DstPort != 53 || p.PayloadLen != 4 {
		t.Fatalf("udp decode wrong: %+v", p)
	}
}

func TestDecodeVLAN(t *testing.T) {
	inner := ip4(6, tcpSeg(1, 2, FlagSYN, 100, nil))
	b := make([]byte, 0, 22+len(inner))
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // dst+src mac
	b = append(b, 0x81, 0x00, 0x00, 0x0a)             // VLAN tag, vid 10
	b = append(b, 0x08, 0x00)                         // inner ethertype IPv4
	b = append(b, inner...)
	p, err := Decode(LinkEthernet, time.Now(), b)
	if err != nil {
		t.Fatalf("vlan decode: %v", err)
	}
	if p.Proto != ProtoTCP || p.SrcPort != 1 {
		t.Fatalf("vlan inner wrong: %+v", p)
	}
}

func TestDecodeMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x45},
		eth(0x0800, []byte{0x45, 0, 0}),      // IPv4 claim, truncated
		eth(0x0800, ip4(6, []byte{0, 0, 0})), // TCP claim, truncated L4
		eth(0x86dd, []byte{0x60, 0, 0}),      // IPv6 claim, truncated
	}
	for i, c := range cases {
		if _, err := Decode(LinkEthernet, time.Now(), c); err == nil {
			t.Fatalf("case %d: expected error, got nil", i)
		}
	}
}

func TestDecodeUnsupportedEtherType(t *testing.T) {
	if _, err := Decode(LinkEthernet, time.Now(), eth(0x0806, make([]byte, 28))); err != ErrUnsupported {
		t.Fatalf("ARP should be ErrUnsupported, got %v", err)
	}
}
