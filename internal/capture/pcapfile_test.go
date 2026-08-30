package capture

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// tinyPCAP writes a one-packet classic pcap (DLT_RAW) holding a minimal IPv4/UDP
// datagram and returns its path.
func tinyPCAP(t *testing.T) string {
	t.Helper()
	ip := make([]byte, 28) // 20 IPv4 + 8 UDP
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[9] = 17
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(ip[20:22], 1000)
	binary.BigEndian.PutUint16(ip[22:24], 53)

	var buf []byte
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 101) // DLT_RAW
	buf = append(buf, gh...)
	rh := make([]byte, 16)
	binary.LittleEndian.PutUint32(rh[0:4], 1)
	binary.LittleEndian.PutUint32(rh[8:12], uint32(len(ip)))
	binary.LittleEndian.PutUint32(rh[12:16], uint32(len(ip)))
	buf = append(buf, rh...)
	buf = append(buf, ip...)

	p := filepath.Join(t.TempDir(), "tiny.pcap")
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPCAPFileReadsPackets(t *testing.T) {
	src, err := OpenPCAPFile(tinyPCAP(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pkts, errc := src.Packets(context.Background())
	var n int
	for p := range pkts {
		n++
		if p.DstPort != 53 {
			t.Fatalf("dst port: %d", p.DstPort)
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("terminal error: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 packet, got %d", n)
	}
	if s := src.Stats(); s.Packets != 1 || s.Decoded != 1 {
		t.Fatalf("stats: %+v", s)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsNonPCAP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	writeFile(t, p, []byte("not a pcap file at all, just text padding padding"))
	if _, err := OpenPCAPFile(p); err == nil {
		t.Fatalf("expected rejection of non-pcap input")
	}
}

func TestOpenRejectsPCAPNG(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.pcapng")
	// pcapng Section Header Block magic.
	writeFile(t, p, []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0x1c, 0x4d, 0x3c, 0x2b, 0x1a})
	if _, err := OpenPCAPFile(p); err == nil {
		t.Fatalf("pcapng must be rejected with guidance")
	}
}

func TestCommittedFixturesOpen(t *testing.T) {
	for _, f := range []string{"http.pcap", "portscan.pcap", "udp.pcap"} {
		if _, err := OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
