package capture_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// drain replays a committed fixture through the capture layer and returns every
// decoded packet plus the terminal error.
func drain(t *testing.T, path string) ([]packet.Packet, error) {
	t.Helper()
	src, err := capture.OpenPCAPFile(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	pkts, errc := src.Packets(context.Background())
	var got []packet.Packet
	for p := range pkts {
		got = append(got, p)
	}
	return got, <-errc
}

// vectors replays a fixture through capture -> flow -> flow-features-v1.
func vectors(t *testing.T, path string) []features.Vector {
	t.Helper()
	src, err := capture.OpenPCAPFile(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	var out []features.Vector
	tbl := flow.NewTable(flow.Options{
		IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute,
	}, func(r flow.Record) {
		v := features.Extract(r)
		v.FlowID = 0 // flow ids are per-run, not part of the comparison
		out = append(out, v)
	})
	pkts, errc := src.Packets(context.Background())
	for p := range pkts {
		tbl.Observe(p)
	}
	if err := <-errc; err != nil {
		t.Fatalf("stream %s: %v", path, err)
	}
	tbl.Flush()
	return out
}

// TestPCAPNGTwinMatchesClassic is the core issue-#73 assertion: the hand-encoded
// http.pcapng fixture must decode to the same packets — and therefore the same
// flows and the same feature vectors — as its classic http.pcap twin.
func TestPCAPNGTwinMatchesClassic(t *testing.T) {
	classic := filepath.Join("..", "..", "testdata", "pcap", "http.pcap")
	ng := filepath.Join("..", "..", "testdata", "pcap", "http.pcapng")

	cPkts, cErr := drain(t, classic)
	nPkts, nErr := drain(t, ng)
	if cErr != nil || nErr != nil {
		t.Fatalf("terminal errors: classic=%v pcapng=%v", cErr, nErr)
	}
	if len(cPkts) == 0 {
		t.Fatal("classic fixture produced no packets")
	}
	if len(cPkts) != len(nPkts) {
		t.Fatalf("packet count: classic %d, pcapng %d", len(cPkts), len(nPkts))
	}
	for i := range cPkts {
		a, b := cPkts[i], nPkts[i]
		if !a.TS.Equal(b.TS) {
			t.Errorf("packet %d timestamp: classic %s, pcapng %s", i, a.TS, b.TS)
		}
		a.TS, b.TS = time.Time{}, time.Time{}
		if a != b {
			t.Errorf("packet %d differs:\n classic %+v\n pcapng  %+v", i, a, b)
		}
	}

	cVec, nVec := vectors(t, classic), vectors(t, ng)
	if len(cVec) != len(nVec) {
		t.Fatalf("vector count: classic %d, pcapng %d", len(cVec), len(nVec))
	}
	for i := range cVec {
		if cVec[i] != nVec[i] {
			t.Errorf("feature vector %d drifted between the twins:\n classic %+v\n pcapng  %+v", i, cVec[i], nVec[i])
		}
	}
}

func TestPCAPNGStatsMatchClassic(t *testing.T) {
	mk := func(name string) capture.Stats {
		src, err := capture.OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", name))
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		pkts, errc := src.Packets(context.Background())
		for range pkts { //nolint:revive // draining the channel
		}
		if err := <-errc; err != nil {
			t.Fatalf("stream %s: %v", name, err)
		}
		return src.Stats()
	}
	c, n := mk("http.pcap"), mk("http.pcapng")
	if c.Packets != n.Packets || c.Decoded != n.Decoded || c.DecodeErr != n.DecodeErr || c.Bytes != n.Bytes {
		t.Fatalf("stats differ: classic %+v pcapng %+v", c, n)
	}
	if !c.LastTS.Equal(n.LastTS) {
		t.Fatalf("last timestamp: classic %s pcapng %s", c.LastTS, n.LastTS)
	}
}

// ---- hand-built pcapng blocks for the edge cases ----------------------------

func ngBlock(le bool, typ uint32, body []byte) []byte {
	bo := ngBO(le)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(12 + len(body))
	b := bo.AppendUint32(nil, typ)
	b = bo.AppendUint32(b, total)
	b = append(b, body...)
	return bo.AppendUint32(b, total)
}

func ngBO(le bool) binary.AppendByteOrder {
	if le {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func ngSHB(le bool) []byte {
	bo := ngBO(le)
	body := bo.AppendUint32(nil, 0x1A2B3C4D)
	body = bo.AppendUint16(body, 1)
	body = bo.AppendUint16(body, 0)
	body = bo.AppendUint64(body, ^uint64(0))
	return ngBlock(le, 0x0A0D0D0A, body)
}

// ngIDB builds an Interface Description Block. tsresol < 0 omits the option.
func ngIDB(le bool, linkType uint16, tsresol int) []byte {
	bo := ngBO(le)
	body := bo.AppendUint16(nil, linkType)
	body = bo.AppendUint16(body, 0)
	body = bo.AppendUint32(body, 65535)
	if tsresol >= 0 {
		body = bo.AppendUint16(body, 9)
		body = bo.AppendUint16(body, 1)
		body = append(body, byte(tsresol), 0, 0, 0)
		body = bo.AppendUint16(body, 0)
		body = bo.AppendUint16(body, 0)
	}
	return ngBlock(le, 0x00000001, body)
}

func ngEPB(le bool, ifID uint32, ticks uint64, data []byte) []byte {
	bo := ngBO(le)
	body := bo.AppendUint32(nil, ifID)
	body = bo.AppendUint32(body, uint32(ticks>>32))
	body = bo.AppendUint32(body, uint32(ticks))
	body = bo.AppendUint32(body, uint32(len(data)))
	body = bo.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	return ngBlock(le, 0x00000006, body)
}

// rawIPUDP is a minimal IPv4/UDP datagram for DLT_RAW captures.
func rawIPUDP(dstPort uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 28)
	b[9] = 17
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[20:22], 1000)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	return b
}

func writeTmp(t *testing.T, name string, parts ...[]byte) string {
	t.Helper()
	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPCAPNGTimestampResolution proves if_tsresol (code 9) is honoured for both
// the decimal and the binary form.
func TestPCAPNGTimestampResolution(t *testing.T) {
	cases := []struct {
		name    string
		tsresol int
		ticks   uint64
		want    time.Time
	}{
		{"microseconds (default value 6)", 6, 1_724_000_000_000_123, time.Unix(1_724_000_000, 123_000).UTC()},
		{"nanoseconds (value 9)", 9, 1_724_000_000_000_000_123, time.Unix(1_724_000_000, 123).UTC()},
		{"binary 2^-16 (value 0x90)", 0x90, uint64(1_724_000_000)<<16 | 32768, time.Unix(1_724_000_000, 500_000_000).UTC()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTmp(t, "res.pcapng",
				ngSHB(true), ngIDB(true, 101, tc.tsresol), ngEPB(true, 0, tc.ticks, rawIPUDP(53)))
			pkts, err := drain(t, p)
			if err != nil {
				t.Fatalf("terminal error: %v", err)
			}
			if len(pkts) != 1 {
				t.Fatalf("want 1 packet, got %d", len(pkts))
			}
			if !pkts[0].TS.Equal(tc.want) {
				t.Fatalf("timestamp: got %s, want %s", pkts[0].TS.UTC(), tc.want)
			}
		})
	}
}

func TestPCAPNGBigEndianSection(t *testing.T) {
	p := writeTmp(t, "be.pcapng",
		ngSHB(false), ngIDB(false, 101, 6), ngEPB(false, 0, 1_724_000_000_000_000, rawIPUDP(53)))
	pkts, err := drain(t, p)
	if err != nil {
		t.Fatalf("terminal error: %v", err)
	}
	if len(pkts) != 1 || pkts[0].DstPort != 53 {
		t.Fatalf("big-endian section decode: %+v", pkts)
	}
}

func TestPCAPNGRejections(t *testing.T) {
	tests := []struct {
		name  string
		parts [][]byte
	}{
		{"unsupported link type", [][]byte{ngSHB(true), ngIDB(true, 105 /* 802.11 */, 6)}},
		{"no interface description block", [][]byte{ngSHB(true), ngEPB(true, 0, 1, rawIPUDP(53))}},
		{"packet references undefined interface", [][]byte{ngSHB(true), ngIDB(true, 101, 6), ngEPB(true, 7, 1, rawIPUDP(53))}},
		{"second section header block", [][]byte{ngSHB(true), ngIDB(true, 101, 6), ngEPB(true, 0, 1, rawIPUDP(53)), ngSHB(true)}},
		{"bad byte-order magic", [][]byte{{0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1c, 0, 0, 0}}},
		{"crafted oversized block length", [][]byte{ngSHB(true), {0x01, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f}}},
		{"truncated block body", [][]byte{ngSHB(true), {0x01, 0, 0, 0, 0x20, 0, 0, 0, 1, 0, 0, 0}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTmp(t, "bad.pcapng", tc.parts...)
			src, err := capture.OpenPCAPFile(p)
			if err != nil {
				return // rejected at open — good
			}
			// Header looked plausible; the stream must surface the error instead.
			pkts, errc := src.Packets(context.Background())
			for range pkts { //nolint:revive // draining
			}
			if e := <-errc; e == nil {
				t.Fatalf("%s: expected an error, got a clean stream", tc.name)
			}
		})
	}
}

func TestPCAPNGSimplePacketBlock(t *testing.T) {
	bo := binary.LittleEndian
	data := rawIPUDP(53)
	spbBody := bo.AppendUint32(nil, uint32(len(data)))
	spbBody = append(spbBody, data...)
	spb := ngBlock(true, 0x00000003, spbBody)

	p := writeTmp(t, "spb.pcapng", ngSHB(true), ngIDB(true, 101, 6), spb)
	pkts, err := drain(t, p)
	if err != nil {
		t.Fatalf("terminal error: %v", err)
	}
	if len(pkts) != 1 || pkts[0].DstPort != 53 {
		t.Fatalf("simple packet block decode: %+v", pkts)
	}
	if !pkts[0].TS.IsZero() {
		t.Fatalf("simple packet block should carry no timestamp, got %s", pkts[0].TS)
	}
}

func TestPCAPNGSkipsUnknownBlocks(t *testing.T) {
	// An Interface Statistics Block (type 5) between the IDB and the packet must
	// be skipped by total length, not misread.
	bo := binary.LittleEndian
	isbBody := bo.AppendUint32(nil, 0) // interface id
	isbBody = bo.AppendUint32(isbBody, 0)
	isbBody = bo.AppendUint32(isbBody, 0)
	isb := ngBlock(true, 0x00000005, isbBody)

	p := writeTmp(t, "isb.pcapng",
		ngSHB(true), ngIDB(true, 101, 6), isb, ngEPB(true, 0, 1_724_000_000_000_000, rawIPUDP(53)))
	pkts, err := drain(t, p)
	if err != nil {
		t.Fatalf("terminal error: %v", err)
	}
	if len(pkts) != 1 || pkts[0].DstPort != 53 {
		t.Fatalf("unknown-block skip: %+v", pkts)
	}
}
