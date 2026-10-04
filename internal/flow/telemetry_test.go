package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func TestOrderedTimingAndImmutableSnapshots(t *testing.T) {
	var rows []Record
	table := NewTable(Options{SnapshotInterval: time.Second}, func(r Record) { rows = append(rows, r) })
	base := time.Unix(100, 0)
	p := packet.Packet{TS: base, SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"), Proto: packet.ProtoUDP, SrcPort: 10000, DstPort: 53, TotalLen: 100}
	for i := 0; i < 40; i++ {
		p.TS = base.Add(time.Duration(i) * time.Second)
		table.Observe(p)
		table.Tick(p.TS)
	}
	table.Flush()
	if len(rows) < 2 {
		t.Fatal("no snapshots")
	}
	first := rows[0].Telemetry
	if first.Samples != 2 {
		t.Fatalf("snapshot mutated: %d", first.Samples)
	}
	last := rows[len(rows)-1].Telemetry
	g, s := last.Ordered()
	if len(g) != 32 || len(s) != 32 || g[0] != 1 || g[31] != 1 || s[0] != 100 {
		t.Fatal("bad ring order")
	}
}
