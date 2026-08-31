package capture

import (
	"context"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// identifiedSource is a fakeSource that speaks for a named observation point but
// leaves packet.Packet.Sensor alone, the way a future non-SYNPOIP source would.
// The Manager must fill the gap in.
type identifiedSource struct {
	fakeSource
	id, loc string
}

func (s *identifiedSource) SensorIdentity() (string, string) { return s.id, s.loc }

// stampingSource asserts its own provenance, the way the two SYNPOIP sources do.
// The Manager must not overwrite it.
type stampingSource struct {
	identifiedSource
	stamp string
}

func (s *stampingSource) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	in, errc := s.fakeSource.Packets(ctx)
	out := make(chan packet.Packet)
	go func() {
		defer close(out)
		for p := range in {
			p.Sensor = s.stamp
			select {
			case out <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// TestManagerStampsTheObservationPoint: a source that reports an identity has it
// applied to its packets, one that stamps its own keeps what it asserted, and a
// plain local source stays unattributed so the pipeline can label it "local"
// (issue #126).
func TestManagerStampsTheObservationPoint(t *testing.T) {
	reported := &identifiedSource{fakeSource: fakeSource{total: 3, tag: 1}, id: "opnsense-wan", loc: "cph-valby-gw01"}
	stamping := &stampingSource{
		identifiedSource: identifiedSource{fakeSource: fakeSource{total: 3, tag: 2}, id: "registered-name", loc: "dmz"},
		stamp:            "asserted-by-the-source",
	}
	local := &fakeSource{total: 3, tag: 3}

	m := newManager(64, 50*time.Millisecond)
	for _, s := range []struct {
		name string
		src  Source
	}{{"wan", reported}, {"dmz", stamping}, {"eth0", local}} {
		if err := m.Add(s.name, s.src, SourceMeta{Kind: "test"}); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pkts, _ := m.Packets(ctx)

	bySensor := map[string]map[uint16]int{}
	for i := 0; i < 9; i++ {
		select {
		case p := <-pkts:
			if bySensor[p.Sensor] == nil {
				bySensor[p.Sensor] = map[uint16]int{}
			}
			bySensor[p.Sensor][p.SrcPort]++
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 9 packets arrived: %v", i, bySensor)
		}
	}

	if n := bySensor["opnsense-wan"][1]; n != 3 {
		t.Errorf("the reported identity reached %d of 3 packets: %v", n, bySensor)
	}
	if n := bySensor["asserted-by-the-source"][2]; n != 3 {
		t.Errorf("the Manager overwrote a source's own provenance: %v", bySensor)
	}
	if n := bySensor[""][3]; n != 3 {
		t.Errorf("a local source's packets were attributed to a sensor: %v", bySensor)
	}

	// The same identity is published on the status row, so an operator can see
	// which sensor a capture source speaks for without reading a flow.
	row, ok := m.Get("wan")
	if !ok {
		t.Fatal("no status row for wan")
	}
	if row.SensorID != "opnsense-wan" || row.Location != "cph-valby-gw01" {
		t.Errorf("status row identity = %q/%q, want opnsense-wan/cph-valby-gw01", row.SensorID, row.Location)
	}
	if row, ok := m.Get("eth0"); !ok || row.SensorID != "" || row.Location != "" {
		t.Errorf("a local source claims a sensor identity: %+v", row)
	}
	_ = m.Close()
}
