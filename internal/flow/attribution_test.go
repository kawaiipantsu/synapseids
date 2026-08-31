package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Two sensors watching the same routed conversation see the same 5-tuple. The
// flow table must keep them apart: merging them would double every packet and
// byte count and silently corrupt every feature derived from them (issue #126,
// docs/adr/0030).
func TestTwoSensorsSameTupleStaySeparateFlows(t *testing.T) {
	var got []Record
	tbl := NewTable(Options{IdleTimeout: time.Minute, MaxLifetime: time.Hour}, func(r Record) { got = append(got, r) })
	t0 := time.Unix(1000, 0)

	// The identical exchange, observed at two points. The wan sensor also sees a
	// data packet the dmz sensor does not, so the two flows are distinguishable
	// by their counters and not only by their label.
	for _, sensor := range []string{"wan", "dmz"} {
		syn := mkPkt(t0, "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagSYN, 60)
		syn.Sensor = sensor
		synack := mkPkt(t0.Add(time.Millisecond), "10.0.0.2", "10.0.0.1", 80, 5000, packet.ProtoTCP, packet.FlagSYN|packet.FlagACK, 60)
		synack.Sensor = sensor
		tbl.Observe(syn)
		tbl.Observe(synack)
	}
	extra := mkPkt(t0.Add(2*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagPSH|packet.FlagACK, 500)
	extra.Sensor = "wan"
	tbl.Observe(extra)

	if n := tbl.Stats().Active; n != 2 {
		t.Fatalf("two observation points produced %d active flow(s), want 2 — the sensors merged", n)
	}
	tbl.Flush()
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}

	bySensor := map[string]Record{}
	for _, r := range got {
		bySensor[r.Sensor()] = r
	}
	wan, ok := bySensor["wan"]
	if !ok {
		t.Fatalf("no flow attributed to wan: %+v", bySensor)
	}
	dmz, ok := bySensor["dmz"]
	if !ok {
		t.Fatalf("no flow attributed to dmz: %+v", bySensor)
	}
	// Neither flow may carry the other's packets.
	if wan.FwdPackets != 2 || wan.BwdPackets != 1 || wan.FwdBytes != 560 {
		t.Errorf("wan flow = fwd %d pkts/%d B, bwd %d pkts; want 2/560 and 1 — counts leaked across sensors",
			wan.FwdPackets, wan.FwdBytes, wan.BwdPackets)
	}
	if dmz.FwdPackets != 1 || dmz.BwdPackets != 1 || dmz.FwdBytes != 60 {
		t.Errorf("dmz flow = fwd %d pkts/%d B, bwd %d pkts; want 1/60 and 1",
			dmz.FwdPackets, dmz.FwdBytes, dmz.BwdPackets)
	}
	if wan.ID == dmz.ID {
		t.Errorf("both observation points share flow id %d", wan.ID)
	}
	// The scope is identity, not topology: the tuple itself is untouched by it.
	if wan.Key.A != dmz.Key.A || wan.Key.PortA != dmz.Key.PortA || wan.Key.Proto != dmz.Key.Proto {
		t.Errorf("the 5-tuple differs between sensors: %+v vs %+v", wan.Key, dmz.Key)
	}
}

// A locally-captured packet carries no observation point, so its key is exactly
// what it was before flow attribution existed — and a sensor's flows never fold
// into the local table's.
func TestUnattributedPacketsKeepTheLocalScope(t *testing.T) {
	local := mkPkt(time.Unix(1000, 0), "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagSYN, 60)
	remote := local
	remote.Sensor = "wan"

	lk, _ := KeyOf(local)
	rk, _ := KeyOf(remote)
	if lk.Sensor != "" {
		t.Errorf("a local packet was scoped to %q", lk.Sensor)
	}
	if lk == rk {
		t.Error("a sensor's packet shares a key with local capture")
	}
	// KeyOfEndpoints answers the 5-tuple only: a record rebuilt from the wire
	// makes no claim about where it was seen.
	ek, _ := KeyOfEndpoints(local.SrcIP, local.SrcPort, local.DstIP, local.DstPort, local.Proto)
	if ek != lk {
		t.Errorf("KeyOfEndpoints = %+v, want the unscoped key %+v", ek, lk)
	}
}

// A flow record off the wire keeps the sensor it was attributed to when its key
// is rebuilt: no endpoint can say where a flow was observed.
func TestWithDerivedKeyPreservesTheSensorScope(t *testing.T) {
	r := Record{
		InitiatorIP:   netip.MustParseAddr("10.0.0.1"),
		InitiatorPort: 5000,
		ResponderIP:   netip.MustParseAddr("10.0.0.2"),
		ResponderPort: 80,
		Proto:         packet.ProtoTCP,
	}.WithSensor("edge-flow")

	got := r.WithDerivedKey()
	if got.Sensor() != "edge-flow" {
		t.Errorf("sensor scope = %q after WithDerivedKey, want edge-flow", got.Sensor())
	}
	want, _ := KeyOfEndpoints(r.InitiatorIP, r.InitiatorPort, r.ResponderIP, r.ResponderPort, r.Proto)
	want.Sensor = "edge-flow"
	if got.Key != want {
		t.Errorf("key = %+v, want %+v", got.Key, want)
	}
}
