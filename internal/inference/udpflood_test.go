package inference

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// dos.udp_flood used to require only a rate and a direction ratio, with no
// volume guard. A flood is defined by volume; a rate on a one- or two-packet
// flow says nothing. Combined with a feature bug that reported 1e6 packets/second
// for zero-duration flows, this classified every single-packet DNS response on a
// live WAN link as dos_ddos at severity critical and 100% confidence.
//
// Both halves are fixed; this pins the rule's half, which should have held even
// with the bad feature.
func TestSinglePacketUDPIsNotADoSFlood(t *testing.T) {
	idx := map[string]int{}
	for _, f := range schema.FlowFeaturesV1().Features {
		idx[f.Name] = f.Index
	}

	newVec := func(pkts, pps float64) features.Vector {
		var v features.Vector
		v.Schema = features.SchemaID
		v.Values[idx["protocol_udp"]] = 1
		v.Values[idx["packets_forward"]] = pkts
		v.Values[idx["packets_per_second"]] = pps
		v.Values[idx["packet_direction_ratio"]] = 1
		return v
	}

	h := NewHeuristic("heuristic-v1", RolePrimary)

	top := func(pkts, pps float64) (string, float64) {
		idx, p := h.Classify(newVec(pkts, pps)).Top()
		return schema.ClassName(idx), p
	}

	// A DNS reply: one packet. Even at an absurd claimed rate it is not a flood.
	if cls, p := top(1, 1_000_000); cls == "dos_ddos" {
		t.Errorf("a single-packet UDP flow was classified dos_ddos (score %.4f)", p)
	}

	// Two packets a millisecond apart clear 500/s honestly, and still are not a flood.
	if cls, p := top(2, 2000); cls == "dos_ddos" {
		t.Errorf("a two-packet UDP flow was classified dos_ddos (score %.4f)", p)
	}

	// A genuine high-volume one-directional UDP flood must still be caught.
	if cls, _ := top(50_000, 20_000); cls != "dos_ddos" {
		t.Errorf("a real UDP flood (50k packets at 20k/s) was classified %q, want dos_ddos", cls)
	}
}
