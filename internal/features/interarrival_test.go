package features_test

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// These tests pin the frozen missing-value contract for the inter-arrival
// features of flow-features-v1 (schemas/features/flow-features-v1.json):
//
//	15 interarrival_mean          "0 for <2 packets"
//	16 interarrival_min           "0 for <2 packets"
//	17 interarrival_max           "0 for <2 packets"
//	18 interarrival_stddev        "0 for <3 packets"
//	19 forward_interarrival_mean  "0 for <2 forward packets"
//	20 backward_interarrival_mean "0 for <2 backward packets"
//
// A gap only exists between two consecutive packets, so N packets yield N-1
// gaps and a single-packet flow has no inter-arrival distribution at all. In
// every such case the value is the schema's default_missing sentinel (0), never
// a measured zero. GitHub issue #72.

// udpIATPkt builds a minimal UDP packet.Packet for the flow engine. UDP keeps
// the flow open until Flush (no TCP teardown), and the initiator is simply the
// source of the first packet observed.
func udpIATPkt(ts time.Time, src, dst string, sp, dp uint16) packet.Packet {
	return packet.Packet{
		TS:       ts,
		SrcIP:    netip.MustParseAddr(src),
		DstIP:    netip.MustParseAddr(dst),
		SrcPort:  sp,
		DstPort:  dp,
		Proto:    packet.ProtoUDP,
		TotalLen: 80,
	}
}

// extractOneFlow feeds pkts through a flow.Table, closes everything at capture
// end, and returns the flow-features-v1 vector for the single resulting flow.
func extractOneFlow(t *testing.T, pkts ...packet.Packet) features.Vector {
	t.Helper()
	var recs []flow.Record
	tbl := flow.NewTable(
		flow.Options{IdleTimeout: time.Minute, MaxLifetime: time.Hour},
		func(r flow.Record) { recs = append(recs, r) },
	)
	for _, p := range pkts {
		tbl.Observe(p)
	}
	tbl.Flush()
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 flow record, got %d", len(recs))
	}
	return features.Extract(recs[0])
}

func TestInterarrivalSinglePacketFlowIsSentinelZero(t *testing.T) {
	t0 := time.Unix(1_000, 0)
	v := extractOneFlow(t, udpIATPkt(t0, "10.0.0.1", "10.0.0.2", 40000, 53))

	for _, name := range []string{
		"interarrival_mean",
		"interarrival_min",
		"interarrival_max",
		"interarrival_stddev",
	} {
		if got := v.Get(name); got != 0 {
			t.Errorf("%s = %v for a 1-packet flow, want 0 (frozen default_missing sentinel)", name, got)
		}
	}
}

func TestInterarrivalTwoPacketFlowHasGapButNoStdDev(t *testing.T) {
	t0 := time.Unix(2_000, 0)
	const gap = 0.5 // one 500 ms gap
	v := extractOneFlow(t,
		udpIATPkt(t0, "10.0.0.1", "10.0.0.2", 40001, 53),
		udpIATPkt(t0.Add(500*time.Millisecond), "10.0.0.1", "10.0.0.2", 40001, 53),
	)

	for _, name := range []string{"interarrival_mean", "interarrival_min", "interarrival_max"} {
		if got := v.Get(name); math.Abs(got-gap) > 1e-12 {
			t.Errorf("%s = %v, want %v (the single inter-arrival gap)", name, got, gap)
		}
	}
	if got := v.Get("interarrival_stddev"); got != 0 {
		t.Errorf("interarrival_stddev = %v for a 2-packet flow (one gap), want 0 (frozen sentinel: <3 packets)", got)
	}
}

func TestInterarrivalThreePacketFlowHasStdDev(t *testing.T) {
	t0 := time.Unix(3_000, 0)
	// Two unequal, exactly-representable gaps: 0.25 s then 0.75 s.
	// mean 0.5, min 0.25, max 0.75, population stddev 0.25.
	v := extractOneFlow(t,
		udpIATPkt(t0, "10.0.0.1", "10.0.0.2", 40002, 53),
		udpIATPkt(t0.Add(250*time.Millisecond), "10.0.0.1", "10.0.0.2", 40002, 53),
		udpIATPkt(t0.Add(1000*time.Millisecond), "10.0.0.1", "10.0.0.2", 40002, 53),
	)

	if got := v.Get("interarrival_stddev"); got <= 0 {
		t.Errorf("interarrival_stddev = %v for a 3-packet flow with unequal gaps, want > 0", got)
	}
	for _, tc := range []struct {
		name string
		want float64
	}{
		{"interarrival_mean", 0.5},
		{"interarrival_min", 0.25},
		{"interarrival_max", 0.75},
		{"interarrival_stddev", 0.25},
	} {
		if got := v.Get(tc.name); math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestForwardBackwardInterarrivalNeedTwoPacketsPerDirection(t *testing.T) {
	t0 := time.Unix(4_000, 0)

	// 1 forward packet, 2 backward packets. Initiator is 10.0.0.1 (first packet).
	// Forward has no gap; backward has one 0.3 s gap.
	oneFwd := extractOneFlow(t,
		udpIATPkt(t0, "10.0.0.1", "10.0.0.2", 40003, 53),
		udpIATPkt(t0.Add(100*time.Millisecond), "10.0.0.2", "10.0.0.1", 53, 40003),
		udpIATPkt(t0.Add(400*time.Millisecond), "10.0.0.2", "10.0.0.1", 53, 40003),
	)
	if got := oneFwd.Get("forward_interarrival_mean"); got != 0 {
		t.Errorf("forward_interarrival_mean = %v with only 1 forward packet, want 0 (frozen sentinel)", got)
	}
	if got := oneFwd.Get("backward_interarrival_mean"); math.Abs(got-0.3) > 1e-9 {
		t.Errorf("backward_interarrival_mean = %v with 2 backward packets, want the 0.3 s gap", got)
	}

	// 2 forward packets: the forward gap is now defined.
	twoFwd := extractOneFlow(t,
		udpIATPkt(t0, "10.0.0.1", "10.0.0.2", 40004, 53),
		udpIATPkt(t0.Add(250*time.Millisecond), "10.0.0.1", "10.0.0.2", 40004, 53),
	)
	if got := twoFwd.Get("forward_interarrival_mean"); math.Abs(got-0.25) > 1e-12 {
		t.Errorf("forward_interarrival_mean = %v with 2 forward packets, want 0.25", got)
	}
}
