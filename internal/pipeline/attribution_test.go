package pipeline_test

// Flow attribution end to end (issue #126) and the flow-table counters a
// sensor-fed daemon reports (issue #125).
//
// The case that matters is two sensors observing the same 5-tuple: a packet
// routed between two monitored segments is genuinely seen twice, and folding
// those observations into one flow would double every count the features are
// derived from. These tests drive the real capture.Manager, because the Manager
// is what stamps the observation point on the packet path.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/packet"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// sensorSource is a synthSource that speaks for a named observation point, like
// a SYNPOIP session does. capture.Manager asks for the identity once at
// registration and stamps it on every packet the source yields.
type sensorSource struct {
	synthSource
	id  string
	loc string
}

func (s *sensorSource) SensorIdentity() (string, string) { return s.id, s.loc }

// tcpExchange builds one complete TCP conversation between a and b: SYN,
// SYN/ACK, ACK, one data packet each way, then a two-sided FIN so the flow
// closes inside the run rather than at the final flush.
func tcpExchange(a, b netip.Addr, port uint16, base time.Time, dataLen int) []packet.Packet {
	mk := func(i int, fromA bool, flags uint8, size int) packet.Packet {
		p := packet.Packet{
			TS:        base.Add(time.Duration(i) * time.Millisecond),
			Proto:     packet.ProtoTCP,
			IPVersion: 4,
			TCPFlags:  flags,
			TotalLen:  size,
		}
		if fromA {
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = a, b, port, 80
		} else {
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = b, a, 80, port
		}
		return p
	}
	return []packet.Packet{
		mk(0, true, packet.FlagSYN, 60),
		mk(1, false, packet.FlagSYN|packet.FlagACK, 60),
		mk(2, true, packet.FlagACK, 52),
		mk(3, true, packet.FlagPSH|packet.FlagACK, dataLen),
		mk(4, false, packet.FlagACK, 52),
		mk(5, true, packet.FlagFIN|packet.FlagACK, 52),
		mk(6, false, packet.FlagFIN|packet.FlagACK, 52),
	}
}

// TestTwoRawSensorsSameTupleAreNotMerged is the test this whole change exists
// for. Two raw-mode sensors stream the *same* conversation into one pipeline.
// The result must be two flows, one per sensor, each with its own counters —
// not one flow with everything doubled.
func TestTwoRawSensorsSameTupleAreNotMerged(t *testing.T) {
	a := netip.MustParseAddr("87.54.62.131")
	b := netip.MustParseAddr("10.20.30.40")
	base := time.Unix(1_700_000_000, 0).UTC()

	// Identical five-tuple, identical timing; only the data packet's size differs
	// so the two flows cannot be told apart by their label alone.
	wan := &sensorSource{synthSource: synthSource{pkts: tcpExchange(a, b, 44100, base, 500)}, id: "opnsense-wan", loc: "cph-valby-gw01"}
	dmz := &sensorSource{synthSource: synthSource{pkts: tcpExchange(a, b, 44100, base, 1400)}, id: "opnsense-dmz", loc: "cph-valby-gw01"}

	mgr := capture.NewManager()
	if err := mgr.Add("opnsense-wan", wan, capture.SourceMeta{Kind: capture.CollectorSourceKind, Mode: "raw"}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add("opnsense-dmz", dmz, capture.SourceMeta{Kind: capture.CollectorSourceKind, Mode: "raw"}); err != nil {
		t.Fatal(err)
	}

	store := storage.NewMem(100, 100)
	bus := events.New()
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	statsCh := make(chan flow.Stats, 8)
	done := make(chan pipeline.Stats, 1)
	go func() {
		st, _ := pipeline.Run(ctx, mgr, rt, bus, store, pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute, MaxFlows: 1000},
			Sensor: "local",
			OnStats: func(s flow.Stats) {
				select {
				case statsCh <- s:
				default:
				}
			},
		})
		done <- st
	}()

	// Both conversations tear down with a two-sided FIN, so both flows close
	// during the run. Wait for the work itself, never a timer.
	deadline := time.Now().Add(10 * time.Second)
	for len(store.RecentFlows(10)) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d flow(s) closed; want one per sensor", len(store.RecentFlows(10)))
		}
		time.Sleep(2 * time.Millisecond)
	}
	_ = mgr.Close()
	st := <-done

	flows := store.RecentFlows(10)
	if len(flows) != 2 {
		t.Fatalf("two sensors observing one conversation produced %d flow(s), want 2: %+v", len(flows), flows)
	}
	bySensor := map[string]storage.FlowRecord{}
	for _, f := range flows {
		bySensor[f.Sensor] = f
	}
	if len(bySensor) != 2 {
		t.Fatalf("flows are attributed to %d distinct sensor(s), want 2: %+v", len(bySensor), bySensor)
	}
	if _, ok := bySensor["local"]; ok {
		t.Errorf("a sensor's flow was labelled with the pipeline's own name (issue #126): %+v", bySensor["local"])
	}

	for _, want := range []struct {
		sensor   string
		fwdBytes uint64
	}{{"opnsense-wan", 60 + 52 + 500 + 52}, {"opnsense-dmz", 60 + 52 + 1400 + 52}} {
		f, ok := bySensor[want.sensor]
		if !ok {
			t.Fatalf("no flow attributed to %s: %+v", want.sensor, bySensor)
		}
		// 4 forward and 3 backward packets — not 8 and 6.
		if f.FwdPackets != 4 || f.BwdPackets != 3 {
			t.Errorf("%s: fwd/bwd packets = %d/%d, want 4/3 — the two sensors' packets merged",
				want.sensor, f.FwdPackets, f.BwdPackets)
		}
		if f.FwdBytes != want.fwdBytes {
			t.Errorf("%s: fwd bytes = %d, want %d", want.sensor, f.FwdBytes, want.fwdBytes)
		}
		if f.InitiatorIP != "87.54.62.131" {
			t.Errorf("%s: initiator = %q", want.sensor, f.InitiatorIP)
		}
	}

	// The classification carries the same attribution as its flow: the rolling
	// log renders one without joining the other.
	for _, c := range store.RecentClassifications(10) {
		f, ok := store.Flow(c.FlowID)
		if !ok {
			t.Fatalf("classification for unknown flow %d", c.FlowID)
		}
		if c.Sensor != f.Sensor {
			t.Errorf("flow %d: classification sensor %q != flow sensor %q", c.FlowID, c.Sensor, f.Sensor)
		}
		if c.Sensor == "local" {
			t.Errorf("classification %d attributed to the pipeline instead of the sensor", c.FlowID)
		}
	}

	// Issue #125: the table that served the sensors is the one whose counters are
	// reported. The final OnStats call happens after the flush, so it is the
	// authoritative snapshot of the run.
	if st.Flows != 2 {
		t.Errorf("pipeline stats = %+v, want 2 flows", st)
	}
	var last flow.Stats
	for {
		select {
		case s := <-statsCh:
			last = s
			continue
		default:
		}
		break
	}
	if last.Started != 2 || last.Closed != 2 {
		t.Errorf("flow-table counters = %+v, want started=2 closed=2 on a sensor-fed pipeline (issue #125)", last)
	}
}

// A source that reports no observation point — a local NIC, a replay — keeps the
// pipeline's own sensor name, so "local" still means exactly what it says.
func TestLocalCaptureKeepsTheConfiguredSensorName(t *testing.T) {
	a := netip.MustParseAddr("10.1.1.2")
	b := netip.MustParseAddr("10.1.1.9")
	src := &synthSource{pkts: tcpExchange(a, b, 44100, time.Unix(1_700_000_000, 0).UTC(), 300)}

	mgr := capture.NewManager()
	if err := mgr.Add("eth0", src, capture.SourceMeta{Kind: "nic"}); err != nil {
		t.Fatal(err)
	}
	store := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan pipeline.Stats, 1)
	go func() {
		st, _ := pipeline.Run(ctx, mgr, rt, events.New(), store, pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
			Sensor: "local",
		})
		done <- st
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(store.RecentFlows(10)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the local flow never closed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	_ = mgr.Close()
	<-done

	for _, f := range store.RecentFlows(10) {
		if f.Sensor != "local" {
			t.Errorf("local capture attributed to %q, want %q", f.Sensor, "local")
		}
		if f.SensorMode != "" || f.SensorFlowID != 0 {
			t.Errorf("local capture claimed remote provenance: mode=%q sensor_flow_id=%d", f.SensorMode, f.SensorFlowID)
		}
	}
	for _, c := range store.RecentClassifications(10) {
		if c.Sensor != "local" {
			t.Errorf("local classification attributed to %q", c.Sensor)
		}
	}
}
