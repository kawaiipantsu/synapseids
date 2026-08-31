package pipeline_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// TestInsightObserverEndToEnd replays a real fixture through the production
// pipeline and asserts the host and timeline aggregates that Investigation mode
// reads (PROJECT.md §19.4-6). portscan.pcap is one scanner sweeping 24 ports on
// one target, so both sides of every flow must show up with a matching profile.
func TestInsightObserverEndToEnd(t *testing.T) {
	pf, err := capture.OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"))
	if err != nil {
		t.Fatalf("open portscan.pcap: %v", err)
	}
	bus := events.New()
	store := storage.NewMem(1000, 1000)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	ix := insight.New(insight.Options{})
	defer ix.Close() //nolint:errcheck // always nil

	st, err := pipeline.Run(context.Background(), capture.NewReplay(pf, capture.SpeedMax), rt, bus, store,
		pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
			Sensor: "test", Observer: ix,
		})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	ix.Sync()

	if ix.Stats().Observed != st.Flows {
		t.Errorf("aggregator saw %d records, pipeline emitted %d", ix.Stats().Observed, st.Flows)
	}
	if ix.Stats().Dropped != 0 {
		t.Errorf("Dropped = %d, want 0 — the aggregator must keep up with a max-speed replay", ix.Stats().Dropped)
	}

	// Exactly the two endpoints in the capture.
	hosts := ix.Hosts("", insight.SortFlows, 100)
	if len(hosts) != 2 {
		t.Fatalf("want 2 observed hosts, got %d: %+v", len(hosts), hosts)
	}

	scanner, ok := ix.Host("10.0.0.66")
	if !ok {
		t.Fatal("scanner 10.0.0.66 has no profile")
	}
	target, ok := ix.Host("10.0.0.1")
	if !ok {
		t.Fatal("target 10.0.0.1 has no profile")
	}

	if scanner.Flows != st.Flows || target.Flows != st.Flows {
		t.Errorf("flow counts = scanner %d / target %d, want %d each", scanner.Flows, target.Flows, st.Flows)
	}
	if scanner.FlowsInitiated != st.Flows || scanner.FlowsResponded != 0 {
		t.Errorf("scanner initiated/responded = %d/%d, want %d/0",
			scanner.FlowsInitiated, scanner.FlowsResponded, st.Flows)
	}
	if target.FlowsResponded != st.Flows || target.FlowsInitiated != 0 {
		t.Errorf("target initiated/responded = %d/%d, want 0/%d",
			target.FlowsInitiated, target.FlowsResponded, st.Flows)
	}

	// The class mix is the point of the fixture: every flow is a scan.
	if len(scanner.Classes) != 1 || scanner.Classes[0].Class != "scan" || scanner.Classes[0].Count != st.Flows {
		t.Errorf("scanner class mix = %+v, want %d × scan", scanner.Classes, st.Flows)
	}
	if len(target.Classes) != 1 || target.Classes[0].Class != "scan" {
		t.Errorf("target class mix = %+v, want scan only", target.Classes)
	}

	// Volume mirrors between the two sides.
	if scanner.BytesOut != target.BytesIn || scanner.BytesIn != target.BytesOut {
		t.Errorf("byte totals do not mirror: scanner out/in %d/%d, target in/out %d/%d",
			scanner.BytesOut, scanner.BytesIn, target.BytesIn, target.BytesOut)
	}
	if scanner.BytesOut == 0 {
		t.Error("scanner sent zero bytes")
	}

	// One peer each, and one protocol.
	if len(scanner.TopPeers) != 1 || scanner.TopPeers[0].IP != "10.0.0.1" ||
		scanner.TopPeers[0].Flows != st.Flows {
		t.Errorf("scanner peers = %+v", scanner.TopPeers)
	}
	if len(scanner.Protocols) != 1 || scanner.Protocols[0].Proto != "TCP" {
		t.Errorf("scanner protocols = %+v", scanner.Protocols)
	}
	// A sweep hits many distinct service ports, each once.
	if len(scanner.TopPorts) < 5 {
		t.Errorf("scanner top ports = %+v, want a spread of scanned ports", scanner.TopPorts)
	}
	for _, p := range scanner.TopPorts {
		if p.Flows != 1 {
			t.Errorf("port %d seen %d times, want 1 in a single sweep", p.Port, p.Flows)
		}
	}
	if len(scanner.RecentFlows) == 0 {
		t.Error("scanner has no recent flows")
	}

	// The timeline carries every verdict.
	var total uint32
	for _, b := range ix.Timeline(1, time.Time{}, time.Time{}).Buckets {
		total += b.Total
	}
	if uint64(total) != st.Classifications {
		t.Errorf("timeline total = %d, want %d classifications", total, st.Classifications)
	}
}

// A pipeline with no Observer must behave exactly as before.
func TestNilObserverIsHarmless(t *testing.T) {
	pf, err := capture.OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", "http.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := pipeline.Run(context.Background(), capture.NewReplay(pf, capture.SpeedMax),
		inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary)),
		events.New(), storage.NewMem(100, 100),
		pipeline.Options{Flow: flow.Options{IdleTimeout: 30 * time.Second}, Sensor: "test"})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if st.Flows == 0 {
		t.Error("no flows without an Observer")
	}
}
