package pipeline_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// TestAlertsEndToEnd replays the real portscan fixture through the production
// pipeline and asserts the detection feed, so the wiring in pipeline.publish is
// exercised rather than mocked.
//
// portscan.pcap is one scanner sweeping 24 ports on one target. Every one of
// those flows classifies as `scan`, and the dedup key is (src, dst, class), so
// the whole sweep must collapse to ONE detection with a count matching the
// scan verdicts — and exactly one AlertCreated event on the bus (issue #117,
// PROJECT.md §22).
func TestAlertsEndToEnd(t *testing.T) {
	pf, err := capture.OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"))
	if err != nil {
		t.Fatalf("open portscan.pcap: %v", err)
	}
	bus := events.New()
	sub := bus.Subscribe(8192)
	defer sub.Close()
	store := storage.NewMem(1000, 1000)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	al := alert.New(alert.DefaultPolicy(), alert.Options{Bus: bus})
	defer al.Close() //nolint:errcheck // always nil

	st, err := pipeline.Run(context.Background(), capture.NewReplay(pf, capture.SpeedMax), rt, bus, store,
		pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
			Sensor: "test", Alerts: al,
		})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	al.Sync()

	stats := al.Stats()
	if stats.Observed != st.Classifications {
		t.Errorf("alert store saw %d verdicts, the pipeline produced %d", stats.Observed, st.Classifications)
	}
	if stats.Dropped != 0 {
		t.Errorf("dropped = %d, want 0 — the alert goroutine must keep up with a max-speed replay", stats.Dropped)
	}

	page := al.Detections(alert.Query{Limit: 100})
	if page.Total != 1 {
		t.Fatalf("the sweep produced %d detections, want 1: %+v", page.Total, page.Detections)
	}
	d := page.Detections[0]
	if d.Class != "scan" || d.Severity != alert.SeverityMedium {
		t.Errorf("class/severity = %q/%q, want scan/medium", d.Class, d.Severity)
	}
	if d.SrcIP != "10.0.0.66" || d.DstIP != "10.0.0.1" {
		t.Errorf("tuple = %s -> %s, want 10.0.0.66 -> 10.0.0.1", d.SrcIP, d.DstIP)
	}
	if d.Count < 2 {
		t.Errorf("count = %d, want the whole sweep folded into one detection", d.Count)
	}
	if d.Count != stats.Created+stats.Deduped {
		t.Errorf("count %d != created %d + deduped %d", d.Count, stats.Created, stats.Deduped)
	}
	if d.Reason == "" || len(d.Models) == 0 {
		t.Errorf("detection carries no explanation: reason=%q models=%+v", d.Reason, d.Models)
	}

	// One AlertCreated for the whole sweep: this is the §22 property the
	// WebSocket depends on.
	alerts := 0
	for draining := true; draining; {
		select {
		case ev := <-sub.C:
			if ev.Type == events.AlertCreated {
				alerts++
			}
		default:
			draining = false
		}
	}
	if alerts != 1 {
		t.Errorf("AlertCreated published %d times for one sweep, want 1", alerts)
	}
	if sub.Dropped() != 0 {
		t.Fatalf("the test subscriber dropped %d events — the count above is not trustworthy", sub.Dropped())
	}
}

// TestPipelineWithoutAlertStore proves alerting is optional: a nil Alerts hook
// leaves the data plane untouched.
func TestPipelineWithoutAlertStore(t *testing.T) {
	pf, err := capture.OpenPCAPFile(filepath.Join("..", "..", "testdata", "pcap", "portscan.pcap"))
	if err != nil {
		t.Fatalf("open portscan.pcap: %v", err)
	}
	bus := events.New()
	sub := bus.Subscribe(8192)
	defer sub.Close()
	store := storage.NewMem(1000, 1000)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))

	st, err := pipeline.Run(context.Background(), capture.NewReplay(pf, capture.SpeedMax), rt, bus, store,
		pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
			Sensor: "test",
		})
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	if st.Classifications == 0 {
		t.Fatal("no classifications — the fixture or the pipeline is broken, not the alert wiring")
	}
	for draining := true; draining; {
		select {
		case ev := <-sub.C:
			if ev.Type == events.AlertCreated {
				t.Fatal("AlertCreated was published with no alert store wired")
			}
		default:
			draining = false
		}
	}
}
