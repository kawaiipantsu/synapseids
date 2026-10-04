package pipeline_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/policy"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

type alertCounter struct{ n int }

func (a *alertCounter) Observe(_ *storage.FlowRecord, _ *storage.Classification) { a.n++ }
func TestPolicySuppressesDeliveryButKeepsVerdict(t *testing.T) {
	_, baseline := runFixture(t, "portscan.pcap")
	classes := baseline.RecentClassifications(1000)
	if len(classes) == 0 {
		t.Fatal("empty fixture")
	}
	ip := classes[0].InitiatorIP
	s, _ := policy.Open(filepath.Join(t.TempDir(), "p.json"))
	d := s.Get()
	d.Rules = []policy.Rule{{CIDR: ip, Mode: "owned", SuppressClasses: []string{"scan"}}}
	if _, e := s.Replace(d); e != nil {
		t.Fatal(e)
	}
	pf, e := capture.OpenPCAPFile(fixture("portscan.pcap"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = pf.Close() }()
	mem := storage.NewMem(2000, 2000)
	a := &alertCounter{}
	_, e = pipeline.Run(context.Background(), capture.NewReplay(pf, capture.SpeedMax), inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)), events.New(), mem, pipeline.Options{Flow: flow.Options{IdleTimeout: 30 * time.Second}, Policy: s, Alerts: a})
	if e != nil {
		t.Fatal(e)
	}
	suppressed := 0
	for _, cl := range mem.RecentClassifications(1000) {
		if cl.InitiatorIP == ip && cl.Result.Class == "scan" {
			if !cl.AlertSuppressed {
				t.Fatal("scan not suppressed")
			}
			suppressed++
		}
	}
	if suppressed == 0 || int(s.SuppressedAlerts.Load()) != suppressed {
		t.Fatal("missing suppression counters")
	}
	if a.n+suppressed != mem.Stats().Classifications {
		t.Fatal("non-suppressed alerts lost")
	}
}
func TestPolicyExcludesRemoteFlowRecords(t *testing.T) {
	s, _ := policy.Open(filepath.Join(t.TempDir(), "p.json"))
	d := s.Get()
	d.Rules = []policy.Rule{{CIDR: "192.0.2.0/24", Mode: "exclude"}}
	_, _ = s.Replace(d)
	records := make(chan pcapoverip.SensorRecord, 1)
	records <- pcapoverip.SensorRecord{Flow: &flow.Record{InitiatorIP: netip.MustParseAddr("198.51.100.1"), ResponderIP: netip.MustParseAddr("192.0.2.8")}}
	close(records)
	pf, e := capture.OpenPCAPFile(fixture("portscan.pcap"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = pf.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mem := storage.NewMem(10, 10)
	_, _ = pipeline.Run(ctx, capture.NewReplay(pf, capture.SpeedMax), inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)), events.New(), mem, pipeline.Options{Policy: s, Records: records})
	if s.ExcludedRecords.Load() != 1 {
		t.Fatal("remote flow bypass not counted")
	}
	for _, fr := range mem.RecentFlows(10) {
		if fr.ResponderIP == "192.0.2.8" {
			t.Fatal("excluded flow retained")
		}
	}
}
