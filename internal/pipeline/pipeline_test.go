package pipeline_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "pcap", name)
}

func runFixture(t *testing.T, name string) (pipeline.Stats, storage.Store) {
	t.Helper()
	pf, err := capture.OpenPCAPFile(fixture(name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	src := capture.NewReplay(pf, capture.SpeedMax)
	bus := events.New()
	sub := bus.Subscribe(4096)
	defer sub.Close()
	store := storage.NewMem(1000, 1000)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))

	st, err := pipeline.Run(context.Background(), src, rt, bus, store, pipeline.Options{
		Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
		Sensor: "test",
	})
	if err != nil {
		t.Fatalf("pipeline.Run(%s): %v", name, err)
	}
	return st, store
}

// fixedAnomaly is a stand-in AnomalyScorer that returns the same verdict for
// every flow, so the pipeline → storage carry of Result.Anomaly is what is
// under test.
type fixedAnomaly struct{}

func (fixedAnomaly) ID() string           { return "ae-test" }
func (fixedAnomaly) Family() string       { return "flow-anomaly-v1" }
func (fixedAnomaly) Role() inference.Role { return inference.RoleAnomaly }
func (fixedAnomaly) ScoreAnomaly(features.Vector) inference.AnomalyOutput {
	return inference.AnomalyOutput{
		ModelID: "ae-test", Available: true,
		ReconError: 0.5, Score: 0.6, Threshold: 0.4, Exceeds: true,
	}
}

// fixedSequence is a stand-in SequenceScorer: always predicts SCAN, and records
// the largest window length it saw so a test can prove the ring filled.
type fixedSequence struct{ maxLen int }

func (s *fixedSequence) ID() string           { return "seq-test" }
func (s *fixedSequence) Family() string       { return "flow-sequence-v1" }
func (s *fixedSequence) Role() inference.Role { return inference.RoleSequence }
func (s *fixedSequence) ScoreSequence(w [][features.Size]float64) inference.Scores {
	if len(w) > s.maxLen {
		s.maxLen = len(w)
	}
	var sc inference.Scores
	sc[1] = 1 // scan
	return sc
}

func TestPipelineRunsSequenceModelWithAWindow(t *testing.T) {
	pf, err := capture.OpenPCAPFile(fixture("portscan.pcap"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	src := capture.NewReplay(pf, capture.SpeedMax)
	store := storage.NewMem(2000, 2000)
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	seq := &fixedSequence{}
	rt.SetSequenceModels(seq)

	if _, err := pipeline.Run(context.Background(), src, rt, events.New(), store, pipeline.Options{
		Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
		Sensor: "test",
	}); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	cls := store.RecentClassifications(2000)
	if len(cls) == 0 {
		t.Fatal("no classifications")
	}
	sawSeqPeer := false
	for _, c := range cls {
		for _, m := range c.Result.Models {
			if m.Role == inference.RoleSequence {
				sawSeqPeer = true
				if m.ModelID != "seq-test" || m.Class != "scan" {
					t.Fatalf("sequence peer output wrong: %+v", m)
				}
			}
		}
		if c.Result.Class == "" {
			t.Fatalf("flow %d: supervised verdict missing", c.FlowID)
		}
	}
	if !sawSeqPeer {
		t.Fatal("no RoleSequence entry in any stored Result.Models")
	}
	// portscan.pcap is a sweep — every flow is a distinct 5-tuple, so each
	// window is length 1. The ring's accumulate/wrap/prune behaviour is covered
	// directly in seqwindow_test.go.
	if seq.maxLen < 1 {
		t.Fatal("sequence model was never handed a window")
	}
}

func TestPipelineRecordsAnomalyWhenModelActive(t *testing.T) {
	pf, err := capture.OpenPCAPFile(fixture("portscan.pcap"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	src := capture.NewReplay(pf, capture.SpeedMax)
	store := storage.NewMem(1000, 1000)
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	rt.SetAnomalyModels(fixedAnomaly{})

	if _, err := pipeline.Run(context.Background(), src, rt, events.New(), store, pipeline.Options{
		Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
		Sensor: "test",
	}); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	cls := store.RecentClassifications(1000)
	if len(cls) == 0 {
		t.Fatal("no classifications stored")
	}
	for _, c := range cls {
		if c.Result.Anomaly == nil || !c.Result.Anomaly.Available ||
			c.Result.Anomaly.ModelID != "ae-test" || c.Result.Anomaly.Score != 0.6 || !c.Result.Anomaly.Exceeds {
			t.Fatalf("flow %d: anomaly not carried to storage: %+v", c.FlowID, c.Result.Anomaly)
		}
		// The anomaly model must not have altered the supervised verdict.
		if c.Result.Class == "" {
			t.Fatalf("flow %d: supervised class went missing", c.FlowID)
		}
	}
}

func TestPortScanEndToEnd(t *testing.T) {
	st, store := runFixture(t, "portscan.pcap")
	if st.Packets == 0 || st.Flows == 0 || st.Classifications == 0 {
		t.Fatalf("nothing flowed through: %+v", st)
	}

	cls := store.RecentClassifications(1000)
	var scan, total int
	for _, c := range cls {
		total++
		if c.Result.Class == "scan" {
			scan++
		}
	}
	if total == 0 || scan*2 <= total {
		t.Fatalf("portscan.pcap: only %d/%d flows classified as scan — expected a clear majority", scan, total)
	}
}

func TestHTTPAndUDPClassifyNormal(t *testing.T) {
	for _, name := range []string{"http.pcap", "udp.pcap"} {
		_, store := runFixture(t, name)
		cls := store.RecentClassifications(100)
		if len(cls) == 0 {
			t.Fatalf("%s: no classifications", name)
		}
		for _, c := range cls {
			if c.Result.Class != "normal" {
				t.Errorf("%s flow %d classified %s, want normal (score %.2f)", name, c.FlowID, c.Result.Class, c.Result.Score)
			}
		}
	}
}

func TestPipelineEmitsEvents(t *testing.T) {
	pf, err := capture.OpenPCAPFile(fixture("http.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	sub := bus.Subscribe(256)
	defer sub.Close()
	seen := map[events.Type]int{}
	done := make(chan struct{})
	go func() {
		for ev := range sub.C {
			seen[ev.Type]++
			if seen[events.ClassificationCreated] > 0 && seen[events.FlowClosed] > 0 {
				close(done)
				return
			}
		}
	}()

	store := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	if _, err := pipeline.Run(context.Background(), pf, rt, bus, store, pipeline.Options{
		Flow: flow.Options{IdleTimeout: time.Minute, MaxLifetime: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected FlowClosed + ClassificationCreated events, saw %v", seen)
	}
}
