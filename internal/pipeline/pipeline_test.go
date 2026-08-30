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
