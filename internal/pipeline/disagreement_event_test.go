package pipeline_test

import (
	"context"
	"sync"
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

// constModel is a stub Classifier that always predicts one fixed class.
type constModel struct {
	id   string
	role inference.Role
	top  int
}

func (c constModel) ID() string           { return c.id }
func (c constModel) Family() string       { return "flow-classifier-v1" }
func (c constModel) Role() inference.Role { return c.role }
func (c constModel) Classify(features.Vector) inference.Scores {
	var s inference.Scores
	s[c.top] = 1
	return s
}

// A two-model ensemble that disagrees must publish ModelDisagreementDetected
// events whose payload carries the full per-model breakdown, not just the
// combined verdict (PROJECT.md §12, §17).
func TestDisagreementEventCarriesPerModelOutputs(t *testing.T) {
	pf, err := capture.OpenPCAPFile(fixture("portscan.pcap"))
	if err != nil {
		t.Fatalf("open portscan.pcap: %v", err)
	}
	src := capture.NewReplay(pf, capture.SpeedMax)

	bus := events.New()
	sub := bus.Subscribe(4096)

	var mu sync.Mutex
	var events0 []storage.Classification
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.C {
			if ev.Type != events.ModelDisagreementDetected {
				continue
			}
			cl, ok := ev.Data.(storage.Classification)
			if !ok {
				t.Errorf("ModelDisagreementDetected data is %T, want storage.Classification", ev.Data)
				continue
			}
			mu.Lock()
			events0 = append(events0, cl)
			mu.Unlock()
		}
	}()

	store := storage.NewMem(2000, 2000)
	// Primary heuristic calls portscan flows "scan"; the shadow global model
	// always says "normal", so the two alert-driving models disagree on every
	// scan flow.
	rt := inference.NewRuntime(
		inference.NewHeuristic("primary-v1", inference.RolePrimary),
		constModel{id: "always-normal", role: inference.RoleGlobal, top: 0},
	)

	if _, err := pipeline.Run(context.Background(), src, rt, bus, store, pipeline.Options{
		Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
		Sensor: "test",
	}); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	sub.Close() // ends the range loop once buffered events drain
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(events0) == 0 {
		t.Fatal("expected at least one ModelDisagreementDetected event")
	}
	for _, cl := range events0 {
		if !cl.Result.Disagreement {
			t.Errorf("flow %d: event payload missing Disagreement flag", cl.FlowID)
		}
		if len(cl.Result.Models) < 2 {
			t.Fatalf("flow %d: disagreement event carries %d model outputs, want >= 2",
				cl.FlowID, len(cl.Result.Models))
		}
		ids := map[string]bool{}
		for _, m := range cl.Result.Models {
			ids[m.ModelID] = true
			var sum float64
			for _, p := range m.Scores {
				sum += p
			}
			if sum <= 0 {
				t.Errorf("flow %d model %s: empty 7-wide score vector in payload", cl.FlowID, m.ModelID)
			}
		}
		if !ids["primary-v1"] || !ids["always-normal"] {
			t.Errorf("flow %d: want both models in payload, got %v", cl.FlowID, ids)
		}
	}
}
