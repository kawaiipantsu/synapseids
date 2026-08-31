package inference

import (
	"sync"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

// TestActivateSwapsModelSet checks Activate replaces the whole model set with a
// single trained primary, and Deactivate restores the NewRuntime fallback.
func TestActivateSwapsModelSet(t *testing.T) {
	heur := NewHeuristic("heuristic-v1", RolePrimary)
	rt := NewRuntime(heur)

	if got := rt.Models(); len(got) != 1 || got[0].ID() != "heuristic-v1" {
		t.Fatalf("initial models = %v", got)
	}

	trained := constModel{id: "onnx-1", role: RolePrimary, class: classScan}
	rt.Activate(trained)

	got := rt.Models()
	if len(got) != 1 || got[0].ID() != "onnx-1" {
		t.Fatalf("after Activate models = %v", got)
	}
	if res := rt.Score(zeroVec(1)); res.Class != "scan" {
		t.Fatalf("after Activate the verdict should come from onnx-1 (scan), got %s", res.Class)
	}

	rt.Deactivate()
	got = rt.Models()
	if len(got) != 1 || got[0].ID() != "heuristic-v1" {
		t.Fatalf("after Deactivate models = %v", got)
	}
	if res := rt.Score(zeroVec(2)); res.Class != "normal" {
		t.Fatalf("after Deactivate the heuristic (normal on an empty vector) should drive, got %s", res.Class)
	}
}

// TestActivateAtomicUnderRace hammers Score from many goroutines while another
// goroutine churns Activate/Deactivate/SetModels. Under -race this must never
// panic, never observe a nil model, and always return a non-empty verdict — the
// swap is a whole-slice replacement, never an in-place edit.
func TestActivateAtomicUnderRace(t *testing.T) {
	rt := NewRuntime(NewHeuristic("heuristic-v1", RolePrimary))

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var v features.Vector
			for {
				select {
				case <-stop:
					return
				default:
				}
				res := rt.Score(v)
				if res.Class == "" || len(res.Models) == 0 {
					t.Errorf("Score returned an empty result during a swap: %+v", res)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		models := []Classifier{
			constModel{id: "a", role: RolePrimary, class: classScan},
			constModel{id: "b", role: RolePrimary, class: classDoS},
		}
		for i := 0; i < 4000; i++ {
			switch i % 3 {
			case 0:
				rt.Activate(models[i%2])
			case 1:
				rt.Deactivate()
			case 2:
				rt.SetModels(models...)
			}
		}
		close(stop)
	}()

	wg.Wait()
}
