package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/workbench"
)

func TestWorkbenchReviewedCorpusRequiresHumanLabelsAndRetainedInputs(t *testing.T) {
	cfg := config.Default()
	cfg.Models.Directory = t.TempDir()
	st := storage.NewMem(100, 100)
	bus := events.New()
	aud := audit.New(t.TempDir(), quiet)
	rv := review.Open(t.TempDir(), st, bus, aud, quiet)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	s := New(cfg, bus, st, rt, nil, aud, nil, nil, nil, nil, nil, nil, nil, rv, nil)
	s.start = time.Now().Add(-time.Minute)
	q, err := workbench.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetWorkbench(q)
	states := []review.State{review.StateCorrect, review.StateIncorrect, review.StateUnsure, review.StateIgnoredPattern, review.StateCorrect}
	for i, state := range states {
		id := uint64(i + 1)
		st.PutClassification(rvVerdict(id, "scan", .9, rvScores(.1, .9), false))
		if i < 4 { // Last review has an aged-out flow, so no usable inputs.
			b := &features.BehaviorVector{Schema: features.BehaviorSchemaID}
			b.Values[0] = float64(id)
			st.PutFlow(storage.FlowRecord{ID: id, Behavior: b, Sensor: "private-observer", InitiatorIP: "192.0.2.1", ResponderIP: "198.51.100.1", FirstSeen: s.start})
		}
		label := ""
		if state == review.StateIncorrect {
			label = "normal"
		}
		if _, err := rv.Put(id, state, label, "private-analyst-note"); err != nil {
			t.Fatal(err)
		}
	}
	rr := rvWrite(t, s.Handler(), "POST", "/api/v1/workbench/reviews", "{}")
	if rr.Code != http.StatusCreated {
		t.Fatalf("export status %d: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		Corpus  workbench.Corpus `json:"corpus"`
		Skipped int              `json:"skipped"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Corpus.Rows != 2 || response.Skipped != 1 || response.Corpus.Classes["normal"] != 1 || response.Corpus.Classes["scan"] != 1 {
		t.Fatalf("unexpected label coverage: %+v", response)
	}
	raw, err := os.ReadFile(filepath.Join(q.Dir(), "corpora", response.Corpus.ID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-observer", "private-analyst-note", "192.0.2.1", "198.51.100.1", "predicted_class"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("private context appeared in numeric export: %s", private)
		}
	}
	// Reused numeric flow IDs after a daemon restart cannot attach old reviews
	// to new traffic and silently create incorrect training truth.
	s.start = time.Now().Add(time.Second)
	rr = rvWrite(t, s.Handler(), "POST", "/api/v1/workbench/reviews", "{}")
	if rr.Code != http.StatusConflict {
		t.Fatalf("prior-session reviews exported: %d", rr.Code)
	}
}
