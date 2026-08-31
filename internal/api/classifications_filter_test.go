package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// seededServer builds an API handler over a store pre-loaded with four verdicts
// spanning the filterable dimensions of GET /api/v1/classifications.
func seededServer(t *testing.T) http.Handler {
	t.Helper()
	store := storage.NewMem(200, 200)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	h := New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	mk := func(flowID uint64, class string, classID int, score float64, disagree bool, modelIDs ...string) storage.Classification {
		var models []inference.ModelOutput
		for _, id := range modelIDs {
			models = append(models, inference.ModelOutput{
				ModelID: id, Class: class, ClassID: classID, Score: score,
			})
		}
		return storage.Classification{
			FlowID: flowID,
			Result: inference.Result{
				FlowID: flowID, Class: class, ClassID: classID, Score: score,
				Disagreement: disagree, Models: models,
			},
		}
	}
	store.PutClassification(mk(1, "normal", 0, 0.99, false, "heuristic-v1"))
	store.PutClassification(mk(2, "scan", 1, 0.80, true, "heuristic-v1", "global-v1"))
	store.PutClassification(mk(3, "scan", 1, 0.55, false, "heuristic-v1"))
	store.PutClassification(mk(4, "dos_ddos", 2, 0.91, true, "primary-v2"))
	return h
}

func getClassifications(t *testing.T, h http.Handler, query string) (int, []storage.Classification) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/classifications"+query, nil))
	if rr.Code != http.StatusOK {
		return rr.Code, nil
	}
	var out []storage.Classification
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not a JSON array: %v (body %s)", err, rr.Body.String())
	}
	return rr.Code, out
}

func TestClassificationsNoFilterUnchanged(t *testing.T) {
	h := seededServer(t)
	code, out := getClassifications(t, h, "")
	if code != http.StatusOK || len(out) != 4 {
		t.Fatalf("no-filter default should return all 4 newest, got code %d len %d", code, len(out))
	}
	if out[0].FlowID != 4 {
		t.Fatalf("newest-first order broken: first FlowID = %d", out[0].FlowID)
	}
}

func TestClassificationsDisagreementFilter(t *testing.T) {
	h := seededServer(t)
	code, out := getClassifications(t, h, "?disagreement=true")
	if code != http.StatusOK || len(out) != 2 {
		t.Fatalf("want 2 disagreement rows, got code %d len %d", code, len(out))
	}
	for _, c := range out {
		if !c.Result.Disagreement {
			t.Fatalf("row %d is not a disagreement", c.FlowID)
		}
	}
}

func TestClassificationsClassFilter(t *testing.T) {
	h := seededServer(t)
	code, out := getClassifications(t, h, "?class=scan")
	if code != http.StatusOK || len(out) != 2 {
		t.Fatalf("want 2 scan rows, got code %d len %d", code, len(out))
	}
	for _, c := range out {
		if c.Result.Class != "scan" {
			t.Fatalf("row %d class %q, want scan", c.FlowID, c.Result.Class)
		}
	}
}

func TestClassificationsClassFilterUnknown(t *testing.T) {
	h := seededServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/classifications?class=bogus", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown class must be 400, got %d", rr.Code)
	}
}

func TestClassificationsModelFilter(t *testing.T) {
	h := seededServer(t)

	code, out := getClassifications(t, h, "?model=global-v1")
	if code != http.StatusOK || len(out) != 1 || out[0].FlowID != 2 {
		t.Fatalf("model=global-v1 should match only flow 2, got code %d %+v", code, out)
	}

	code, out = getClassifications(t, h, "?model=heuristic-v1")
	if code != http.StatusOK || len(out) != 3 {
		t.Fatalf("model=heuristic-v1 should match 3 rows, got code %d len %d", code, len(out))
	}
}

func TestClassificationsMinConfidence(t *testing.T) {
	h := seededServer(t)

	// Fraction scale: scores >= 0.9 → flows 1 (0.99) and 4 (0.91).
	code, out := getClassifications(t, h, "?min_confidence=0.9")
	if code != http.StatusOK || len(out) != 2 {
		t.Fatalf("min_confidence=0.9 should match 2 rows, got code %d len %d", code, len(out))
	}

	// Percentage scale: the same threshold expressed 0..100.
	if _, outPct := getClassifications(t, h, "?min_confidence=90"); len(outPct) != 2 {
		t.Fatalf("min_confidence=90 (percent) should match the same 2 rows, got %d", len(outPct))
	}

	// Unparseable value → 400.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/classifications?min_confidence=abc", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("min_confidence=abc must be 400, got %d", rr.Code)
	}
}

func TestClassificationsCombinedFiltersRespectLimit(t *testing.T) {
	h := seededServer(t)

	code, out := getClassifications(t, h, "?class=scan&disagreement=true")
	if code != http.StatusOK || len(out) != 1 || out[0].FlowID != 2 {
		t.Fatalf("class=scan&disagreement=true should match only flow 2, got %+v", out)
	}

	code, out = getClassifications(t, h, "?disagreement=true&limit=1")
	if code != http.StatusOK || len(out) != 1 {
		t.Fatalf("limit must still cap filtered results, got code %d len %d", code, len(out))
	}
	if out[0].FlowID != 4 {
		t.Fatalf("filtered results must stay newest-first, got FlowID %d", out[0].FlowID)
	}
}
