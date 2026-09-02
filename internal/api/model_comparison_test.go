package api

// GET /api/v1/models/comparison (issue #48): the read-side fold of every model's
// per-flow output the runtime already records on each Classification.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var cmpBase = time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)

func cmpModelOutput(id string, role inference.Role, classID int, score float64) inference.ModelOutput {
	var sc inference.Scores
	sc[classID] = score
	return inference.ModelOutput{
		ModelID: id, Role: role,
		Class: className(classID), ClassID: classID, Score: score, Scores: sc,
	}
}

func className(i int) string {
	// tiny local mirror so the test does not import internal/schema
	return []string{"normal", "scan", "dos_ddos", "brute_force", "botnet_c2", "web_attack", "suspicious"}[i]
}

func comparisonServer(t *testing.T) http.Handler {
	t.Helper()
	store := storage.NewMem(100, 100)

	put := func(flowID uint64, at time.Time, disagree bool, outs ...inference.ModelOutput) {
		store.PutClassification(storage.Classification{
			FlowID: flowID, TS: at, Sensor: "local", Proto: "tcp",
			Result: inference.Result{
				FlowID: flowID, Class: outs[0].Class, ClassID: outs[0].ClassID, Score: outs[0].Score,
				Disagreement: disagree, Models: outs,
			},
		})
	}

	// flow 1: both say normal — agreement.
	put(1, cmpBase.Add(1*time.Second), false,
		cmpModelOutput("heuristic-v1", inference.RolePrimary, 0, 0.90),
		cmpModelOutput("shadow-v2", inference.RoleExperimental, 0, 0.80))
	// flow 2: primary says scan, shadow says normal — disagreement.
	put(2, cmpBase.Add(2*time.Second), true,
		cmpModelOutput("heuristic-v1", inference.RolePrimary, 1, 0.95),
		cmpModelOutput("shadow-v2", inference.RoleExperimental, 0, 0.60))
	// flow 3: only the primary scored it — not comparable.
	put(3, cmpBase.Add(3*time.Second), false,
		cmpModelOutput("heuristic-v1", inference.RolePrimary, 0, 0.70))

	cfg := config.Default()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	return New(cfg, events.New(), store, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()
}

func TestModelComparison(t *testing.T) {
	h := comparisonServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/models/comparison", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Window struct {
			Scanned, Matched int
			Truncated        bool
		}
		Classes          []string
		FlowsCompared    int     `json:"flows_compared"`
		SingleModelRows  int     `json:"single_model_rows"`
		DisagreementRate float64 `json:"disagreement_rate"`
		Models           []struct {
			ModelID           string `json:"model_id"`
			Role              string
			Rows              int
			MeanConfidence    float64        `json:"mean_confidence"`
			ClassDistribution map[string]int `json:"class_distribution"`
		}
		Pairs []struct {
			A, B                   string
			BothScored             int `json:"both_scored"`
			Agree, Disagree        int
			AgreementRate          float64 `json:"agreement_rate"`
			MeanAbsConfidenceDelta float64 `json:"mean_abs_confidence_delta"`
			ClassMatrix            [][]int `json:"class_matrix"`
		}
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, rr.Body.String())
	}

	if body.Window.Matched != 3 {
		t.Fatalf("matched = %d, want 3", body.Window.Matched)
	}
	if body.FlowsCompared != 2 || body.SingleModelRows != 1 {
		t.Fatalf("flows_compared=%d single_model_rows=%d, want 2/1", body.FlowsCompared, body.SingleModelRows)
	}
	if got, want := body.DisagreementRate, 1.0/3.0; got < want-1e-9 || got > want+1e-9 {
		t.Fatalf("disagreement_rate = %v, want ~0.333", got)
	}
	if len(body.Classes) != 7 {
		t.Fatalf("classes = %v", body.Classes)
	}

	byID := map[string]int{}
	for i, m := range body.Models {
		byID[m.ModelID] = i
	}
	if len(body.Models) != 2 {
		t.Fatalf("models = %+v, want 2", body.Models)
	}
	// primary sorts first.
	if body.Models[0].ModelID != "heuristic-v1" {
		t.Fatalf("first model = %s, want heuristic-v1 (primary sorts first)", body.Models[0].ModelID)
	}
	hp := body.Models[byID["heuristic-v1"]]
	if hp.Rows != 3 || hp.ClassDistribution["normal"] != 2 || hp.ClassDistribution["scan"] != 1 {
		t.Fatalf("heuristic-v1 model summary = %+v", hp)
	}
	sh := body.Models[byID["shadow-v2"]]
	if sh.Rows != 2 {
		t.Fatalf("shadow-v2 rows = %d, want 2", sh.Rows)
	}

	if len(body.Pairs) != 1 {
		t.Fatalf("pairs = %+v, want 1", body.Pairs)
	}
	p := body.Pairs[0]
	if p.A != "heuristic-v1" || p.B != "shadow-v2" {
		t.Fatalf("pair = %s/%s", p.A, p.B)
	}
	if p.BothScored != 2 || p.Agree != 1 || p.Disagree != 1 {
		t.Fatalf("pair counts = both=%d agree=%d disagree=%d, want 2/1/1", p.BothScored, p.Agree, p.Disagree)
	}
	if p.AgreementRate != 0.5 {
		t.Fatalf("agreement_rate = %v, want 0.5", p.AgreementRate)
	}
	// flow 1: |0.90-0.80| = 0.10; flow 2: |0.95-0.60| = 0.35; mean = 0.225.
	if got := p.MeanAbsConfidenceDelta; got < 0.225-1e-9 || got > 0.225+1e-9 {
		t.Fatalf("mean_abs_confidence_delta = %v, want 0.225", got)
	}
	if len(p.ClassMatrix) != 7 || len(p.ClassMatrix[0]) != 7 {
		t.Fatalf("class_matrix shape = %dx%d", len(p.ClassMatrix), len(p.ClassMatrix[0]))
	}
	// flow 1: a=normal(0), b=normal(0). flow 2: a=scan(1), b=normal(0).
	if p.ClassMatrix[0][0] != 1 || p.ClassMatrix[1][0] != 1 {
		t.Fatalf("class_matrix = %v, want [0][0]=1 and [1][0]=1", p.ClassMatrix)
	}
}

func TestModelComparisonTimeAndClassFilters(t *testing.T) {
	h := comparisonServer(t)

	// from= excludes flow 1 (t+1s); class=scan keeps only flow 2.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/models/comparison?class=scan", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Window struct{ Matched int }
		Pairs  []struct {
			BothScored int `json:"both_scored"`
		}
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Window.Matched != 1 {
		t.Fatalf("class=scan matched = %d, want 1", body.Window.Matched)
	}

	// A bad time bound is a 400, not a silent empty answer.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/models/comparison?from=not-a-time", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad from= status = %d, want 400", rr.Code)
	}
}
