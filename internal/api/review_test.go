package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// The /api/v1/review* routes (PROJECT.md §16; issues #42, #64).

var rvBase = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

func rvScores(v ...float64) inference.Scores {
	var s inference.Scores
	for i := range v {
		if i < len(s) {
			s[i] = v[i]
		}
	}
	return s
}

func rvVerdict(id uint64, class string, score float64, sc inference.Scores, disagree bool) storage.Classification {
	return storage.Classification{
		FlowID:        id,
		TS:            rvBase.Add(time.Duration(id) * time.Second),
		Sensor:        "local",
		Proto:         "TCP",
		InitiatorIP:   "10.0.0.5",
		InitiatorPort: 40000 + uint16(id%1000), //nolint:gosec // small test ids
		ResponderIP:   "10.0.0.9",
		ResponderPort: 3306,
		Result: inference.Result{
			FlowID: id, Class: class, Score: score, Disagreement: disagree,
			Models: []inference.ModelOutput{
				{ModelID: "heuristic-v1", Role: inference.RolePrimary, Class: class, Score: score, Scores: sc},
			},
		},
	}
}

// reviewServer wires a real review store over a temp directory plus a store
// holding four verdicts with known probability vectors:
//
//	10  normal 0.99/0.01  margin 0.98  confident
//	20  normal 0.51/0.49  margin 0.02  near-tie
//	30  scan   0.20/0.70  margin 0.50  middling, ensemble disagreement
//	40  normal uniform    margin 0.00  no idea
func reviewServer(t *testing.T) (http.Handler, *events.Bus, string) {
	t.Helper()
	cfg := config.Default()
	auditDir := t.TempDir()
	cfg.Models.Directory = auditDir

	st := storage.NewMem(100, 100)
	u := 1.0 / 7.0
	for _, c := range []storage.Classification{
		rvVerdict(10, "normal", 0.99, rvScores(0.99, 0.01), false),
		rvVerdict(20, "normal", 0.51, rvScores(0.51, 0.49), false),
		rvVerdict(30, "scan", 0.70, rvScores(0.20, 0.70, 0.10), true),
		rvVerdict(40, "normal", u, rvScores(u, u, u, u, u, u, u), false),
	} {
		st.PutClassification(c)
	}

	bus := events.New()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	rv := review.Open(t.TempDir(), st, bus, audit.New(auditDir, quiet), quiet)
	h := New(cfg, bus, st, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, rv).Handler()
	return h, bus, auditDir
}

func rvGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	return rr
}

func rvWrite(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func rvDecode(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rr.Code, rr.Body.String())
	}
	return m
}

// readAuditLog returns the whole audit log written under dir.
func readAuditLog(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, audit.FileName)) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	return string(b)
}

// queueIDs pulls the flow ids out of a queue response, in order.
func queueIDs(t *testing.T, rr *httptest.ResponseRecorder) []uint64 {
	t.Helper()
	body := rvDecode(t, rr)
	raw, ok := body["queue"].([]any)
	if !ok {
		t.Fatalf("response has no queue array: %s", rr.Body.String())
	}
	out := make([]uint64, 0, len(raw))
	for _, it := range raw {
		m, ok := it.(map[string]any)
		if !ok {
			t.Fatalf("queue item is %T", it)
		}
		f, ok := m["flow_id"].(float64)
		if !ok {
			t.Fatalf("queue item has no flow_id: %v", m)
		}
		out = append(out, uint64(f))
	}
	return out
}

func eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- the queue ------------------------------------------------------------

func TestReviewQueueSortUncertainty(t *testing.T) {
	h, _, _ := reviewServer(t)

	rr := rvGet(t, h, "/api/v1/review/queue?sort=uncertainty")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	want := []uint64{40, 20, 30, 10} // margin 0.00, 0.02, 0.50, 0.98
	if got := queueIDs(t, rr); !eq(got, want) {
		t.Fatalf("queue order = %v, want %v (least-confident first)", got, want)
	}

	body := rvDecode(t, rr)
	if body["sort"] != "uncertainty" {
		t.Errorf("sort echo = %v", body["sort"])
	}
	items := body["queue"].([]any)
	first := items[0].(map[string]any)
	for _, k := range []string{"margin", "uncertainty", "entropy", "top1", "top2", "predicted_class", "predicted_score", "model_id", "review_state", "scores"} {
		if _, ok := first[k]; !ok {
			t.Errorf("queue item is missing %q: %v", k, first)
		}
	}
	if _, ok := body["ranking"]; !ok {
		t.Error("the queue response should document the ranking formula")
	}
	if _, ok := body["vocabulary"]; !ok {
		t.Error("the queue response should carry the state/class/sort vocabulary")
	}
}

func TestReviewQueueSortDisagreementAndRecent(t *testing.T) {
	h, _, _ := reviewServer(t)

	// Only flow 30 disagrees, so it leads; the rest fall back to margin order.
	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?sort=disagreement")); !eq(got, []uint64{30, 40, 20, 10}) {
		t.Errorf("disagreement order = %v, want 30 first", got)
	}
	// Default and explicit recent are newest first.
	want := []uint64{40, 30, 20, 10}
	for _, p := range []string{"/api/v1/review/queue", "/api/v1/review/queue?sort=recent"} {
		if got := queueIDs(t, rvGet(t, h, p)); !eq(got, want) {
			t.Errorf("%s = %v, want %v", p, got, want)
		}
	}
}

func TestReviewQueueBadSort(t *testing.T) {
	h, _, _ := reviewServer(t)
	rr := rvGet(t, h, "/api/v1/review/queue?sort=margin")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rr.Code)
	}
	for _, want := range []string{"uncertainty", "recent", "disagreement"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("the 400 should echo the valid sorts, got %q", rr.Body.String())
		}
	}
}

// TestReviewQueueReusesClassFilters proves class/model/min_confidence/
// disagreement mean the same thing here as on /api/v1/classifications.
func TestReviewQueueReusesClassFilters(t *testing.T) {
	h, _, _ := reviewServer(t)

	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?disagreement=true")); !eq(got, []uint64{30}) {
		t.Errorf("disagreement=true = %v, want just flow 30", got)
	}
	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?min_confidence=0.9")); !eq(got, []uint64{10}) {
		t.Errorf("min_confidence=0.9 = %v, want just flow 10", got)
	}
	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?class=scan")); !eq(got, []uint64{30}) {
		t.Errorf("class=scan = %v, want just flow 30", got)
	}
	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?model=heuristic-v1&limit=2&sort=uncertainty")); !eq(got, []uint64{40, 20}) {
		t.Errorf("model+limit = %v", got)
	}
	if got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?model=nope")); len(got) != 0 {
		t.Errorf("unknown model = %v, want empty", got)
	}
	if rr := rvGet(t, h, "/api/v1/review/queue?class=not_a_class"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad class → %d, want 400", rr.Code)
	}
	if rr := rvGet(t, h, "/api/v1/review/queue?min_confidence=-1"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad min_confidence → %d, want 400", rr.Code)
	}
}

// TestReviewQueueDropsTerminalStates is the §16 exclusion rule over HTTP.
func TestReviewQueueDropsTerminalStates(t *testing.T) {
	h, _, _ := reviewServer(t)

	if rr := rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"correct"}`); rr.Code != http.StatusCreated {
		t.Fatalf("review flow 10 → %d: %s", rr.Code, rr.Body.String())
	}
	if rr := rvWrite(t, h, "PUT", "/api/v1/review/20", `{"state":"unsure","note":"could be either"}`); rr.Code != http.StatusCreated {
		t.Fatalf("review flow 20 → %d: %s", rr.Code, rr.Body.String())
	}
	if rr := rvWrite(t, h, "PUT", "/api/v1/review/30", `{"state":"ignored_pattern"}`); rr.Code != http.StatusCreated {
		t.Fatalf("review flow 30 → %d: %s", rr.Code, rr.Body.String())
	}

	got := queueIDs(t, rvGet(t, h, "/api/v1/review/queue?sort=recent"))
	if !eq(got, []uint64{40, 20}) {
		t.Fatalf("queue = %v, want the unreviewed (40) and unsure (20) flows only", got)
	}
}

// ---- the write route ------------------------------------------------------

func TestReviewWriteCreatesThenUpdates(t *testing.T) {
	h, bus, auditDir := reviewServer(t)
	sub := bus.Subscribe(8)
	defer sub.Close()

	rr := rvWrite(t, h, "PUT", "/api/v1/review/20", `{"state":"correct","note":"ordinary browsing"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("first review → %d, want 201: %s", rr.Code, rr.Body.String())
	}
	rec := rvDecode(t, rr)["review"].(map[string]any)
	if rec["state"] != "correct" {
		t.Errorf("state = %v", rec["state"])
	}
	if rec["predicted_class"] != "normal" {
		t.Errorf("predicted_class = %v, want normal", rec["predicted_class"])
	}
	if rec["effective_label"] != "normal" {
		t.Errorf("effective_label = %v, want the confirmed prediction", rec["effective_label"])
	}
	if rec["reviewer"] != audit.ActorLocal {
		t.Errorf("reviewer = %v, want %q", rec["reviewer"], audit.ActorLocal)
	}

	// A second write is a correction: 200, not 201.
	rr = rvWrite(t, h, "POST", "/api/v1/review/20", `{"state":"incorrect","human_label":"brute_force","note":"mysql hammering"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("correction → %d, want 200: %s", rr.Code, rr.Body.String())
	}
	rec = rvDecode(t, rr)["review"].(map[string]any)
	if rec["human_label"] != "brute_force" {
		t.Errorf("human_label = %v", rec["human_label"])
	}
	// The §16 invariant, on the wire: the prediction is still there, untouched.
	if rec["predicted_class"] != "normal" {
		t.Errorf("predicted_class = %v after a correction — it must never change", rec["predicted_class"])
	}
	if score, _ := rec["predicted_score"].(float64); score != 0.51 {
		t.Errorf("predicted_score = %v, want 0.51", rec["predicted_score"])
	}
	if rec["model_id"] != "heuristic-v1" {
		t.Errorf("model_id = %v", rec["model_id"])
	}
	hist, ok := rec["history"].([]any)
	if !ok || len(hist) != 1 {
		t.Fatalf("history = %v, want one superseded decision", rec["history"])
	}

	// ReviewUpdated on the bus, twice.
	for i := 0; i < 2; i++ {
		select {
		case ev := <-sub.C:
			if ev.Type != events.ReviewUpdated {
				t.Fatalf("event %d type = %q, want ReviewUpdated", i, ev.Type)
			}
		case <-time.After(time.Second):
			t.Fatalf("only %d ReviewUpdated event(s) published", i)
		}
	}

	// And two audit lines.
	lines := strings.Split(strings.TrimSpace(readAuditLog(t, auditDir)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log has %d line(s), want 2:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	var last audit.Record
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatalf("parse audit line: %v", err)
	}
	if last.Event != audit.EventReviewUpdated || last.SubjectType != audit.SubjectReview || last.Subject != "20" {
		t.Errorf("audit record = %+v", last)
	}
}

func TestReviewWriteBadState(t *testing.T) {
	h, _, _ := reviewServer(t)
	rr := rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"probably_fine"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	for _, want := range []string{"unreviewed", "correct", "incorrect", "unsure", "ignored_pattern"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("the 400 must echo the valid states; %q is missing from %q", want, rr.Body.String())
		}
	}
}

func TestReviewWriteBadLabel(t *testing.T) {
	h, _, _ := reviewServer(t)
	rr := rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"incorrect","human_label":"very_bad_traffic"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	for _, want := range []string{"traffic-classes-v1", "brute_force", "web_attack"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("the 400 must echo the valid classes; %q is missing from %q", want, rr.Body.String())
		}
	}
}

func TestReviewWriteIncorrectWithoutALabel(t *testing.T) {
	h, _, _ := reviewServer(t)
	rr := rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"incorrect"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "requires human_label") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

// TestReviewWriteEvictedFlowIs404: you cannot review a flow the bounded ring has
// already forgotten, and the error has to say why.
func TestReviewWriteEvictedFlowIs404(t *testing.T) {
	h, _, _ := reviewServer(t)
	rr := rvWrite(t, h, "PUT", "/api/v1/review/99999", `{"state":"unsure"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "evicted") {
		t.Errorf("the 404 must explain eviction, got %q", rr.Body.String())
	}
}

// TestReviewWriteRejectsAPredictionField: there is no wire field that could
// overwrite the model's claim, and sending one is an error rather than a silent
// no-op (DisallowUnknownFields).
func TestReviewWriteRejectsAPredictionField(t *testing.T) {
	h, _, _ := reviewServer(t)
	for _, body := range []string{
		`{"state":"correct","predicted_class":"scan"}`,
		`{"state":"correct","predicted_score":0.1}`,
		`{"state":"correct","model_id":"forged"}`,
	} {
		rr := rvWrite(t, h, "PUT", "/api/v1/review/10", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s → %d, want 400 (unknown field)", body, rr.Code)
		}
	}
	// And the flow is still unreviewed.
	if rr := rvGet(t, h, "/api/v1/review/10"); rr.Code != http.StatusNotFound {
		t.Errorf("flow 10 was reviewed by a rejected request (%d)", rr.Code)
	}
}

func TestReviewWriteBadFlowID(t *testing.T) {
	h, _, _ := reviewServer(t)
	for _, p := range []string{"/api/v1/review/abc", "/api/v1/review/0", "/api/v1/review/-3"} {
		if rr := rvWrite(t, h, "PUT", p, `{"state":"unsure"}`); rr.Code != http.StatusBadRequest {
			t.Errorf("PUT %s → %d, want 400", p, rr.Code)
		}
	}
}

// ---- read routes ----------------------------------------------------------

func TestReviewGetOne(t *testing.T) {
	h, _, _ := reviewServer(t)
	if rr := rvGet(t, h, "/api/v1/review/10"); rr.Code != http.StatusNotFound {
		t.Fatalf("unreviewed flow → %d, want 404", rr.Code)
	}
	rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"correct","note":"fine"}`)

	rr := rvGet(t, h, "/api/v1/review/10")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	rec := rvDecode(t, rr)["review"].(map[string]any)
	if rec["flow_id"].(float64) != 10 || rec["state"] != "correct" || rec["predicted_class"] != "normal" {
		t.Errorf("review = %v", rec)
	}
	if rr := rvGet(t, h, "/api/v1/review/nope"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad id → %d, want 400", rr.Code)
	}
}

func TestReviewList(t *testing.T) {
	h, _, _ := reviewServer(t)
	rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"correct"}`)
	rvWrite(t, h, "PUT", "/api/v1/review/20", `{"state":"incorrect","human_label":"brute_force"}`)
	rvWrite(t, h, "PUT", "/api/v1/review/30", `{"state":"unsure"}`)

	rr := rvGet(t, h, "/api/v1/review")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	body := rvDecode(t, rr)
	if got := len(body["reviews"].([]any)); got != 3 {
		t.Errorf("reviews = %d, want 3", got)
	}
	if _, ok := body["stats"]; !ok {
		t.Error("the list response should carry the stats strip")
	}

	rr = rvGet(t, h, "/api/v1/review?state=unsure")
	rows := rvDecode(t, rr)["reviews"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["flow_id"].(float64) != 30 {
		t.Errorf("state=unsure = %v, want just flow 30", rows)
	}

	if rr := rvGet(t, h, "/api/v1/review?state=maybe"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad state → %d, want 400", rr.Code)
	}
}

func TestReviewStats(t *testing.T) {
	h, _, _ := reviewServer(t)
	rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"correct"}`)
	rvWrite(t, h, "PUT", "/api/v1/review/20", `{"state":"incorrect","human_label":"brute_force"}`)
	rvWrite(t, h, "PUT", "/api/v1/review/30", `{"state":"unsure"}`)

	rr := rvGet(t, h, "/api/v1/review/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	stats := rvDecode(t, rr)["stats"].(map[string]any)
	if stats["total"].(float64) != 3 {
		t.Errorf("total = %v, want 3", stats["total"])
	}
	byState := stats["by_state"].(map[string]any)
	if len(byState) != 5 {
		t.Errorf("by_state has %d keys, want all five states", len(byState))
	}
	for k, want := range map[string]float64{"correct": 1, "incorrect": 1, "unsure": 1, "ignored_pattern": 0, "unreviewed": 0} {
		if byState[k].(float64) != want {
			t.Errorf("by_state[%s] = %v, want %v", k, byState[k], want)
		}
	}
	if stats["terminal"].(float64) != 2 || stats["open"].(float64) != 1 {
		t.Errorf("terminal/open = %v/%v, want 2/1", stats["terminal"], stats["open"])
	}
}

// TestReviewRoutesWithoutAStoreAre503 — the routes must degrade, not panic.
func TestReviewRoutesWithoutAStoreAre503(t *testing.T) {
	h := newTestServer()
	for _, p := range []string{"/api/v1/review", "/api/v1/review/queue", "/api/v1/review/stats", "/api/v1/review/10"} {
		if rr := rvGet(t, h, p); rr.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s → %d, want 503", p, rr.Code)
		}
	}
	if rr := rvWrite(t, h, "PUT", "/api/v1/review/10", `{"state":"unsure"}`); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("PUT → %d, want 503", rr.Code)
	}
}

// TestQueueLiteralRoutesBeatTheWildcard: /queue and /stats must not be parsed as
// flow ids.
func TestQueueLiteralRoutesBeatTheWildcard(t *testing.T) {
	h, _, _ := reviewServer(t)
	for _, p := range []string{"/api/v1/review/queue", "/api/v1/review/stats"} {
		rr := rvGet(t, h, p)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s → %d, want 200 (the literal route must win)", p, rr.Code)
		}
	}
}
