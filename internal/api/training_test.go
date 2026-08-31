package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/training"
)

func trainingServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Training.Directory = dir
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	trs := training.Open(dir, audit.New(t.TempDir(), func(string, ...any) {}), func(string, ...any) {})
	return New(cfg, events.New(), storage.NewMem(100, 100), rt, nil, nil, nil, nil, nil, nil, nil, trs, nil, nil, nil).Handler()
}

func treq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func tdecode(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return m
}

func trun(t *testing.T, rr *httptest.ResponseRecorder) training.Run {
	t.Helper()
	var run training.Run
	if err := json.Unmarshal(rr.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run %q: %v", rr.Body.String(), err)
	}
	return run
}

func TestTrainingRegisterReturnsProgressURL(t *testing.T) {
	h := trainingServer(t)
	rr := treq(t, h, "POST", "/api/v1/training",
		`{"name":"nightly","epochs_total":10,"trainer_version":"0.1.0","recipe":{"name":"r","seed":7}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: code %d, body %s", rr.Code, rr.Body)
	}
	m := tdecode(t, rr)
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatal("no id in response")
	}
	pu, _ := m["progress_url"].(string)
	if !strings.HasSuffix(pu, "/api/v1/training/"+id+"/progress") {
		t.Fatalf("progress_url = %q", pu)
	}
}

func TestTrainingProgressThenGet(t *testing.T) {
	h := trainingServer(t)
	m := tdecode(t, treq(t, h, "POST", "/api/v1/training", `{"name":"r","epochs_total":3}`))
	id := m["id"].(string)
	pu := "/api/v1/training/" + id + "/progress"

	for i := 1; i <= 3; i++ {
		body := `{"event":"epoch","epoch":` + strconv.Itoa(i) + `,"train_loss":0.5,"val_loss":0.6,"val_accuracy":0.8,"lr":0.001}`
		rr := treq(t, h, "POST", pu, body)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("progress %d: code %d body %s", i, rr.Code, rr.Body)
		}
	}

	rr := treq(t, h, "GET", "/api/v1/training/"+id, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: code %d", rr.Code)
	}
	var run training.Run
	if err := json.Unmarshal(rr.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if run.Epoch != 3 || len(run.History) != 3 || run.Status != training.StatusRunning {
		t.Fatalf("run after 3 epochs: epoch=%d history=%d status=%q", run.Epoch, len(run.History), run.Status)
	}

	// A trailing newline (the trainer's JSON-line writer) is tolerated.
	rr = treq(t, h, "POST", pu, `{"event":"epoch","epoch":4,"train_loss":0.4}`+"\n")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("newline-terminated body: code %d body %s", rr.Code, rr.Body)
	}
}

func TestTrainingDoneMarksCompletedAndStoresFinal(t *testing.T) {
	h := trainingServer(t)
	id := tdecode(t, treq(t, h, "POST", "/api/v1/training", `{"name":"r","epochs_total":2}`))["id"].(string)
	pu := "/api/v1/training/" + id + "/progress"

	treq(t, h, "POST", pu, `{"event":"epoch","epoch":1,"train_loss":0.5,"val_loss":0.6}`)
	treq(t, h, "POST", pu, `{"event":"epoch","epoch":2,"train_loss":0.3,"val_loss":0.4}`)

	done := `{"event":"done","metrics":{"accuracy":0.97,"macro_f1":0.96,"macro_precision":0.95,` +
		`"macro_recall":0.97,"per_class":[{"class":"NORMAL","precision":1,"recall":1,"f1":1,"support":50}],` +
		`"confusion":[[7,0,0,0,0,0,0],[0,7,0,0,0,0,0],[0,0,7,0,0,0,0],[0,0,0,7,0,0,0],` +
		`[0,0,0,0,7,0,0],[0,0,0,0,0,7,0],[0,0,0,0,0,0,7]],"test":{"accuracy":0.95,"macro_f1":0.94}}}`
	rr := treq(t, h, "POST", pu, done)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("done: code %d body %s", rr.Code, rr.Body)
	}

	run := trun(t, treq(t, h, "GET", "/api/v1/training/"+id, ""))
	if run.Status != training.StatusCompleted {
		t.Fatalf("status = %q, want completed", run.Status)
	}
	if run.FinishedAt == "" {
		t.Fatal("FinishedAt empty")
	}
	var final map[string]any
	if err := json.Unmarshal(run.Final, &final); err != nil {
		t.Fatalf("final not JSON: %v", err)
	}
	if final["accuracy"].(float64) != 0.97 {
		t.Fatalf("final accuracy = %v", final["accuracy"])
	}
	if _, ok := final["confusion"]; !ok {
		t.Fatal("final missing confusion matrix")
	}

	// Progress after done is a 409.
	rr = treq(t, h, "POST", pu, `{"event":"epoch","epoch":3}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("progress after done: code %d, want 409", rr.Code)
	}
}

func TestTrainingFail(t *testing.T) {
	h := trainingServer(t)
	id := tdecode(t, treq(t, h, "POST", "/api/v1/training", `{"name":"r","epochs_total":2}`))["id"].(string)

	rr := treq(t, h, "POST", "/api/v1/training/"+id+"/fail", `{"reason":"cuda oom"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("fail: code %d body %s", rr.Code, rr.Body)
	}
	run := trun(t, treq(t, h, "GET", "/api/v1/training/"+id, ""))
	if run.Status != training.StatusFailed || run.FailReason != "cuda oom" {
		t.Fatalf("after fail: status=%q reason=%q", run.Status, run.FailReason)
	}
}

func TestTrainingNotFound(t *testing.T) {
	h := trainingServer(t)
	if rr := treq(t, h, "GET", "/api/v1/training/nope", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("GET unknown: code %d", rr.Code)
	}
	if rr := treq(t, h, "POST", "/api/v1/training/nope/progress", `{"event":"epoch","epoch":1}`); rr.Code != http.StatusNotFound {
		t.Fatalf("progress unknown: code %d", rr.Code)
	}
	if rr := treq(t, h, "POST", "/api/v1/training/nope/fail", `{"reason":"x"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("fail unknown: code %d", rr.Code)
	}
}

func TestTrainingListOrdering(t *testing.T) {
	h := trainingServer(t)
	var ids []string
	for _, name := range []string{"first", "second", "third"} {
		ids = append(ids, tdecode(t, treq(t, h, "POST", "/api/v1/training", `{"name":"`+name+`","epochs_total":1}`))["id"].(string))
	}
	rr := treq(t, h, "GET", "/api/v1/training", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: code %d", rr.Code)
	}
	var resp struct {
		Runs       []training.Run `json:"runs"`
		HistoryCap int            `json:"history_cap"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Runs) != 3 {
		t.Fatalf("list len = %d", len(resp.Runs))
	}
	// Newest first: the last created id is first.
	if resp.Runs[0].ID != ids[2] || resp.Runs[2].ID != ids[0] {
		t.Fatalf("list not newest-first: %s ... %s", resp.Runs[0].ID, resp.Runs[2].ID)
	}
	if resp.HistoryCap != training.HistoryCap {
		t.Fatalf("history_cap = %d", resp.HistoryCap)
	}
}

func TestTrainingRoutesUnavailableWithoutStore(t *testing.T) {
	// newTestServer wires a nil training store.
	h := newTestServer()
	if rr := treq(t, h, "GET", "/api/v1/training", ""); rr.Code != http.StatusOK {
		t.Fatalf("GET list without store should be 200 empty, got %d", rr.Code)
	}
	if rr := treq(t, h, "POST", "/api/v1/training", `{"name":"x"}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST without store: code %d, want 503", rr.Code)
	}
}
