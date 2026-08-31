package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func newTestServer() http.Handler {
	cfg := config.Default()
	bus := events.New()
	store := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	return New(cfg, bus, store, rt, nil, nil, nil, nil, nil, nil).Handler()
}

type stubFlowStats struct{ fs FlowStats }

func (s stubFlowStats) FlowStats() FlowStats { return s.fs }

func TestStatusEndpoint(t *testing.T) {
	h := newTestServer()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status code %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("status not JSON: %v", err)
	}
	if body["feature_schema"] != "flow-features-v1" {
		t.Fatalf("feature_schema = %v", body["feature_schema"])
	}
	if body["loopback"] != true {
		t.Fatalf("default config should report loopback=true")
	}

	live, ok := body["live"].(map[string]any)
	if !ok {
		t.Fatalf("status payload has no live object: %v", body["live"])
	}
	for _, k := range []string{"ws_clients", "ws_client_drops", "ws_frames_batched"} {
		if _, present := live[k]; !present {
			t.Fatalf("live.%s missing from status payload: %v", k, live)
		}
	}

	// The flow object is always present; with no provider it reports zeroes and
	// the configured cap (PROJECT.md §22, §24).
	fl, ok := body["flow"].(map[string]any)
	if !ok {
		t.Fatalf("status has no flow object: %v", body["flow"])
	}
	for _, k := range []string{"active", "started", "closed", "snapshots", "evicted", "max"} {
		if _, present := fl[k]; !present {
			t.Fatalf("flow object missing %q: %v", k, fl)
		}
	}
	if fl["max"].(float64) != float64(config.Default().Capture.MaxFlows) {
		t.Fatalf("flow.max = %v, want %d", fl["max"], config.Default().Capture.MaxFlows)
	}
}

func TestStatusFlowObjectFromProvider(t *testing.T) {
	cfg := config.Default()
	bus := events.New()
	store := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	want := FlowStats{Active: 7, Started: 20, Closed: 13, Snapshots: 2, Evicted: 5, Max: 3}
	h := New(cfg, bus, store, rt, nil, nil, nil, stubFlowStats{want}, nil, nil).Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status code %d", rr.Code)
	}
	var body struct {
		Flow FlowStats `json:"flow"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("status not JSON: %v", err)
	}
	if body.Flow != want {
		t.Fatalf("flow = %+v, want %+v", body.Flow, want)
	}
}

func TestSchemaEndpoints(t *testing.T) {
	h := newTestServer()
	for _, path := range []string{"/api/v1/schemas/features", "/api/v1/schemas/classes"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "frozen") {
			t.Fatalf("%s: code %d body %.60s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestFlowsAndClassificationsEmpty(t *testing.T) {
	h := newTestServer()
	for _, path := range []string{"/api/v1/flows", "/api/v1/classifications", "/api/v1/models"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: %d", path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/flows/999", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing flow should 404, got %d", rr.Code)
	}
}

func TestReplayEndpointsWithoutController(t *testing.T) {
	h := newTestServer() // rc == nil
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/replay", strings.NewReader(`{"path":"x"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no controller should be 503, got %d", rr.Code)
	}
}

func TestIndexServed(t *testing.T) {
	h := newTestServer()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "SynapseIDS") {
		t.Fatalf("built-in web page not served: %d", rr.Code)
	}
}
