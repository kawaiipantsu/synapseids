package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

type stubCaptures struct{ rows []capture.SourceStatus }

func (s stubCaptures) List() []capture.SourceStatus { return s.rows }

func (s stubCaptures) Get(name string) (capture.SourceStatus, bool) {
	for _, r := range s.rows {
		if r.Name == name {
			return r, true
		}
	}
	return capture.SourceStatus{}, false
}

func serverWithCaptures(cp CaptureStatusProvider) http.Handler {
	return New(config.Default(), events.New(), storage.NewMem(100, 100),
		inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, cp).Handler()
}

func TestCapturesEmptyWithoutProvider(t *testing.T) {
	rr := httptest.NewRecorder()
	serverWithCaptures(nil).ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var got []capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not a JSON array: %v (%s)", err, rr.Body.String())
	}
	if len(got) != 0 {
		t.Fatalf("want empty list, got %v", got)
	}
}

func TestCapturesListFields(t *testing.T) {
	row := capture.SourceStatus{
		Name: "eth0", Kind: "nic", State: capture.StateRunning,
		Packets: 10, Decoded: 9, Bytes: 1200, Drops: 3,
		PPS: 5.5, BPS: 660, LastPacket: time.Unix(1700000000, 0).UTC(),
		Filter: "(all)",
	}
	rr := httptest.NewRecorder()
	serverWithCaptures(stubCaptures{rows: []capture.SourceStatus{row}}).
		ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var raw []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 row, got %d", len(raw))
	}
	// PROJECT.md §19.14 fields plus identity.
	for _, k := range []string{
		"name", "kind", "state", "packets", "bytes", "drops",
		"pps", "bps", "last_packet", "filter", "error", "connection_latency_ms",
	} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("row missing field %q: %v", k, raw[0])
		}
	}
}

func TestCaptureByName(t *testing.T) {
	h := serverWithCaptures(stubCaptures{rows: []capture.SourceStatus{
		{Name: "lo", Kind: "nic", State: capture.StateRunning},
	}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/lo", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("by-name code %d", rr.Code)
	}
	var one capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil || one.Name != "lo" {
		t.Fatalf("by-name body = %s (%v)", rr.Body.String(), err)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/missing", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing source should 404, got %d", rr.Code)
	}
}

func TestCaptureByNameWithoutProvider(t *testing.T) {
	rr := httptest.NewRecorder()
	serverWithCaptures(nil).ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/lo", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("no provider should 404 on by-name, got %d", rr.Code)
	}
}
