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

type fakeSensors struct{ rows []capture.SensorStatus }

func (f fakeSensors) Sensors() []capture.SensorStatus { return f.rows }
func (f fakeSensors) Sensor(id string) (capture.SensorStatus, bool) {
	for _, r := range f.rows {
		if r.SensorID == id {
			return r, true
		}
	}
	return capture.SensorStatus{}, false
}

func sensorHandler(sp SensorStatusProvider) http.Handler {
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	return New(config.Default(), events.New(), storage.NewMem(10, 10), rt,
		nil, nil, nil, nil, nil, nil, nil, nil, sp).Handler()
}

func TestSensorsEmptyWithoutProvider(t *testing.T) {
	rr := httptest.NewRecorder()
	sensorHandler(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sensors", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var got []capture.SensorStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", rr.Body.String(), err)
	}
	if len(got) != 0 {
		t.Fatalf("want [], got %+v", got)
	}
	// 404 for a specific id with no provider.
	rr = httptest.NewRecorder()
	sensorHandler(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/x", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for /sensors/x, got %d", rr.Code)
	}
}

func TestSensorsListAndByID(t *testing.T) {
	now := time.Now().UTC()
	sp := fakeSensors{rows: []capture.SensorStatus{{
		SensorID: "edge-1", Location: "wan", RemoteAddr: "203.0.113.9:51000",
		LinkType: 1, Filter: "wan ip", ConnectedAt: now,
		Packets: 42, Bytes: 9000, Drops: 1, PPS: 3.5, BPS: 700,
		LastPacket: now, State: "running", AgentVersion: "0.1.0", OSArch: "freebsd/amd64",
		SessionID: "edge-1|wan-abc", SourceName: "edge-1",
	}}}
	h := sensorHandler(sp)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sensors", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 sensor, got %d", len(list))
	}
	for _, k := range []string{"sensor_id", "location", "remote_addr", "link_type", "filter", "connected_at", "packets", "bytes", "drops", "pps", "bps", "last_packet", "state"} {
		if _, ok := list[0][k]; !ok {
			t.Errorf("field %q missing from /api/v1/sensors row", k)
		}
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/edge-1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("by-id status %d", rr.Code)
	}
	var one capture.SensorStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.SensorID != "edge-1" || one.Location != "wan" || one.Packets != 42 {
		t.Fatalf("by-id row wrong: %+v", one)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown id, got %d", rr.Code)
	}
}
