package api

// The sensor= / location= scope over rows that now carry real attribution
// (issue #126). Before it, a raw-mode sensor's rows were labelled "local" and
// these filters could only ever return nothing for them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// scopedServer stores one flow + verdict per sensor: a raw-mode sensor on the
// wan, a flow-mode sensor in the dmz, and the daemon's own capture.
func scopedServer(t *testing.T) http.Handler {
	t.Helper()
	store := storage.NewMem(200, 200)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "opnsense-wan", Location: "cph-valby-gw01", State: capture.StateRunning, Mode: "raw"},
		{SensorID: "opnsense-dmz", Location: "cph-valby-gw01", State: capture.StateRunning, Mode: "flow"},
		{SensorID: "branch-1", Location: "aarhus", State: capture.StateRunning, Mode: "raw"},
	}}
	h := New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, nil, nil, sp, nil, nil).Handler()

	put := func(id uint64, sensor, mode string) {
		store.PutFlow(storage.FlowRecord{
			ID: id, Sensor: sensor, SensorMode: mode, Proto: "TCP",
			InitiatorIP: "87.54.62.131", ResponderIP: "10.0.0.9",
			Features: features.Vector{FlowID: id},
		})
		store.PutClassification(storage.Classification{
			FlowID: id, Sensor: sensor, Proto: "TCP",
			Result: inference.Result{FlowID: id, Class: "normal", Score: 0.9},
		})
	}
	put(1, "opnsense-wan", "")     // raw mode: built from packets, attributed on the packet path
	put(2, "opnsense-dmz", "flow") // record mode: attributed by the collector
	put(3, "local", "")            // the daemon's own capture
	return h
}

func scopedFlows(t *testing.T, h http.Handler, query string) (int, []storage.FlowRecord) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/flows"+query, nil))
	if rr.Code != http.StatusOK {
		return rr.Code, nil
	}
	var out []storage.FlowRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not a JSON array: %v (body %s)", err, rr.Body.String())
	}
	return rr.Code, out
}

func TestSensorScopeSelectsRawModeRows(t *testing.T) {
	h := scopedServer(t)

	// A raw-mode sensor is scopeable now: this returned nothing before #126.
	code, flows := scopedFlows(t, h, "?sensor=opnsense-wan")
	if code != http.StatusOK || len(flows) != 1 || flows[0].ID != 1 {
		t.Fatalf("sensor=opnsense-wan → %d, %+v; want flow 1", code, flows)
	}
	code, cls := getClassifications(t, h, "?sensor=opnsense-wan")
	if code != http.StatusOK || len(cls) != 1 || cls[0].FlowID != 1 {
		t.Fatalf("classifications sensor=opnsense-wan → %d, %+v", code, cls)
	}

	// The record-mode sensor keeps working, unchanged.
	if _, flows := scopedFlows(t, h, "?sensor=opnsense-dmz"); len(flows) != 1 || flows[0].ID != 2 {
		t.Errorf("sensor=opnsense-dmz → %+v; want flow 2", flows)
	}

	// "local" still means the daemon's own capture, and nothing else.
	if _, flows := scopedFlows(t, h, "?sensor="+LocalSensorLabel); len(flows) != 1 || flows[0].ID != 3 {
		t.Errorf("sensor=local → %+v; want only the locally-captured flow 3", flows)
	}

	// A sensor with no stored rows is an empty result, not an error: it may
	// simply have produced nothing yet.
	if code, flows := scopedFlows(t, h, "?sensor=branch-1"); code != http.StatusOK || len(flows) != 0 {
		t.Errorf("sensor=branch-1 → %d, %+v; want an empty 200", code, flows)
	}
}

func TestLocationScopeSpansItsSensors(t *testing.T) {
	h := scopedServer(t)

	// One location, two sensors, one of them raw: both must come back.
	code, flows := scopedFlows(t, h, "?location=cph-valby-gw01")
	if code != http.StatusOK || len(flows) != 2 {
		t.Fatalf("location=cph-valby-gw01 → %d, %+v; want both sensors' flows", code, flows)
	}
	got := map[string]bool{}
	for _, f := range flows {
		got[f.Sensor] = true
	}
	if !got["opnsense-wan"] || !got["opnsense-dmz"] {
		t.Errorf("location scope missed a sensor: %v", got)
	}

	// sensor= narrows within location= rather than widening it.
	if _, flows := scopedFlows(t, h, "?location=cph-valby-gw01&sensor=opnsense-wan"); len(flows) != 1 || flows[0].ID != 1 {
		t.Errorf("location+sensor → %+v; want just flow 1", flows)
	}
	// A disjoint pair selects nothing — an empty 200, not everything.
	if _, flows := scopedFlows(t, h, "?location=aarhus&sensor=opnsense-wan"); len(flows) != 0 {
		t.Errorf("disjoint location+sensor → %+v; want nothing", flows)
	}
	// A location nobody reports stays a 400 rather than a silently empty 200.
	if code, _ := scopedFlows(t, h, "?location=nowhere"); code != http.StatusBadRequest {
		t.Errorf("location=nowhere → %d, want 400", code)
	}
}

// A row stored without attribution — written by an embedder, or before #126 —
// still scopes through its verdict, so the fallback join is not dead code.
func TestSensorScopeFallsBackToTheVerdictJoin(t *testing.T) {
	store := storage.NewMem(200, 200)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	h := New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	store.PutFlow(storage.FlowRecord{ID: 7, Proto: "TCP", Features: features.Vector{FlowID: 7}})
	store.PutClassification(storage.Classification{
		FlowID: 7, Sensor: "legacy-sensor",
		Result: inference.Result{FlowID: 7, Class: "normal", Score: 0.9},
	})

	if _, flows := scopedFlows(t, h, "?sensor=legacy-sensor"); len(flows) != 1 || flows[0].ID != 7 {
		t.Errorf("an unattributed flow did not scope through its verdict: %+v", flows)
	}
	if _, flows := scopedFlows(t, h, "?sensor=someone-else"); len(flows) != 0 {
		t.Errorf("the fallback join matched the wrong sensor: %+v", flows)
	}
}

// An anonymous peer reported no id, so nothing can select its rows. The topology
// must say so rather than promise a scope that returns nothing.
func TestTopologyAnonymousSensorIsNotAttributable(t *testing.T) {
	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "", Location: "wan", State: capture.StateRunning, Mode: "raw", SourceName: "203.0.113.9:51000"},
		{SensorID: "edge-1", Location: "wan", State: capture.StateRunning, Mode: "raw"},
	}}
	got := getTopology(t, sp)
	if len(got.Locations) != 1 {
		t.Fatalf("want one location, got %+v", got.Locations)
	}
	wan := got.Locations[0]
	if wan.AttributableSensors != 1 {
		t.Errorf("attributable = %d, want 1 of 2 (the anonymous peer is not)", wan.AttributableSensors)
	}
	for _, s := range wan.Sensors {
		want := AttributionPackets
		if s.SensorID == "" {
			want = AttributionNone
		}
		if s.FlowAttribution != want {
			t.Errorf("sensor %q attribution = %q, want %q", s.SensorID, s.FlowAttribution, want)
		}
	}
	if got.AttributableSensors == 0 {
		t.Error("no sensor is attributable at all — the raw-mode sensor should be")
	}
}
