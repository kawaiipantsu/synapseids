package api

// GET /api/v1/sensors/topology (issue #46) and the sensor= / location= scope it
// hands out. The tests that matter most are the honest ones: an empty collector
// must be an empty grouping and not an error, the unassigned bucket must not
// invent a location, and a location that no sensor reports must be a 400 rather
// than a silently empty 200.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
)

func getTopology(t *testing.T, sp SensorStatusProvider) SensorTopology {
	t.Helper()
	rr := httptest.NewRecorder()
	sensorHandler(sp).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/api/v1/sensors/topology", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var got SensorTopology
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", rr.Body.String(), err)
	}
	return got
}

// No collector at all: an empty grouping, 200, and collector:false so an operator
// can tell "not wired" from "wired but nobody connected".
func TestTopologyWithoutCollector(t *testing.T) {
	got := getTopology(t, nil)
	if got.Collector {
		t.Error("collector = true with a nil provider")
	}
	if got.Locations == nil {
		t.Error("locations is null; want an empty array so the view can render")
	}
	if len(got.Locations) != 0 || got.Sensors != 0 || got.LocationCount != 0 {
		t.Errorf("want an empty topology, got %+v", got)
	}
	if got.ScopeSensorParam != "sensor" || got.ScopeLocationParam != "location" {
		t.Errorf("scope params = %q/%q", got.ScopeSensorParam, got.ScopeLocationParam)
	}
	if got.LocalSensorLabel != LocalSensorLabel || got.ScopeNote == "" {
		t.Error("the scope contract must be stated even with no sensors")
	}
}

// A collector with no sensors connected: still empty, but collector:true.
func TestTopologyEmptyCollector(t *testing.T) {
	got := getTopology(t, fakeSensors{})
	if !got.Collector {
		t.Error("collector = false with a provider wired")
	}
	if len(got.Locations) != 0 || got.Sensors != 0 {
		t.Errorf("want an empty topology, got %+v", got)
	}
}

func TestTopologyGroupsByLocationWithAggregates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sp := fakeSensors{rows: []capture.SensorStatus{
		{
			SensorID: "wan-b", Location: "wan", State: capture.StateRunning, Mode: "raw",
			Packets: 100, Bytes: 10000, Drops: 0, PPS: 10, BPS: 1000, LastPacket: now,
			AgentVersion: "0.1.0", OSArch: "linux/amd64",
		},
		{
			SensorID: "wan-a", Location: "wan", State: capture.StateRunning, Mode: "flow",
			Records: 50, RecordBytes: 5000, PPS: 0, BPS: 0,
			AgentVersion: "0.1.0", OSArch: "freebsd/amd64",
		},
		{
			SensorID: "dmz-1", Location: "dmz", State: capture.StateRunning, Mode: "feature",
			Records: 7, RecordBytes: 700, LastPacket: now.Add(-time.Minute),
		},
	}}
	got := getTopology(t, sp)

	if got.Sensors != 3 || got.LocationCount != 2 {
		t.Fatalf("want 3 sensors in 2 locations, got %d in %d", got.Sensors, got.LocationCount)
	}
	// wan has 2 sensors so it sorts ahead of dmz's 1.
	if got.Locations[0].Location != "wan" || got.Locations[1].Location != "dmz" {
		t.Fatalf("location order = %q, %q; want the busiest first",
			got.Locations[0].Location, got.Locations[1].Location)
	}

	wan := got.Locations[0]
	if wan.SensorCount != 2 || wan.Running != 2 || wan.Health != HealthOK {
		t.Errorf("wan = %d sensors, %d running, health %q", wan.SensorCount, wan.Running, wan.Health)
	}
	if wan.Packets != 100 || wan.Bytes != 10000 || wan.PPS != 10 || wan.BPS != 1000 {
		t.Errorf("wan packet aggregates = %+v", wan)
	}
	if wan.Records != 50 || wan.RecordBytes != 5000 {
		t.Errorf("wan record aggregates = %d/%d, want 50/5000", wan.Records, wan.RecordBytes)
	}
	if !wan.LastPacket.Equal(now) {
		t.Errorf("wan last_packet = %s, want the newest across the group (%s)", wan.LastPacket, now)
	}
	// Modes are the distinct set, sorted.
	if len(wan.Modes) != 2 || wan.Modes[0] != "flow" || wan.Modes[1] != "raw" {
		t.Errorf("wan modes = %v, want [flow raw]", wan.Modes)
	}
	// Sensors within a group are ordered by id, so the view does not reshuffle.
	if wan.Sensors[0].SensorID != "wan-a" || wan.Sensors[1].SensorID != "wan-b" {
		t.Errorf("wan sensor order = %q,%q", wan.Sensors[0].SensorID, wan.Sensors[1].SensorID)
	}
	// The embedded SensorStatus fields survive.
	if wan.Sensors[1].AgentVersion != "0.1.0" || wan.Sensors[1].OSArch != "linux/amd64" {
		t.Errorf("embedded sensor detail lost: %+v", wan.Sensors[1])
	}

	// Attribution: flow/feature mode is scopeable, raw is not.
	if wan.Sensors[0].FlowAttribution != AttributionRecords {
		t.Errorf("flow-mode sensor attribution = %q, want %q",
			wan.Sensors[0].FlowAttribution, AttributionRecords)
	}
	if wan.Sensors[1].FlowAttribution != AttributionNone {
		t.Errorf("raw-mode sensor attribution = %q, want %q",
			wan.Sensors[1].FlowAttribution, AttributionNone)
	}
	if wan.AttributableSensors != 1 {
		t.Errorf("wan attributable = %d, want 1 of 2", wan.AttributableSensors)
	}
	if got.AttributableSensors != 2 {
		t.Errorf("total attributable = %d, want 2 (one flow, one feature)", got.AttributableSensors)
	}

	// Totals are the sum over groups.
	if got.Records != 57 || got.Packets != 100 {
		t.Errorf("totals = %d records / %d packets, want 57 / 100", got.Records, got.Packets)
	}
}

// An empty location must land in an explicit bucket, last, flagged — and no
// location may be invented for the sensor itself.
func TestTopologyUnassignedBucket(t *testing.T) {
	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "nowhere-1", Location: "", State: capture.StateRunning, Mode: "raw"},
		{SensorID: "nowhere-2", Location: "   ", State: capture.StateRunning, Mode: "raw"},
		{SensorID: "edge-1", Location: "wan", State: capture.StateRunning, Mode: "raw"},
	}}
	got := getTopology(t, sp)

	if got.LocationCount != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", got.LocationCount, got.Locations)
	}
	// The unassigned bucket is last even though it holds more sensors than wan.
	last := got.Locations[len(got.Locations)-1]
	if !last.Unassigned {
		t.Fatalf("the unassigned bucket is not last: %+v", got.Locations)
	}
	if last.Location != UnassignedLocation {
		t.Errorf("unassigned bucket key = %q, want %q", last.Location, UnassignedLocation)
	}
	if last.SensorCount != 2 {
		t.Errorf("unassigned holds %d sensors, want 2 (empty and whitespace-only)", last.SensorCount)
	}
	if got.UnassignedSensors != 2 {
		t.Errorf("unassigned_sensors = %d, want 2", got.UnassignedSensors)
	}
	// The sensors keep their own empty location: nothing was invented for them.
	for _, s := range last.Sensors {
		if s.Location != "" && s.Location != "   " {
			t.Errorf("sensor %s had a location invented: %q", s.SensorID, s.Location)
		}
	}
	for _, g := range got.Locations[:len(got.Locations)-1] {
		if g.Unassigned {
			t.Errorf("named location %q flagged unassigned", g.Location)
		}
	}
}

// Locations differing only in case stay distinct: merging them would mean picking
// a spelling no sensor sent.
func TestTopologyDoesNotNormaliseLocationCase(t *testing.T) {
	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "a", Location: "WAN", State: capture.StateRunning, Mode: "flow"},
		{SensorID: "b", Location: "wan", State: capture.StateRunning, Mode: "flow"},
	}}
	got := getTopology(t, sp)
	if got.LocationCount != 2 {
		t.Errorf("want WAN and wan kept apart, got %d group(s): %+v", got.LocationCount, got.Locations)
	}
}

func TestTopologyHealth(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []capture.SensorStatus
		want string
	}{
		{
			name: "all running, no drops",
			rows: []capture.SensorStatus{{SensorID: "a", Location: "l", State: capture.StateRunning}},
			want: HealthOK,
		},
		{
			name: "running but dropping",
			rows: []capture.SensorStatus{{SensorID: "a", Location: "l", State: capture.StateRunning, Drops: 3}},
			want: HealthDegraded,
		},
		{
			name: "one of two stopped",
			rows: []capture.SensorStatus{
				{SensorID: "a", Location: "l", State: capture.StateRunning},
				{SensorID: "b", Location: "l", State: capture.StateStopped},
			},
			want: HealthDegraded,
		},
		{
			name: "nothing running",
			rows: []capture.SensorStatus{{SensorID: "a", Location: "l", State: capture.StateError}},
			want: HealthDown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := getTopology(t, fakeSensors{rows: tc.rows})
			if len(got.Locations) != 1 {
				t.Fatalf("want 1 group, got %d", len(got.Locations))
			}
			if got.Locations[0].Health != tc.want {
				t.Errorf("health = %q, want %q", got.Locations[0].Health, tc.want)
			}
		})
	}
}

// The literal /sensors/topology path must not be swallowed by /sensors/{id}.
func TestTopologyRouteBeatsTheSensorWildcard(t *testing.T) {
	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "topology", Location: "wan", State: capture.StateRunning, Mode: "raw"},
	}}
	rr := httptest.NewRecorder()
	sensorHandler(sp).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/api/v1/sensors/topology", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	// It must be the topology document, not the sensor whose id is "topology".
	var probe map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &probe); err != nil {
		t.Fatal(err)
	}
	if _, ok := probe["locations"]; !ok {
		t.Errorf("the wildcard route won: body = %s", rr.Body.String())
	}
}
