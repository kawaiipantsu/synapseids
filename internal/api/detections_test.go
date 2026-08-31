package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var detBase = time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)

func detVerdict(flowID uint64, ts time.Time, src, dst string, dport uint16, class string, score float64) storage.Classification {
	return storage.Classification{
		FlowID:        flowID,
		TS:            ts,
		Sensor:        "test",
		Proto:         "tcp",
		InitiatorIP:   src,
		InitiatorPort: 51234,
		ResponderIP:   dst,
		ResponderPort: dport,
		Result: inference.Result{
			FlowID: flowID, Class: class, Score: score,
			Models: []inference.ModelOutput{{
				ModelID: "heuristic-v1", Role: inference.RolePrimary, Class: class, Score: score,
			}},
		},
	}
}

// detectionServer wires a real alert store with three detections of different
// classes, severities, confidences and activity times, so one fixture exercises
// every filter.
func detectionServer(t *testing.T) http.Handler {
	t.Helper()
	al := alert.New(alert.DefaultPolicy(), alert.Options{})
	t.Cleanup(func() { _ = al.Close() })

	for _, cl := range []storage.Classification{
		detVerdict(4231, detBase, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.983),
		detVerdict(4232, detBase.Add(10*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9),
		detVerdict(51, detBase.Add(time.Minute), "10.0.0.66", "10.10.10.1", 80, "scan", 0.75),
		detVerdict(52, detBase.Add(2*time.Minute), "10.0.0.77", "10.10.10.2", 53, "dos_ddos", 0.95),
		detVerdict(53, detBase.Add(3*time.Minute), "10.0.0.88", "10.10.10.3", 443, "normal", 0.99),
	} {
		c := cl
		al.Observe(nil, &c)
	}
	al.Sync()

	cfg := config.Default()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	return New(cfg, events.New(), storage.NewMem(100, 100), rt,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, al).Handler()
}

func TestDetectionsList(t *testing.T) {
	h := detectionServer(t)
	rr := get(t, h, "/api/v1/detections")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	page := decode[alert.Page](t, rr)
	if page.Total != 3 || page.Returned != 3 {
		t.Fatalf("total/returned = %d/%d, want 3/3 (`normal` never alerts): %+v", page.Total, page.Returned, page.Detections)
	}
	if page.Evicted != 0 {
		t.Errorf("evicted = %d, want 0", page.Evicted)
	}
	// Most recently active first.
	if got := []string{page.Detections[0].Class, page.Detections[1].Class, page.Detections[2].Class}; got[0] != "dos_ddos" || got[1] != "scan" || got[2] != "brute_force" {
		t.Errorf("order = %v, want dos_ddos, scan, brute_force", got)
	}

	bf := page.Detections[2]
	if bf.Count != 2 || bf.FlowID != 4231 {
		t.Errorf("brute_force count/flow_id = %d/%d, want 2/4231", bf.Count, bf.FlowID)
	}
	if len(bf.FlowIDs) != 2 || bf.FlowIDs[0] != 4231 || bf.FlowIDs[1] != 4232 {
		t.Errorf("flow_ids = %v, want [4231 4232]", bf.FlowIDs)
	}
	if bf.Severity != alert.SeverityHigh {
		t.Errorf("severity = %q, want high", bf.Severity)
	}
	if bf.SrcIP != "10.0.0.5" || bf.DstIP != "10.10.10.21" || bf.DstPort != 3306 || bf.Protocol != "tcp" {
		t.Errorf("tuple = %+v", bf)
	}
	if bf.Reason == "" || len(bf.Models) != 1 {
		t.Errorf("reason/models = %q/%+v", bf.Reason, bf.Models)
	}
}

// TestDetectionsJSONShape pins the wire contract the SPA is built against: the
// exact field names, and detections as [] rather than null when empty.
func TestDetectionsJSONShape(t *testing.T) {
	h := detectionServer(t)
	var body map[string]any
	if err := json.Unmarshal(get(t, h, "/api/v1/detections").Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for _, k := range []string{"detections", "total", "returned", "evicted"} {
		if _, ok := body[k]; !ok {
			t.Errorf("response has no %q key", k)
		}
	}
	list, ok := body["detections"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("detections = %v", body["detections"])
	}
	first, _ := list[0].(map[string]any)
	for _, k := range []string{
		"id", "ts", "last_ts", "count", "class", "severity", "confidence",
		"flow_id", "flow_ids", "src_ip", "dst_ip", "src_port", "dst_port",
		"protocol", "disagreement", "reason", "models",
	} {
		if _, ok := first[k]; !ok {
			t.Errorf("detection has no %q key: %v", k, first)
		}
	}
	models, _ := first["models"].([]any)
	if len(models) == 0 {
		t.Fatal("models is empty")
	}
	m, _ := models[0].(map[string]any)
	for _, k := range []string{"model_id", "role", "class", "confidence"} {
		if _, ok := m[k]; !ok {
			t.Errorf("model verdict has no %q key: %v", k, m)
		}
	}
}

func TestDetectionsEmptyWithoutStore(t *testing.T) {
	h := newTestServer() // al == nil
	rr := get(t, h, "/api/v1/detections")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); !jsonHasEmptyList(t, body) {
		t.Errorf("body = %s, want an empty detections list", body)
	}
	if rr := get(t, h, "/api/v1/detections/1"); rr.Code != http.StatusNotFound {
		t.Errorf("code %d, want 404 without a store", rr.Code)
	}
}

func jsonHasEmptyList(t *testing.T, body string) bool {
	t.Helper()
	var page alert.Page
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return page.Detections != nil && len(page.Detections) == 0 && page.Total == 0
}

func TestDetectionsFilters(t *testing.T) {
	h := detectionServer(t)
	cases := []struct {
		name  string
		query string
		want  []string // classes in response order
	}{
		{"class", "?class=scan", []string{"scan"}},
		{"class no match", "?class=botnet_c2", nil},
		{"severity", "?severity=critical", []string{"dos_ddos"}},
		{"severity high", "?severity=high", []string{"brute_force"}},
		{"min_confidence fraction", "?min_confidence=0.9", []string{"dos_ddos", "brute_force"}},
		{"min_confidence percentage", "?min_confidence=95", []string{"dos_ddos", "brute_force"}},
		{"since", "?since=2026-08-31T18:01:30Z", []string{"dos_ddos"}},
		{"limit", "?limit=1", []string{"dos_ddos"}},
		{"combined", "?class=brute_force&min_confidence=0.5&severity=high", []string{"brute_force"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := get(t, h, "/api/v1/detections"+tc.query)
			if rr.Code != http.StatusOK {
				t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
			}
			page := decode[alert.Page](t, rr)
			got := make([]string, 0, len(page.Detections))
			for _, d := range page.Detections {
				got = append(got, d.Class)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("classes = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("classes = %v, want %v", got, tc.want)
				}
			}
		})
	}

	// limit truncates the page but total still reports the match count.
	page := decode[alert.Page](t, get(t, h, "/api/v1/detections?limit=1"))
	if page.Total != 3 || page.Returned != 1 {
		t.Errorf("limit=1 gave total/returned = %d/%d, want 3/1", page.Total, page.Returned)
	}
}

// TestDetectionsBadParams is the 400 contract. This route is stricter than the
// older collection routes on purpose (see detections.go): an unknown or
// unparseable parameter must not silently widen the result.
func TestDetectionsBadParams(t *testing.T) {
	h := detectionServer(t)
	for _, q := range []string{
		"?nope=1",
		"?Class=scan", // case matters; this is not the parameter
		"?class=ransomware",
		"?severity=urgent",
		"?severity=LOW",
		"?min_confidence=abc",
		"?min_confidence=-1",
		"?min_confidence=101",
		"?since=yesterday",
		"?since=2026-08-31",
		"?limit=0",
		"?limit=-5",
		"?limit=lots",
		"?class=scan&bogus=1",
	} {
		if rr := get(t, h, "/api/v1/detections"+q); rr.Code != http.StatusBadRequest {
			t.Errorf("GET /api/v1/detections%s = %d, want 400 (body %q)", q, rr.Code, rr.Body.String())
		}
	}

	// limit above the cap is clamped, not rejected — the cap is a server policy,
	// not a client error.
	if rr := get(t, h, "/api/v1/detections?limit=100000"); rr.Code != http.StatusOK {
		t.Errorf("limit above the cap = %d, want 200", rr.Code)
	}
}

func TestDetectionByID(t *testing.T) {
	h := detectionServer(t)

	page := decode[alert.Page](t, get(t, h, "/api/v1/detections"))
	want := page.Detections[0]

	rr := get(t, h, "/api/v1/detections/"+strconv.FormatUint(want.ID, 10))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	got := decode[alert.Detection](t, rr)
	if got.ID != want.ID || got.Class != want.Class || got.Count != want.Count {
		t.Errorf("detection = %+v, want %+v", got, want)
	}

	// Same shape and same status codes as GET /api/v1/flows/{id}.
	if rr := get(t, h, "/api/v1/detections/999999"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rr.Code)
	}
	for _, bad := range []string{"abc", "-1", "1.5", ""} {
		if rr := get(t, h, "/api/v1/detections/"+bad); rr.Code == http.StatusOK {
			t.Errorf("id %q = %d, want a client error", bad, rr.Code)
		}
	}
}

// TestStatusAlertCounters pins the four counters issue #117 asks for.
func TestStatusAlertCounters(t *testing.T) {
	h := detectionServer(t)
	var body map[string]any
	if err := json.Unmarshal(get(t, h, "/api/v1/status").Body.Bytes(), &body); err != nil {
		t.Fatalf("status not JSON: %v", err)
	}
	alerts, ok := body["alerts"].(map[string]any)
	if !ok {
		t.Fatalf("status has no alerts object: %v", body["alerts"])
	}
	for _, k := range []string{"created", "deduped", "suppressed", "evicted"} {
		if _, present := alerts[k]; !present {
			t.Errorf("status.alerts has no %q counter", k)
		}
	}
	if alerts["created"] != float64(3) {
		t.Errorf("status.alerts.created = %v, want 3", alerts["created"])
	}
	if alerts["deduped"] != float64(1) {
		t.Errorf("status.alerts.deduped = %v, want 1", alerts["deduped"])
	}
	if alerts["enabled"] != true {
		t.Errorf("status.alerts.enabled = %v, want true", alerts["enabled"])
	}

	// A daemon with no alert store reports zeroes rather than omitting the key.
	if err := json.Unmarshal(get(t, newTestServer(), "/api/v1/status").Body.Bytes(), &body); err != nil {
		t.Fatalf("status not JSON: %v", err)
	}
	if alerts, ok := body["alerts"].(map[string]any); !ok || alerts["created"] != float64(0) {
		t.Errorf("status.alerts without a store = %v", body["alerts"])
	}
}
