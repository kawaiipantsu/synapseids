package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/obs"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// rawServer is newTestServer's guts, returning *Server so a test can call
// SetMetrics before wiring the handler.
func rawServer() *Server {
	return New(config.Default(), events.New(), storage.NewMem(100, 100),
		inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary)),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

func TestMetricsEndpoint(t *testing.T) {
	h := newTestServer()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("code %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain...", ct)
	}
	body := rr.Body.String()

	// A representative sample from each section must be present even on a bare
	// server (nil metrics, nil providers).
	for _, want := range []string{
		"# TYPE synapseids_build_info gauge",
		"synapseids_uptime_seconds ",
		"# TYPE synapseids_flows_active gauge",
		"# TYPE synapseids_storage_flows gauge",
		"# TYPE synapseids_inference_latency_seconds histogram",
		"synapseids_inference_latency_seconds_count 0",
		"# TYPE synapseids_events_published_total counter",
		"# TYPE synapseids_detections_created_total counter",
		"synapseids_classifications_total{class=\"scan\"} 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in /metrics output:\n%s", want, body)
		}
	}

	// Every HELP line must be followed by a TYPE line for the same family — a
	// cheap structural check that the writer is not emitting samples before the
	// header.
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "# HELP ") {
			name := strings.Fields(line)[2]
			if !strings.Contains(body, "# TYPE "+name+" ") {
				t.Errorf("family %q has HELP but no TYPE", name)
			}
		}
	}
}

func TestMetricsEndpointWithRecordedValues(t *testing.T) {
	m := obs.New()
	m.ObserveScore(1, 3*time.Millisecond) // "scan"
	m.ObserveScore(1, 5*time.Millisecond)
	m.ObserveFeatureExtract(200 * time.Microsecond)

	srv := rawServer()
	srv.SetMetrics(m)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	body := rr.Body.String()
	for _, want := range []string{
		"synapseids_inference_latency_seconds_count 2",
		"synapseids_feature_extract_latency_seconds_count 1",
		"synapseids_classifications_total{class=\"scan\"} 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
}
