package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/enrichment"
	"github.com/kawaiipantsu/synapseids/internal/training"
)

func TestTrainingMetricsFollowReportedProgressAndStatus(t *testing.T) {
	s := rawServer()
	s.tr = training.Open(t.TempDir(), nil, nil)
	h := s.Handler()
	id := tdecode(t, treq(t, h, "POST", "/api/v1/training", `{"name":"synthetic-run","epochs_total":12}`))["id"].(string)
	path := "/api/v1/training/" + id + "/progress"
	treq(t, h, "POST", path, `{"event":"epoch","epoch":3,"train_loss":0.25,"val_loss":0.4,"val_accuracy":0.875,"val_macro_f1":null,"lr":0.001,"elapsed_s":8.5,"arbitrary_secret":"should-never-be-exported"}`)
	body := get(t, h, "/metrics").Body.String()
	for _, want := range []string{
		`synapseids_training_runs{status="running"} 1`,
		`synapseids_training_epoch{run_id="` + id + `"} 3`,
		`synapseids_training_epochs_planned{run_id="` + id + `"} 12`,
		`synapseids_training_loss{run_id="` + id + `"} 0.25`,
		`synapseids_training_validation_accuracy_ratio{run_id="` + id + `"} 0.875`,
		`synapseids_models_loaded{role="classifier"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, forbidden := range []string{"arbitrary_secret", "should-never-be-exported", "synthetic-run", "synapseids_training_validation_f1_ratio"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("unexpected export: %s", forbidden)
		}
	}
	treq(t, h, "POST", path, `{"event":"done","metrics":{"accuracy":0.875}}`)
	body = get(t, h, "/metrics").Body.String()
	if !strings.Contains(body, `synapseids_training_run_status{run_id="`+id+`",status="completed"} 1`) || !strings.Contains(body, "synapseids_training_finished_timestamp_seconds{") {
		t.Fatal("terminal run metrics missing")
	}
}

func TestTrainingMetricsNeverInventLossBeforeProgress(t *testing.T) {
	s := rawServer()
	s.tr = training.Open(t.TempDir(), nil, nil)
	h := s.Handler()
	treq(t, h, "POST", "/api/v1/training", `{"name":"empty-run","epochs_total":2}`)
	body := get(t, h, "/metrics").Body.String()
	if strings.Contains(body, "# TYPE synapseids_training_loss") {
		t.Fatal("loss fabricated before an epoch")
	}
	if !strings.Contains(body, "synapseids_dataset_versions 0") {
		t.Fatal("empty dataset count missing")
	}
}

func TestEnrichmentEndpointValidatesBatchAndObservedHosts(t *testing.T) {
	h := investigateServer(t)
	for _, path := range []string{"/api/v1/enrichment", "/api/v1/enrichment?ip=example.test", "/api/v1/enrichment?ip=fe80::1%25lo", "/api/v1/enrichment?" + strings.Repeat("ip=10.0.0.5&", 65)} {
		if code := get(t, h, path).Code; code != 400 {
			t.Errorf("invalid batch: %d", code)
		}
	}
	rr := get(t, h, "/api/v1/enrichment?ip=10.0.0.5&ip=192.0.2.1")
	body := decode[struct {
		Hosts []enrichment.Record `json:"hosts"`
	}](t, rr)
	if rr.Code != 200 || len(body.Hosts) != 2 || body.Hosts[0].Status != "disabled" || body.Hosts[1].Status != "unobserved" {
		t.Fatalf("unexpected response %s", rr.Body)
	}
	// A missing insight index must remain nil-safe.
	s := rawServer()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/enrichment?ip=192.0.2.1", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
