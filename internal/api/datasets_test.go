package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var dsBaseTS = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// dsStore fills a memory store with n alternating normal/scan flows.
func dsStore(n int) *storage.Mem {
	st := storage.NewMem(1000, 1000)
	for i := 1; i <= n; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		id := uint64(i) //nolint:gosec // small positive loop bound
		var fv features.Vector
		fv.FlowID = id
		fv.Schema = schema.FlowFeaturesV1().Schema
		for j := range fv.Values {
			fv.Values[j] = float64(id)*0.5 + float64(j)/8
		}
		st.PutFlow(storage.FlowRecord{
			ID: id, Proto: "TCP", InitiatorIP: "10.0.0.5", ResponderIP: "10.0.0.9", Features: fv,
		})
		st.PutClassification(storage.Classification{
			FlowID: id, TS: dsBaseTS.Add(time.Duration(i) * time.Second),
			Proto: "TCP", InitiatorIP: "10.0.0.5", ResponderIP: "10.0.0.9",
			Result: inference.Result{
				FlowID: id, Class: class, Score: 0.9,
				Models: []inference.ModelOutput{{ModelID: "heuristic-v1", Class: class, Score: 0.9}},
			},
		})
	}
	return st
}

// dsRows is the fixture size: 20 normal + 20 scan, comfortably over
// dataset.MinRows so a default selection builds.
const dsRows = 40

// dsServer wires a real dataset manager and audit log over temp directories.
func dsServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	dsDir, auditDir := t.TempDir(), t.TempDir()
	cfg := config.Default()
	cfg.Datasets.Directory = dsDir
	cfg.Models.Directory = auditDir
	st := dsStore(dsRows)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	srv := New(cfg, events.New(), st, rt, nil, audit.New(auditDir, quiet),
		dataset.Open(dsDir, st, nil, quiet), nil, nil, nil, nil, nil, nil, nil)
	return srv, dsDir, auditDir
}

func post(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	return rr
}

func ref(id, version string) string { return url.PathEscape(id + "@" + version) }

const createBody = `{
  "id": "thugs/lab-attacks-2026-08",
  "version": "v1",
  "name": "Lab attacks",
  "description": "replayed corpus",
  "location": "thugs-lab",
  "tags": ["lab"],
  "source_capture_ids": ["replay:portscan.pcap"],
  "selection": {}
}`

// ---- happy paths ---------------------------------------------------------

func TestDatasetCreateListGetDownload(t *testing.T) {
	srv, _, auditDir := dsServer(t)
	h := srv.Handler()

	// create
	rr := post(t, h, "/api/v1/datasets", createBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Dataset dataset.Dataset `json:"dataset"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	d := created.Dataset
	if d.FlowCount != 40 || d.LabelCounts["scan"] != 20 {
		t.Errorf("manifest = %+v", d.Manifest)
	}
	if d.LabelingSource != "model_prediction:heuristic-v1" {
		t.Errorf("labeling_source = %q — Phase 4 datasets are model-labelled", d.LabelingSource)
	}
	if !strings.HasPrefix(d.ContentHash, "sha256:") {
		t.Errorf("content_hash = %q", d.ContentHash)
	}

	// list
	rr = do(t, h, http.MethodGet, "/api/v1/datasets")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET list = %d", rr.Code)
	}
	var list struct {
		Datasets    []dataset.Dataset `json:"datasets"`
		Columns     []string          `json:"columns"`
		LabelColumn string            `json:"label_column"`
		MinRows     int               `json:"min_rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Datasets) != 1 || list.Datasets[0].Ref() != "thugs/lab-attacks-2026-08@v1" {
		t.Fatalf("list = %+v", list.Datasets)
	}
	if len(list.Columns) != schema.FlowFeaturesV1().InputSize+1 || list.LabelColumn != "label" {
		t.Errorf("columns = %d, label_column = %q", len(list.Columns), list.LabelColumn)
	}
	if list.MinRows != dataset.MinRows {
		t.Errorf("min_rows = %d, want %d", list.MinRows, dataset.MinRows)
	}

	// get one — the id contains a "/", so the ref segment is escaped
	r := ref("thugs/lab-attacks-2026-08", "v1")
	rr = do(t, h, http.MethodGet, "/api/v1/datasets/"+r)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET one = %d: %s", rr.Code, rr.Body.String())
	}
	var one struct {
		Dataset  dataset.Dataset   `json:"dataset"`
		Versions []dataset.Dataset `json:"versions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.Dataset.ContentHash != d.ContentHash {
		t.Errorf("GET one returned a different manifest")
	}
	if len(one.Versions) != 1 {
		t.Errorf("versions = %d, want 1", len(one.Versions))
	}

	// download
	rr = do(t, h, http.MethodGet, "/api/v1/datasets/"+r+"/download")
	if rr.Code != http.StatusOK {
		t.Fatalf("download = %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q", ct)
	}
	wantCD := `attachment; filename="thugs_lab-attacks-2026-08-v1.csv"`
	if cd := rr.Header().Get("Content-Disposition"); cd != wantCD {
		t.Errorf("Content-Disposition = %q, want %q", cd, wantCD)
	}
	if got := rr.Header().Get("X-Synapse-Dataset-Hash"); got != d.ContentHash {
		t.Errorf("hash header = %q", got)
	}
	body := rr.Body.String()
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 41 {
		t.Fatalf("csv has %d lines, want 41", len(lines))
	}
	header := strings.Split(lines[0], ",")
	if len(header) != 49 || header[0] != schema.FeatureName(0) || header[48] != "label" {
		t.Errorf("csv header is wrong: %d columns, first %q, last %q", len(header), header[0], header[48])
	}

	// the create was audited
	auditLog, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	if !strings.Contains(string(auditLog), `"event":"DatasetCreated"`) ||
		!strings.Contains(string(auditLog), `"subject":"thugs/lab-attacks-2026-08@v1"`) ||
		!strings.Contains(string(auditLog), `"subject_type":"dataset"`) {
		t.Errorf("dataset create was not audited: %s", auditLog)
	}
}

func TestDatasetCreateAutoVersionAndDerive(t *testing.T) {
	srv, _, auditDir := dsServer(t)
	h := srv.Handler()

	rr := post(t, h, "/api/v1/datasets", `{"id":"hq/base","selection":{}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rr.Code, rr.Body.String())
	}
	var first struct {
		Dataset dataset.Dataset `json:"dataset"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &first)
	if first.Dataset.Version != "v1" {
		t.Fatalf("auto version = %q, want v1", first.Dataset.Version)
	}
	// A name is not required; it falls back to the id.
	if first.Dataset.Name != "hq/base" {
		t.Errorf("name = %q, want the id as a fallback", first.Dataset.Name)
	}

	rr = post(t, h, "/api/v1/datasets",
		`{"id":"hq/base","derive_from":"hq/base@v1","selection":{"proto":"tcp"}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("derive = %d: %s", rr.Code, rr.Body.String())
	}
	var child struct {
		Dataset dataset.Dataset `json:"dataset"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &child)
	if child.Dataset.Version != "v2" {
		t.Errorf("derived version = %q, want v2", child.Dataset.Version)
	}
	if len(child.Dataset.ParentDatasets) != 1 || child.Dataset.ParentDatasets[0] != "hq/base@v1" {
		t.Errorf("parent_datasets = %v", child.Dataset.ParentDatasets)
	}

	// Both versions are addressable and GET one lists the sibling versions.
	rr = do(t, h, http.MethodGet, "/api/v1/datasets/"+ref("hq/base", "v2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET v2 = %d: %s", rr.Code, rr.Body.String())
	}
	var one struct {
		Dataset  dataset.Dataset   `json:"dataset"`
		Versions []dataset.Dataset `json:"versions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.Dataset.Version != "v2" || len(one.Versions) != 2 {
		t.Errorf("GET v2 returned version %q with %d siblings, want v2 and 2", one.Dataset.Version, len(one.Versions))
	}
	if one.Versions[0].Version != "v2" {
		t.Errorf("versions are not newest-first: %q first", one.Versions[0].Version)
	}

	log, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), `"event":"DatasetDerived"`) {
		t.Errorf("derive was not audited as DatasetDerived: %s", log)
	}
}

func TestDatasetDelete(t *testing.T) {
	srv, dsDir, auditDir := dsServer(t)
	h := srv.Handler()

	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rr.Code, rr.Body.String())
	}
	r := ref("thugs/lab-attacks-2026-08", "v1")

	rr := do(t, h, http.MethodDelete, "/api/v1/datasets/"+r)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dsDir, "thugs")); !os.IsNotExist(err) {
		t.Errorf("the dataset directory survived the delete: %v", err)
	}
	if rr := do(t, h, http.MethodDelete, "/api/v1/datasets/"+r); rr.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", rr.Code)
	}
	log, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), `"event":"DatasetDeleted"`) {
		t.Errorf("delete was not audited: %s", log)
	}
}

// ---- error codes ---------------------------------------------------------

func TestDatasetErrorCodes(t *testing.T) {
	srv, _, _ := dsServer(t)
	h := srv.Handler()

	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusCreated {
		t.Fatalf("setup POST = %d: %s", rr.Code, rr.Body.String())
	}

	tests := []struct {
		name, method, path, body string
		want                     int
		wantText                 string
	}{
		{name: "duplicate version", method: http.MethodPost, path: "/api/v1/datasets", body: createBody,
			want: http.StatusConflict, wantText: "immutable"},
		{name: "malformed json", method: http.MethodPost, path: "/api/v1/datasets", body: `{`,
			want: http.StatusBadRequest, wantText: "bad request body"},
		{name: "unknown field", method: http.MethodPost, path: "/api/v1/datasets", body: `{"id":"a","nope":1}`,
			want: http.StatusBadRequest},
		{name: "missing id", method: http.MethodPost, path: "/api/v1/datasets", body: `{"selection":{}}`,
			want: http.StatusBadRequest, wantText: "id is required"},
		{name: "traversal id", method: http.MethodPost, path: "/api/v1/datasets", body: `{"id":"../../etc","selection":{}}`,
			want: http.StatusBadRequest},
		{name: "three-segment id", method: http.MethodPost, path: "/api/v1/datasets", body: `{"id":"a/b/c","selection":{}}`,
			want: http.StatusBadRequest, wantText: "at most one"},
		{name: "uppercase id", method: http.MethodPost, path: "/api/v1/datasets", body: `{"id":"Loud","selection":{}}`,
			want: http.StatusBadRequest, wantText: "lowercase"},
		{name: "bad version", method: http.MethodPost, path: "/api/v1/datasets", body: `{"id":"ok","version":"a/b","selection":{}}`,
			want: http.StatusBadRequest},
		{name: "unknown class filter", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","selection":{"class":"nope"}}`, want: http.StatusBadRequest, wantText: "unknown class"},
		{name: "bad timestamp", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","selection":{"from":"yesterday"}}`, want: http.StatusBadRequest, wantText: "RFC3339"},
		{name: "empty selection", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","selection":{"initiator_ip":"203.0.113.9"}}`,
			want: http.StatusUnprocessableEntity, wantText: "matched no classifications"},
		{name: "single class", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","selection":{"class":"normal"}}`,
			want: http.StatusUnprocessableEntity, wantText: "one class"},
		{name: "too few rows", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","selection":{"limit":4}}`,
			want: http.StatusUnprocessableEntity, wantText: "row floor"},
		{name: "derive from nothing", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","derive_from":"nope@v1","selection":{}}`, want: http.StatusNotFound},
		{name: "bad derive ref", method: http.MethodPost, path: "/api/v1/datasets",
			body: `{"id":"ok","derive_from":"noat","selection":{}}`, want: http.StatusBadRequest},
		{name: "get unknown", method: http.MethodGet, path: "/api/v1/datasets/" + ref("nope", "v1"),
			want: http.StatusNotFound},
		{name: "get bad ref", method: http.MethodGet, path: "/api/v1/datasets/noat",
			want: http.StatusBadRequest, wantText: "<id>@<version>"},
		{name: "download unknown", method: http.MethodGet, path: "/api/v1/datasets/" + ref("nope", "v1") + "/download",
			want: http.StatusNotFound},
		{name: "delete unknown", method: http.MethodDelete, path: "/api/v1/datasets/" + ref("nope", "v1"),
			want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rr *httptest.ResponseRecorder
			if tc.method == http.MethodPost {
				rr = post(t, h, tc.path, tc.body)
			} else {
				rr = do(t, h, tc.method, tc.path)
			}
			if rr.Code != tc.want {
				t.Fatalf("%s %s = %d, want %d: %s", tc.method, tc.path, rr.Code, tc.want, rr.Body.String())
			}
			if tc.wantText != "" && !strings.Contains(rr.Body.String(), tc.wantText) {
				t.Errorf("body %q does not contain %q", rr.Body.String(), tc.wantText)
			}
		})
	}
}

// ---- no manager wired ----------------------------------------------------

func TestDatasetRoutesWithoutAManager(t *testing.T) {
	cfg := config.Default()
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))
	h := New(cfg, events.New(), storage.NewMem(10, 10), rt, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	// The list always renders, so the SPA has something to show.
	rr := do(t, h, http.MethodGet, "/api/v1/datasets")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET list = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"datasets": []`) {
		t.Errorf("want an empty datasets array, got %s", rr.Body.String())
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/datasets/" + ref("a", "v1")},
		{http.MethodDelete, "/api/v1/datasets/" + ref("a", "v1")},
		{http.MethodGet, "/api/v1/datasets/" + ref("a", "v1") + "/download"},
	} {
		if rr := do(t, h, tc.method, tc.path); rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", tc.method, tc.path, rr.Code)
		}
	}
	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("POST = %d, want 503", rr.Code)
	}
}

// ---- selection parity with GET /api/v1/classifications -------------------

func TestDatasetMinConfidenceAcceptsAPercentage(t *testing.T) {
	srv, _, _ := dsServer(t)
	h := srv.Handler()

	// 95 means 95%, exactly as the flow log's slider sends it — and 0.9 < 0.95
	// so nothing matches, which is the point: the value was not read as 95.0.
	rr := post(t, h, "/api/v1/datasets", `{"id":"pct","selection":{"min_confidence":95}}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("min_confidence=95 → %d, want 422 (nothing scores >= 0.95): %s", rr.Code, rr.Body.String())
	}
	rr = post(t, h, "/api/v1/datasets", `{"id":"pct","selection":{"min_confidence":80}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("min_confidence=80 → %d, want 201: %s", rr.Code, rr.Body.String())
	}
}
