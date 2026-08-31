package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/modeltest"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/training"
)

// auditResp mirrors the GET /api/v1/audit envelope.
type auditResp struct {
	Records      []audit.Record `json:"records"`
	Count        int            `json:"count"`
	Limit        int            `json:"limit"`
	MaxLimit     int            `json:"max_limit"`
	ScanBytesCap int64          `json:"scan_bytes_cap"`
}

func getAudit(t *testing.T, h http.Handler, query string) auditResp {
	t.Helper()
	rr := do(t, h, "GET", "/api/v1/audit"+query)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit%s = %d, body %s", query, rr.Code, rr.Body)
	}
	var got auditResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	if got.Count != len(got.Records) {
		t.Fatalf("count %d disagrees with %d records", got.Count, len(got.Records))
	}
	return got
}

func auditEvents(recs []audit.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Event
	}
	return out
}

// ---- the read route ------------------------------------------------------

func TestAuditRouteHappyPath(t *testing.T) {
	srv, _ := modelServer(t)
	srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "hash=sha256:abc")
	srv.audit.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	srv.audit.LogSubject(audit.EventDatasetCreated, audit.ActorLocal, audit.SubjectDataset, "thugs/lab@v1", "flows=40")

	got := getAudit(t, srv.Handler(), "")
	if len(got.Records) != 3 {
		t.Fatalf("got %d records, want 3: %v", len(got.Records), auditEvents(got.Records))
	}
	// Newest first.
	if got.Records[0].Event != audit.EventDatasetCreated {
		t.Fatalf("records are not newest-first: %v", auditEvents(got.Records))
	}
	if got.Records[0].SubjectType != audit.SubjectDataset || got.Records[0].Subject != "thugs/lab@v1" {
		t.Fatalf("dataset record = %+v", got.Records[0])
	}
	if got.Limit != 100 || got.MaxLimit != audit.MaxTail || got.ScanBytesCap != audit.MaxScanBytes {
		t.Fatalf("bounds not reported: limit=%d max=%d scan=%d", got.Limit, got.MaxLimit, got.ScanBytesCap)
	}
}

// An empty log is an empty array, not null and not an error.
func TestAuditRouteEmptyLog(t *testing.T) {
	srv, _ := modelServer(t)
	rr := do(t, srv.Handler(), "GET", "/api/v1/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d, body %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), `"records": []`) {
		t.Fatalf("want an empty array, got %s", rr.Body)
	}
}

func TestAuditRouteFilters(t *testing.T) {
	srv, _ := modelServer(t)
	srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "")
	srv.audit.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, "m-2", "")
	srv.audit.LogSubject(audit.EventDatasetCreated, audit.ActorLocal, audit.SubjectDataset, "thugs/lab@v1", "")
	srv.audit.LogSubject(audit.EventDatasetDeleted, audit.ActorLocal, audit.SubjectDataset, "thugs/lab@v1", "")
	srv.audit.LogSubject(audit.EventTrainingStarted, audit.ActorLocal, audit.SubjectTraining, "run-7", "")
	// A subject type this package knows nothing about (issue #42's review
	// lines) must be filterable with no code change here.
	srv.audit.LogSubject("ReviewLabelChanged", audit.ActorLocal, "review", "flow-42", "SCAN -> NORMAL")

	h := srv.Handler()
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 7},
		{"?subject_type=model", 3},
		{"?subject_type=dataset", 2},
		{"?subject_type=training", 1},
		{"?subject_type=review", 1},
		{"?subject=m-1", 2},
		{"?subject=thugs%2Flab%40v1", 2},
		{"?event=ModelRegistered", 2},
		{"?event=ReviewLabelChanged", 1},
		{"?subject_type=model&subject=m-1&event=ModelActivated", 1},
		{"?subject=nope", 0},
		{"?event=NoSuchEvent", 0},
		{"?subject_type=nosuchtype", 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			got := getAudit(t, h, tc.query)
			if len(got.Records) != tc.want {
				t.Fatalf("got %d records, want %d: %v", len(got.Records), tc.want, auditEvents(got.Records))
			}
		})
	}
}

func TestAuditRouteTimeRange(t *testing.T) {
	srv, _ := modelServer(t)
	srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "")
	h := srv.Handler()

	// A window that certainly contains "now" returns the record; one in the
	// past does not.
	if got := getAudit(t, h, "?from=2020-01-01T00:00:00Z"); len(got.Records) != 1 {
		t.Fatalf("wide from= returned %d records", len(got.Records))
	}
	if got := getAudit(t, h, "?to=2020-01-01T00:00:00Z"); len(got.Records) != 0 {
		t.Fatalf("past to= returned %d records", len(got.Records))
	}
	past := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	future := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	if got := getAudit(t, h, "?from="+past+"&to="+future); len(got.Records) != 1 {
		t.Fatalf("surrounding window returned %d records", len(got.Records))
	}

	// Bad timestamps and an inverted range are 400s, reusing the shared
	// parseTimeRange helper's messages.
	for _, q := range []string{
		"?from=yesterday",
		"?to=not-a-time",
		"?from=" + future + "&to=" + past,
	} {
		rr := do(t, h, "GET", "/api/v1/audit"+q)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("GET /api/v1/audit%s = %d, want 400", q, rr.Code)
		}
	}
}

func TestAuditRouteLimitClamping(t *testing.T) {
	srv, _ := modelServer(t)
	for i := range 40 {
		srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, "m-"+string(rune('a'+i%26)), "")
	}
	h := srv.Handler()

	for _, tc := range []struct {
		query     string
		wantLimit int
		wantRecs  int
	}{
		{"", 100, 40},                        // default
		{"?limit=5", 5, 5},                   // honoured
		{"?limit=0", 100, 40},                // < 1 falls back to the default
		{"?limit=-3", 100, 40},               // ditto
		{"?limit=abc", 100, 40},              // unparseable falls back
		{"?limit=999999", audit.MaxTail, 40}, // clamped to the ceiling
	} {
		t.Run(tc.query, func(t *testing.T) {
			got := getAudit(t, h, tc.query)
			if got.Limit != tc.wantLimit {
				t.Fatalf("limit echoed as %d, want %d", got.Limit, tc.wantLimit)
			}
			if len(got.Records) != tc.wantRecs {
				t.Fatalf("got %d records, want %d", len(got.Records), tc.wantRecs)
			}
		})
	}
}

// No audit logger wired: 503, not a panic and not a 200 with an empty list —
// "nothing has happened" and "the trail is unavailable" are different answers.
func TestAuditRouteNoLoggerIsUnavailable(t *testing.T) {
	cfg := config.Default()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	srv := New(cfg, events.New(), storage.NewMem(10, 10), rt, nil, nil, nil, nil, nil, nil, nil, nil)

	rr := do(t, srv.Handler(), "GET", "/api/v1/audit")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d, want 503", rr.Code)
	}
}

// The audit log is append-only from the API forever: only GET is routed, so no
// client can rewrite or drop history (PROJECT.md §21).
func TestAuditRouteIsReadOnly(t *testing.T) {
	srv, _ := modelServer(t)
	srv.audit.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	h := srv.Handler()

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		rr := do(t, h, method, "/api/v1/audit")
		if rr.Code == http.StatusOK {
			t.Fatalf("%s /api/v1/audit was accepted — the audit log must be append-only", method)
		}
	}
	// The record is still there.
	if got := getAudit(t, h, ""); len(got.Records) != 1 {
		t.Fatalf("got %d records after the write attempts, want 1", len(got.Records))
	}
}

// ---- activation trail ----------------------------------------------------

// register -> activate -> deactivate leaves exactly three records for the
// model, readable through the same path the UI uses.
func TestAuditActivationTrail(t *testing.T) {
	srv, dir := modelServer(t)
	e := registerBundle(t, srv, dir, "alpha", modeltest.Bundle{ModelID: "m-alpha"})
	// registerBundle deliberately does not audit — registration is audited by
	// cmd/synapsed's startup sweep. Mirror that line here.
	srv.audit.Log(audit.EventModelRegistered, audit.ActorLocal, e.ModelID,
		"hash="+e.ContentHash+" status="+string(e.Status))

	h := srv.Handler()
	if rr := do(t, h, "POST", "/api/v1/models/m-alpha/activate"); rr.Code != http.StatusOK {
		t.Fatalf("activate = %d, body %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, "POST", "/api/v1/models/m-alpha/deactivate"); rr.Code != http.StatusOK {
		t.Fatalf("deactivate = %d, body %s", rr.Code, rr.Body)
	}

	// Through Tail directly...
	recs, err := srv.audit.Tail(0, audit.Filter{SubjectType: audit.SubjectModel, Subject: "m-alpha"})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	want := []string{audit.EventModelDeactivated, audit.EventModelActivated, audit.EventModelRegistered}
	if got := auditEvents(recs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Tail = %v, want newest-first %v", got, want)
	}
	for _, r := range recs {
		if r.ModelID != "m-alpha" || r.Subject != "m-alpha" || r.Actor != audit.ActorLocal {
			t.Fatalf("record = %+v", r)
		}
	}
	if !strings.Contains(recs[0].Detail, "restored heuristic") {
		t.Errorf("deactivate detail = %q", recs[0].Detail)
	}
	if !strings.Contains(recs[1].Detail, e.ContentHash) {
		t.Errorf("activate detail %q omits the content hash", recs[1].Detail)
	}

	// ...and through the route, which must agree.
	got := getAudit(t, h, "?subject_type=model&subject=m-alpha")
	if ev := auditEvents(got.Records); strings.Join(ev, ",") != strings.Join(want, ",") {
		t.Fatalf("route = %v, want %v", ev, want)
	}
}

// Activating B while A is active demotes A in the registry. That demotion is a
// state change and must appear under A's own subject, otherwise A's most recent
// audit line still claims it is active.
func TestAuditImplicitDeactivationIsRecorded(t *testing.T) {
	srv, dir := modelServer(t)
	registerBundle(t, srv, dir, "alpha", modeltest.Bundle{ModelID: "m-alpha", Seed: 1})
	registerBundle(t, srv, dir, "beta", modeltest.Bundle{ModelID: "m-beta", Seed: 2})

	h := srv.Handler()
	if rr := do(t, h, "POST", "/api/v1/models/m-alpha/activate"); rr.Code != http.StatusOK {
		t.Fatalf("activate alpha = %d, body %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, "POST", "/api/v1/models/m-beta/activate"); rr.Code != http.StatusOK {
		t.Fatalf("activate beta = %d, body %s", rr.Code, rr.Body)
	}

	// The registry demoted alpha.
	if a, _ := srv.reg.Get("m-alpha"); a.Status != registry.StatusDeactivated {
		t.Fatalf("alpha status = %q, want deactivated", a.Status)
	}
	// And so does the audit trail, under alpha's subject.
	recs, err := srv.audit.Tail(0, audit.Filter{Subject: "m-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{audit.EventModelDeactivated, audit.EventModelActivated}
	if got := auditEvents(recs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("alpha trail = %v, want %v", got, want)
	}
	if !strings.Contains(recs[0].Detail, "m-beta") {
		t.Errorf("alpha's deactivation does not name its replacement: %q", recs[0].Detail)
	}
	// Beta's activation names what it replaced.
	brecs, err := srv.audit.Tail(0, audit.Filter{Subject: "m-beta", Event: audit.EventModelActivated})
	if err != nil {
		t.Fatal(err)
	}
	if len(brecs) != 1 || !strings.Contains(brecs[0].Detail, "replaced=m-alpha") {
		t.Fatalf("beta activation = %+v", brecs)
	}
}

// Deactivating an entry that was never the live primary is a legal no-op, and
// the audit line must not claim it restored the heuristic.
func TestAuditDeactivateNoOpDetailIsHonest(t *testing.T) {
	srv, dir := modelServer(t)
	registerBundle(t, srv, dir, "alpha", modeltest.Bundle{ModelID: "m-alpha"})

	if rr := do(t, srv.Handler(), "POST", "/api/v1/models/m-alpha/deactivate"); rr.Code != http.StatusOK {
		t.Fatalf("deactivate = %d, body %s", rr.Code, rr.Body)
	}
	recs, err := srv.audit.Tail(0, audit.Filter{Subject: "m-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if !strings.Contains(recs[0].Detail, "no-op") || !strings.Contains(recs[0].Detail, "registered") {
		t.Fatalf("no-op deactivate detail = %q", recs[0].Detail)
	}
}

// ---- the §21 coverage claim ---------------------------------------------

// PROJECT.md §21 requires an audit trail for model activation, training and
// dataset edits (human label changes arrive with the review loop, issue #42).
// This drives all three through the API against one shared audit log and
// asserts each writes a record that Tail can find by subject type.
func TestAuditCoversModelsDatasetsAndTraining(t *testing.T) {
	auditDir, dsDir, trDir, modelDir := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	cfg := config.Default()
	cfg.Models.Directory = auditDir
	cfg.Datasets.Directory = dsDir
	cfg.Training.Directory = trDir

	st := dsStore(dsRows)
	aud := audit.New(auditDir, quiet)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	srv := New(cfg, events.New(), st, rt,
		registry.Open(modelDir, quiet), aud,
		dataset.Open(dsDir, st, quiet), nil, nil, nil, nil,
		training.Open(trDir, aud, quiet))
	h := srv.Handler()

	// 1. model activation + deactivation.
	registerBundle(t, srv, modelDir, "alpha", modeltest.Bundle{ModelID: "m-alpha"})
	if rr := do(t, h, "POST", "/api/v1/models/m-alpha/activate"); rr.Code != http.StatusOK {
		t.Fatalf("activate = %d, body %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, "POST", "/api/v1/models/m-alpha/deactivate"); rr.Code != http.StatusOK {
		t.Fatalf("deactivate = %d, body %s", rr.Code, rr.Body)
	}

	// 2. dataset create then delete — the "dataset edits" of §21.
	if rr := post(t, h, "/api/v1/datasets", createBody); rr.Code != http.StatusCreated {
		t.Fatalf("dataset create = %d, body %s", rr.Code, rr.Body)
	}
	delReq := httptest.NewRequest(http.MethodDelete,
		"/api/v1/datasets/"+ref("thugs/lab-attacks-2026-08", "v1"), nil)
	delRR := httptest.NewRecorder()
	h.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK && delRR.Code != http.StatusNoContent {
		t.Fatalf("dataset delete = %d, body %s", delRR.Code, delRR.Body)
	}

	// 3. a training run, started then failed.
	runID := tdecode(t, treq(t, h, "POST", "/api/v1/training",
		`{"name":"nightly","epochs_total":2,"trainer_version":"0.1.0"}`))["id"].(string)
	if rr := treq(t, h, "POST", "/api/v1/training/"+runID+"/fail", `{"reason":"cuda oom"}`); rr.Code != http.StatusAccepted {
		t.Fatalf("training fail = %d, body %s", rr.Code, rr.Body)
	}

	// Every one of the three is in the log, findable by subject type.
	for _, want := range []struct {
		subjectType string
		events      []string // must all be present
	}{
		{audit.SubjectModel, []string{audit.EventModelActivated, audit.EventModelDeactivated}},
		{audit.SubjectDataset, []string{audit.EventDatasetCreated, audit.EventDatasetDeleted}},
		{audit.SubjectTraining, []string{audit.EventTrainingStarted, audit.EventTrainingFailed}},
	} {
		t.Run(want.subjectType, func(t *testing.T) {
			got := getAudit(t, h, "?subject_type="+want.subjectType)
			if len(got.Records) == 0 {
				t.Fatalf("no %s records — §21 requires an audit trail for this", want.subjectType)
			}
			seen := map[string]bool{}
			for _, r := range got.Records {
				if r.SubjectType != want.subjectType {
					t.Fatalf("filter leaked a %q record", r.SubjectType)
				}
				if r.Subject == "" {
					t.Fatalf("record has no subject: %+v", r)
				}
				if r.Actor != audit.ActorLocal {
					t.Fatalf("record actor = %q", r.Actor)
				}
				seen[r.Event] = true
			}
			for _, ev := range want.events {
				if !seen[ev] {
					t.Errorf("%s trail has no %s record (have %v)", want.subjectType, ev, auditEvents(got.Records))
				}
			}
		})
	}

	// model_id is set on model lines only.
	all := getAudit(t, h, "")
	for _, r := range all.Records {
		if r.SubjectType == audit.SubjectModel && r.ModelID == "" {
			t.Errorf("model record has no model_id: %+v", r)
		}
		if r.SubjectType != audit.SubjectModel && r.ModelID != "" {
			t.Errorf("%s record set model_id=%q", r.SubjectType, r.ModelID)
		}
	}
}
