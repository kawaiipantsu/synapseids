package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/report"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var reportBase = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// newReportServer wires a handler over a store and insight index populated with
// a small, deterministic conversation set.
func newReportServer(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Default()
	bus := events.New()
	store := storage.NewMem(200, 200)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))

	rows := []struct {
		id           uint64
		init, resp   string
		rport        uint16
		class        string
		classID      int
		score        float64
		disagreement bool
		off          int
	}{
		{1, "10.10.10.22", "10.10.10.21", 3306, "brute_force", 3, 0.92, false, 0},
		{2, "10.10.10.22", "10.10.10.21", 22, "scan", 1, 0.85, false, 1},
		{3, "10.10.10.22", "10.10.10.9", 443, "normal", 0, 0.97, false, 2},
		{4, "10.10.10.22", "10.10.10.9", 80, "suspicious", 6, 0.41, true, 3},
		{5, "10.10.10.5", "10.10.10.6", 53, "normal", 0, 0.95, false, 4},
	}
	for _, row := range rows {
		ts := reportBase.Add(time.Duration(row.off) * time.Second)
		fr := storage.FlowRecord{
			ID: row.id, Proto: "tcp",
			InitiatorIP: row.init, InitiatorPort: 40000 + uint16(row.id),
			ResponderIP: row.resp, ResponderPort: row.rport,
			FirstSeen: ts.Add(-time.Second), LastSeen: ts, DurationSec: 1,
			FwdPackets: 4, BwdPackets: 2, FwdBytes: 320, BwdBytes: 140,
			CloseReason: "fin",
			Features:    features.Vector{FlowID: row.id, Schema: features.SchemaID},
		}
		cl := storage.Classification{
			FlowID: row.id, TS: ts, Sensor: "local", Proto: "tcp",
			InitiatorIP: row.init, InitiatorPort: fr.InitiatorPort,
			ResponderIP: row.resp, ResponderPort: row.rport,
			Result: inference.Result{
				FlowID: row.id, Class: row.class, ClassID: row.classID,
				Score: row.score, Disagreement: row.disagreement,
				Models: []inference.ModelOutput{{
					ModelID: "heuristic-v1", Role: inference.RolePrimary,
					Class: row.class, ClassID: row.classID, Score: row.score,
				}},
			},
		}
		store.PutFlow(fr)
		store.PutClassification(cl)
		ix.Observe(&fr, &cl)
	}
	ix.Sync()

	return New(cfg, bus, store, rt, nil, nil, nil, nil, nil, nil, ix, nil).Handler()
}

// `get` and `decode` come from hosts_test.go — one helper set per package.

// ------------------------------------------------------- host report, JSON

func TestHostReportJSON(t *testing.T) {
	h := newReportServer(t)
	rr := get(t, h, "/api/v1/reports/host/10.10.10.22?format=json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="synapseids-host-10.10.10.22-`) ||
		!strings.HasSuffix(cd, `.json"`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}

	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("body is not a report: %v", err)
	}
	if rep.Schema != report.SchemaID {
		t.Fatalf("schema = %q", rep.Schema)
	}
	if rep.Scope.Kind != report.ScopeHost || rep.Scope.Host != "10.10.10.22" {
		t.Fatalf("scope = %+v", rep.Scope)
	}
	if rep.Host == nil || rep.Host.IP != "10.10.10.22" {
		t.Fatal("no host profile in the report")
	}
	// Four of the five conversations involve the subject; the fifth must not.
	if rep.Summary.Classifications != 4 {
		t.Fatalf("in-scope verdicts = %d, want 4", rep.Summary.Classifications)
	}
	// brute_force, scan and the disagreeing suspicious verdict are notable;
	// the normal, agreeing one is not.
	if len(rep.NotableFlows) != 3 {
		t.Fatalf("notable flows = %d, want 3", len(rep.NotableFlows))
	}
	if !rep.NotableFlows[0].Disagreement {
		t.Fatal("the disagreeing verdict should rank first")
	}
	// The honesty notes travel with the JSON, not just the HTML.
	var sawPhase7 bool
	for _, n := range rep.Notes {
		if n.Code == "baseline_unavailable" {
			sawPhase7 = true
		}
	}
	if !sawPhase7 {
		t.Fatalf("Phase 7 unavailability note missing: %+v", rep.Notes)
	}
	if rep.Coverage.BaselineAvailable || rep.Coverage.AnomalyAvailable {
		t.Fatal("coverage must not claim a baseline")
	}
	// The active model set is recorded.
	if len(rep.Models) != 1 || rep.Models[0].ID != "heuristic-v1" {
		t.Fatalf("models = %+v", rep.Models)
	}
	// No-store, so a proxy cannot hand back a stale snapshot.
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestHostReportDefaultsToJSON(t *testing.T) {
	h := newReportServer(t)
	rr := get(t, h, "/api/v1/reports/host/10.10.10.22")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// ------------------------------------------------------- host report, HTML

func TestHostReportHTML(t *testing.T) {
	h := newReportServer(t)
	rr := get(t, h, "/api/v1/reports/host/10.10.10.22?format=html")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="synapseids-host-10.10.10.22-`) ||
		!strings.HasSuffix(cd, `.html"`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<!DOCTYPE html>", "10.10.10.22", "@media print",
		"NOT AVAILABLE IN THIS BUILD (Phase 7)", "</html>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HTML body missing %q", want)
		}
	}
	// Self-contained: nothing loadable.
	low := strings.ToLower(body)
	for _, bad := range []string{"http://", "https://", "<script", "<link", "<img"} {
		if strings.Contains(low, bad) {
			t.Fatalf("served HTML contains %q", bad)
		}
	}
}

// -------------------------------------------------------------- range report

func TestRangeReportBothFormats(t *testing.T) {
	h := newReportServer(t)

	rr := get(t, h, "/api/v1/reports/range?format=json")
	if rr.Code != http.StatusOK {
		t.Fatalf("json status = %d, body = %s", rr.Code, rr.Body.String())
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="synapseids-range-`) || !strings.HasSuffix(cd, `.json"`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("not a report: %v", err)
	}
	if rep.Scope.Kind != report.ScopeRange {
		t.Fatalf("scope kind = %q", rep.Scope.Kind)
	}
	if rep.Host != nil {
		t.Fatal("a range report must not carry a host profile")
	}
	if rep.Summary.Classifications != 5 {
		t.Fatalf("verdicts = %d, want all 5", rep.Summary.Classifications)
	}
	if !rep.Scope.Unbounded {
		t.Fatal("no from/to was supplied, so the window is unbounded")
	}

	rr = get(t, h, "/api/v1/reports/range?format=html")
	if rr.Code != http.StatusOK {
		t.Fatalf("html status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "Time-window investigation report") {
		t.Fatal("HTML range report missing its title")
	}
}

func TestRangeReportWindowAndClassFilter(t *testing.T) {
	h := newReportServer(t)
	from := reportBase.Format(time.RFC3339)
	to := reportBase.Add(2 * time.Second).Format(time.RFC3339)

	rr := get(t, h, "/api/v1/reports/range?from="+from+"&to="+to)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("not a report: %v", err)
	}
	if rep.Summary.Classifications != 3 {
		t.Fatalf("windowed verdicts = %d, want 3", rep.Summary.Classifications)
	}
	if rep.Scope.Unbounded {
		t.Fatal("from/to was supplied")
	}

	// parseClassFilters is reused verbatim, so class= means what it means on
	// /api/v1/classifications, and the report echoes it back.
	rr = get(t, h, "/api/v1/reports/range?class=scan")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	rep = report.Report{}
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("not a report: %v", err)
	}
	if rep.Summary.Classifications != 1 {
		t.Fatalf("class=scan verdicts = %d, want 1", rep.Summary.Classifications)
	}
	if rep.Scope.Filter != "class=scan" {
		t.Fatalf("filter echo = %q", rep.Scope.Filter)
	}

	// disagreement= and min_confidence= work too.
	rr = get(t, h, "/api/v1/reports/range?disagreement=true&min_confidence=10")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	rep = report.Report{}
	_ = json.Unmarshal(rr.Body.Bytes(), &rep)
	if rep.Summary.Disagreements != 1 || rep.Summary.Classifications != 1 {
		t.Fatalf("disagreement filter: %+v", rep.Summary)
	}
	if !strings.Contains(rep.Scope.Filter, "disagreement=true") ||
		!strings.Contains(rep.Scope.Filter, "min_confidence=0.1") {
		t.Fatalf("filter echo = %q", rep.Scope.Filter)
	}
}

// ------------------------------------------------------------------ errors

func TestReportBadRequests(t *testing.T) {
	h := newReportServer(t)
	cases := []struct {
		name, url string
		want      int
	}{
		{"bad ip", "/api/v1/reports/host/not-an-ip?format=json", http.StatusBadRequest},
		{"empty-ish ip", "/api/v1/reports/host/10.10.10.999", http.StatusBadRequest},
		{"host with a port", "/api/v1/reports/host/10.10.10.22:80", http.StatusBadRequest},
		{"unknown host", "/api/v1/reports/host/192.0.2.7", http.StatusNotFound},
		{"bad format", "/api/v1/reports/host/10.10.10.22?format=pdf", http.StatusBadRequest},
		{"bad range format", "/api/v1/reports/range?format=csv", http.StatusBadRequest},
		{"bad from", "/api/v1/reports/range?from=yesterday", http.StatusBadRequest},
		{"bad to", "/api/v1/reports/range?to=soon", http.StatusBadRequest},
		{"reversed range", "/api/v1/reports/range?from=2026-08-31T12:00:00Z&to=2026-08-30T12:00:00Z", http.StatusBadRequest},
		{"reversed range on host", "/api/v1/reports/host/10.10.10.22?from=2026-08-31T12:00:00Z&to=2026-08-30T12:00:00Z", http.StatusBadRequest},
		{"bad bucket", "/api/v1/reports/range?bucket=7s", http.StatusBadRequest},
		{"bad class", "/api/v1/reports/range?class=nonsense", http.StatusBadRequest},
		{"bad min_confidence", "/api/v1/reports/range?min_confidence=abc", http.StatusBadRequest},
		{"bad limit", "/api/v1/reports/range?limit=0", http.StatusBadRequest},
		{"negative limit", "/api/v1/reports/range?limit=-4", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := get(t, h, c.url)
			if rr.Code != c.want {
				t.Fatalf("GET %s = %d, want %d (body %q)", c.url, rr.Code, c.want, rr.Body.String())
			}
			// An error response is never an attachment.
			if cd := rr.Header().Get("Content-Disposition"); cd != "" {
				t.Fatalf("error response carries Content-Disposition %q", cd)
			}
		})
	}
}

// A canonicalising path value means ::ffff:10.10.10.22 and 10.10.10.22 address
// the same report rather than one 404ing.
func TestHostReportCanonicalisesTheAddress(t *testing.T) {
	h := newReportServer(t)
	rr := get(t, h, "/api/v1/reports/host/::ffff:10.10.10.22")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("not a report: %v", err)
	}
	if rep.Scope.Host != "10.10.10.22" {
		t.Fatalf("scope host = %q, want the canonical form", rep.Scope.Host)
	}
}

// The flow cap is caller-adjustable and the report says when it truncated.
func TestReportLimitTruncatesAndSaysSo(t *testing.T) {
	h := newReportServer(t)
	rr := get(t, h, "/api/v1/reports/range?limit=1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var rep report.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("not a report: %v", err)
	}
	if len(rep.NotableFlows) != 1 {
		t.Fatalf("notable flows = %d, want 1", len(rep.NotableFlows))
	}
	if !rep.Coverage.NotableFlowsTruncated || !rep.Coverage.Partial {
		t.Fatalf("coverage should flag truncation: %+v", rep.Coverage)
	}
	var sawTruncation bool
	for _, n := range rep.Notes {
		if n.Code == "flows_truncated" {
			sawTruncation = true
		}
	}
	if !sawTruncation {
		t.Fatalf("truncation note missing: %+v", rep.Notes)
	}
	// The documented default is 500 when no limit is given.
	if report.DefaultMaxFlows != 500 {
		t.Fatalf("documented flow cap changed: %d", report.DefaultMaxFlows)
	}
}

// With no insight index wired, a host report 404s rather than panicking, and a
// range report still renders from the store alone.
func TestReportsWithoutInsight(t *testing.T) {
	cfg := config.Default()
	store := storage.NewMem(10, 10)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	h := New(cfg, events.New(), store, rt, nil, nil, nil, nil, nil, nil, nil, nil).Handler()

	if rr := get(t, h, "/api/v1/reports/host/10.0.0.1"); rr.Code != http.StatusNotFound {
		t.Fatalf("host report without insight = %d, want 404", rr.Code)
	}
	rr := get(t, h, "/api/v1/reports/range?format=html")
	if rr.Code != http.StatusOK {
		t.Fatalf("range report without insight = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "aggregation index") {
		t.Fatal("a report built without an index should say so")
	}
}

// A hostile address never reaches a response header: the route re-parses the
// path value with net/netip before anything else, so a crafted "address" is a
// 400 and never becomes a Content-Disposition filename.
func TestReportRejectsHostileHostBeforeItBecomesAHeader(t *testing.T) {
	h := newReportServer(t)
	for _, raw := range []string{
		`%22%3E%3Cscript%3E`,            // "><script>
		`10.10.10.22%22%3B%20evil`,      // 10.10.10.22"; evil
		`a%0D%0ASet-Cookie:%20x=1`,      // CRLF header injection attempt
		`%3Cimg%20src=x%20onerror=1%3E`, // <img src=x onerror=1>
	} {
		rr := get(t, h, "/api/v1/reports/host/"+raw)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("GET .../%s = %d, want 400", raw, rr.Code)
		}
		if cd := rr.Header().Get("Content-Disposition"); cd != "" {
			t.Fatalf("Content-Disposition set on a rejected request: %q", cd)
		}
		// Whatever the response body is, no response header carries the payload.
		for k, vs := range rr.Header() {
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n<>\"") {
					t.Fatalf("header %s = %q carries raw payload bytes", k, v)
				}
			}
		}
	}
}
