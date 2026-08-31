package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/report"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Downloadable investigation reports (PROJECT.md §19.3, §19.4; issue #66,
// ADR 0023).
//
// An operator who has framed a host or a time window in the SPA needs to hand
// the result to someone else. These two routes render the same live state the
// /api/v1/hosts* and /api/v1/timeline routes serve, but as one self-contained
// artefact: JSON for a ticket system, or a single standalone HTML file with no
// external references.
//
// # Security posture
//
// Read-only, so — like the host routes — they need no explicit-action gate. But a
// report is a *concentrated* dump of sensitive telemetry: one request yields
// every observed peer of a host, its ports, its volume, its verdicts and the raw
// feature values behind them, in a file designed to be forwarded. It inherits the
// daemon's loopback-only default and the standing requirement for an
// authenticating proxy on any non-loopback listener (§21). That concentration is
// a stronger argument for the API auth work (#58) than the individual routes are.
//
// Every value in a rendered report is packet- or request-derived and therefore
// untrusted (§28.11). The HTML path renders through html/template; the
// Content-Disposition filename is built by report.Report.Filename, which reduces
// the scope segment to [a-z0-9._-] so a crafted address can neither escape the
// quoted header parameter nor produce a traversal when the browser saves it.

// reportFormats are the supported format= values.
const (
	formatJSON = "json"
	formatHTML = "html"
)

// handleHostReport serves GET /api/v1/reports/host/{ip}.
//
//	format — json (default) | html
//	from   — RFC3339 lower bound (inclusive)
//	to     — RFC3339 upper bound (inclusive)
//	bucket — timeline resolution: 1s | 10s | 1m (default 10s)
//	limit  — notable-flow cap (default 500, max 2000)
//
// It also accepts the /api/v1/classifications filter dialect (class, model,
// min_confidence, disagreement), so an operator does not learn a second one.
func (s *Server) handleHostReport(w http.ResponseWriter, r *http.Request) {
	ip, ok := hostPathValue(w, r)
	if !ok {
		return
	}
	opt, format, ok := s.reportOptions(w, r)
	if !ok {
		return
	}
	opt.Scope = report.ScopeHost
	opt.Host = ip
	s.writeReport(w, opt, format)
}

// handleRangeReport serves GET /api/v1/reports/range with the same parameters
// minus the path address.
func (s *Server) handleRangeReport(w http.ResponseWriter, r *http.Request) {
	opt, format, ok := s.reportOptions(w, r)
	if !ok {
		return
	}
	opt.Scope = report.ScopeRange
	s.writeReport(w, opt, format)
}

// reportOptions parses every query parameter both routes share, writing a 400
// and returning ok=false on the first bad value.
func (s *Server) reportOptions(w http.ResponseWriter, r *http.Request) (report.Options, string, bool) {
	q := r.URL.Query()
	var opt report.Options

	format := q.Get("format")
	switch format {
	case "":
		format = formatJSON
	case formatJSON, formatHTML:
	default:
		http.Error(w, "bad format: want json or html", http.StatusBadRequest)
		return opt, "", false
	}

	tr, ok := parseTimeRange(w, q)
	if !ok {
		return opt, "", false
	}
	opt.From, opt.To = tr.from, tr.to

	bucketSec, ok := insight.ParseBucket(q.Get("bucket"))
	if !ok {
		http.Error(w, "bad bucket: want 1s, 10s or 1m", http.StatusBadRequest)
		return opt, "", false
	}
	if q.Get("bucket") == "" {
		bucketSec = report.DefaultBucketSec
	}
	opt.BucketSec = bucketSec

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "bad limit: want a positive integer", http.StatusBadRequest)
			return opt, "", false
		}
		opt.MaxFlows = n // report.Options clamps to report.MaxFlowsCap
	}

	f, ok := s.parseClassFilters(w, q)
	if !ok {
		return opt, "", false
	}
	if !f.empty() {
		// Hand the report the same predicate /api/v1/classifications applies, so
		// a filtered report and a filtered list agree exactly.
		opt.Keep = f.match
		opt.FilterDesc = f.describe()
	}
	return opt, format, true
}

// writeReport builds and renders a report, or maps the build error to a status.
func (s *Server) writeReport(w http.ResponseWriter, opt report.Options, format string) {
	rep, err := report.Build(report.Sources{
		Store:   s.store,
		Insight: s.insight,
		Runtime: s.rt,
	}, opt)
	switch {
	case errors.Is(err, report.ErrUnknownHost):
		http.Error(w, "host not found", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "could not build report", http.StatusInternalServerError)
		log.Printf("api: build report: %v", err)
		return
	}

	if format == formatHTML {
		body, err := rep.HTML()
		if err != nil {
			http.Error(w, "could not render report", http.StatusInternalServerError)
			log.Printf("api: render report html: %v", err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setAttachment(w, rep.Filename("html"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// The JSON body is the Report struct verbatim; only the headers differ from
	// any other JSON route, so the browser downloads instead of rendering.
	setAttachment(w, rep.Filename("json"))
	writeJSON(w, http.StatusOK, rep)
}

// setAttachment marks the response as a download. name is already reduced to
// [a-z0-9._-] by report.Report.Filename, so the quoted parameter cannot be
// broken out of; the guard here is belt-and-braces for that invariant.
func setAttachment(w http.ResponseWriter, name string) {
	if strings.ContainsAny(name, "\"\\\r\n") {
		name = "synapseids-report" // unreachable; never emit a malformed header
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	// A report is a point-in-time snapshot; never let a proxy serve a stale one.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// describe renders the active filters as a stable, human-readable string for
// the report's scope block. It is deliberately not the raw query string: only
// values the parser already validated are echoed, in a fixed order.
func (f classFilters) describe() string {
	parts := make([]string, 0, 4)
	if f.class != "" {
		parts = append(parts, "class="+f.class)
	}
	if f.model != "" {
		parts = append(parts, "model="+f.model)
	}
	if f.hasMinConf {
		parts = append(parts, fmt.Sprintf("min_confidence=%.3g", f.minConf))
	}
	if f.disagreement {
		parts = append(parts, "disagreement=true")
	}
	return strings.Join(parts, " ")
}

// compile-time assurance that the report package's predicate signature still
// matches classFilters.match, which is what keeps the two filter dialects the
// same one.
var _ func(storage.Classification) bool = classFilters{}.match
