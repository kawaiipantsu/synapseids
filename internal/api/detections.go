package api

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
)

// The detection feed (issue #117, PROJECT.md §17; ADR 0027).
//
// Detections are sensitive network telemetry — they name the addresses the
// sensor believes are attacking or being attacked. These routes are read-only
// and inherit the daemon's loopback-only default posture; put an authenticating
// proxy in front of any non-loopback listener (§21).
//
// Every address, port and protocol in a response is a packet-derived string or
// number emitted as a plain JSON value, never interpolated into markup, a header
// or a query (§28.11).

// detectionsLimitMax caps limit= on GET /api/v1/detections. It is lower than the
// classification routes' 5000 because a detection is already an aggregate: the
// store retains at most alerts.max_recent (default 1000) of them.
const detectionsLimitMax = 1000

// detectionParams is the complete set of query parameters this route accepts.
//
// Unlike the older collection routes, GET /api/v1/detections rejects an unknown
// parameter and an unparseable value with a 400 instead of ignoring it. That is
// deliberate: a typo in `min_confidence` on a route whose whole job is "show me
// what matters" would silently widen the result to everything, and an operator
// would read a filtered-looking page that is not filtered.
var detectionParams = map[string]bool{
	"limit": true, "class": true, "severity": true, "min_confidence": true, "since": true,
}

// handleDetections serves GET /api/v1/detections.
//
//	limit          — max detections (default 100, cap 1000)
//	class          — a traffic-classes-v1 class name
//	severity       — low | medium | high | critical (derived from the class)
//	min_confidence — 0..1, or 0..100 read as a percentage
//	since          — RFC3339; keeps detections ACTIVE at or after it (last_ts)
func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	q, ok := parseDetectionQuery(w, r.URL.Query())
	if !ok {
		return
	}
	// A nil store answers with an empty page rather than a 503: "no detections"
	// is the honest answer for a daemon running without an alert store, and it is
	// indistinguishable from a quiet network only in that both are quiet.
	writeJSON(w, http.StatusOK, s.alerts.Detections(q))
}

// handleDetection serves GET /api/v1/detections/{id}. It mirrors
// GET /api/v1/flows/{id}: a non-numeric id is a 400, an unknown one a 404.
func (s *Server) handleDetection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad detection id", http.StatusBadRequest)
		return
	}
	d, found := s.alerts.Detection(id)
	if !found {
		http.Error(w, "detection not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// parseDetectionQuery validates every parameter, writing a 400 and returning
// ok=false on the first problem.
func parseDetectionQuery(w http.ResponseWriter, v url.Values) (alert.Query, bool) {
	var q alert.Query

	for name := range v {
		if !detectionParams[name] {
			http.Error(w, "unknown query parameter: "+name, http.StatusBadRequest)
			return q, false
		}
	}

	q.Limit = defaultLimit
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, "bad limit: want a positive integer", http.StatusBadRequest)
			return q, false
		}
		if n > detectionsLimitMax {
			n = detectionsLimitMax
		}
		q.Limit = n
	}

	if raw := v.Get("class"); raw != "" {
		if !validClassName(raw) {
			http.Error(w, "unknown class name", http.StatusBadRequest)
			return q, false
		}
		q.Class = raw
	}

	if raw := v.Get("severity"); raw != "" {
		sev := alert.Severity(raw)
		if !alert.ValidSeverity(sev) {
			http.Error(w, "bad severity: want low, medium, high or critical", http.StatusBadRequest)
			return q, false
		}
		q.Severity = sev
	}

	if raw := v.Get("min_confidence"); raw != "" {
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil || n < 0 || n > 100 {
			http.Error(w, "bad min_confidence: want 0..1 or a 0..100 percentage", http.StatusBadRequest)
			return q, false
		}
		if n > 1 { // accept a 0..100 percentage, like /api/v1/classifications
			n /= 100
		}
		q.MinConfidence, q.HasMinConfidence = n, true
	}

	if raw := v.Get("since"); raw != "" {
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			http.Error(w, "bad since: want an RFC3339 timestamp", http.StatusBadRequest)
			return q, false
		}
		q.Since = ts
	}

	return q, true
}
