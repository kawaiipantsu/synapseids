package api

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// handleTimeline serves GET /api/v1/timeline — classification volume bucketed
// over time (PROJECT.md §19.6).
//
//	bucket — 1s (default) | 10s | 1m
//	from   — RFC3339 lower bound (inclusive)
//	to     — RFC3339 upper bound (inclusive)
//	class  — restrict to one traffic-classes-v1 class
//	host   — restrict to conversations involving this address
//
// Unscoped queries are answered from the incrementally maintained ring in
// internal/insight: exact within its window, O(1) per record to keep up to date.
// A class= or host= scope cannot come from that ring — a ring per host would be
// unbounded — so those are bucketed on demand from the newest window of stored
// classifications, which is the same bounded scan the filtered
// /api/v1/classifications query does.
//
// There is no anomaly series. Anomaly scoring is Phase 7; the response says so
// with anomaly_available:false rather than shipping a fabricated zero line.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	bucketSec, ok := insight.ParseBucket(q.Get("bucket"))
	if !ok {
		http.Error(w, "bad bucket: want 1s, 10s or 1m", http.StatusBadRequest)
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}
	class := q.Get("class")
	if class != "" && !validClassName(class) {
		http.Error(w, "unknown class name", http.StatusBadRequest)
		return
	}
	host := ""
	if v := q.Get("host"); v != "" {
		var okHost bool
		host, okHost = parseHostParam(w, v)
		if !okHost {
			return
		}
	}

	if class == "" && host == "" {
		writeJSON(w, http.StatusOK, s.insight.Timeline(bucketSec, tr.from, tr.to))
		return
	}

	keep := func(c storage.Classification) bool {
		if class != "" && c.Result.Class != class {
			return false
		}
		if host != "" && c.InitiatorIP != host && c.ResponderIP != host {
			return false
		}
		return true
	}
	writeJSON(w, http.StatusOK, insight.BucketSamples(
		s.store.RecentClassifications(hostScanLimit), bucketSec, tr.from, tr.to, keep))
}
