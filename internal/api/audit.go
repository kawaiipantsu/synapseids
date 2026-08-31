package api

import (
	"net/http"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/audit"
)

// The audit trail is sensitive operational history — it names every model
// activation, dataset edit and training run, with timestamps. It inherits the
// same loopback-by-default, unauthenticated posture as the rest of the API
// (PROJECT.md §21); do not expose it beyond localhost until #58 lands auth.
//
// This route is read-only and there is deliberately no companion DELETE or
// PATCH: the log is append-only forever. An audit trail an operator can edit
// records nothing worth reading, so the API offers no way to rewrite history —
// only internal/audit's writers append, and only from a state change that
// actually happened.

// handleAudit returns the tail of the audit log, newest record first.
//
// GET /api/v1/audit
//   - limit        1..audit.MaxTail, default 100
//   - subject_type "model" | "dataset" | "training" | any future type
//   - subject      exact subject id (a model_id, a dataset ref, a run id)
//   - event        exact event name, e.g. ModelActivated
//   - from, to     RFC3339, inclusive
//
// The scan is bounded twice over: limit caps the records returned, and the
// reader never looks further back than audit.MaxScanBytes from the end of the
// file, so a long-lived daemon's log cannot turn one request into an unbounded
// read (§22).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil || s.audit.Path() == "" {
		http.Error(w, "audit log not available", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}
	limit := limitParam(r, audit.MaxTail)

	// subject_type is passed through as an opaque string rather than checked
	// against a known set, so a subject type added elsewhere (the review lines
	// of issue #42) is filterable here the day it is first written.
	recs, err := s.audit.Tail(limit, audit.Filter{
		SubjectType: strings.TrimSpace(q.Get("subject_type")),
		Subject:     strings.TrimSpace(q.Get("subject")),
		Event:       strings.TrimSpace(q.Get("event")),
		From:        tr.from,
		To:          tr.to,
	})
	if err != nil {
		http.Error(w, "audit log unreadable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"records":        recs,
		"count":          len(recs),
		"limit":          limit,
		"max_limit":      audit.MaxTail,
		"scan_bytes_cap": audit.MaxScanBytes,
	})
}
