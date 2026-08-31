package api

// Traffic matrix (issue #68): who talks to whom over the observed hosts.
//
// Two sources answer this route, chosen by whether the request is filtered — the
// same split GET /api/v1/timeline already makes, and for the same reason:
//
//   - **unfiltered** → the bounded table internal/insight maintains incrementally
//     off the packet path. O(1) per record to keep current, and exact for every
//     pair it still holds.
//   - **filtered** (class=, model=, min_confidence=, disagreement=, sensor=,
//     location=, from=, to=) → bucketed on demand from the newest window of
//     stored records, because a table per filter combination would be unbounded.
//
// Either way the response says which source answered it and whether it is
// complete: `source`, `partial`, `pairs_evicted`, `truncated` and `scanned`. The
// matrix is a bounded top-N of the heaviest conversations, never a full
// hosts × hosts grid — see internal/insight/matrix.go and ADR 0026 for why.
//
// Addresses in the response are packet-derived strings emitted as plain JSON
// values, exactly as the host routes emit them (§21, §28.11).

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// matrixScanLimit is how many recent stored flow records a filtered matrix walks.
// Like classFilterScan and hostScanLimit, it is the memory store's stand-in for
// an index; a predicate-pushdown backend will replace it.
const matrixScanLimit = 5000

// handleMatrix serves GET /api/v1/matrix.
//
//	limit          — max pairs returned (default 100, cap 2000; 0 is not "all")
//	sort           — flows (default) | bytes | last_seen
//	from, to       — RFC3339 inclusive bounds (forces the scan source)
//	class          — one traffic-classes-v1 class
//	model          — a model id that scored the flow
//	min_confidence — 0..1 (or 0..100) verdict score floor
//	disagreement   — true for model-disagreement pairs only
//	sensor         — scope to one sensor id (see topology.go on attribution)
//	location       — scope to a location's connected sensors
func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	ord, ok := insight.ParseMatrixSort(q.Get("sort"))
	if !ok {
		http.Error(w, "bad sort: want flows, bytes or last_seen", http.StatusBadRequest)
		return
	}
	f, ok := s.parseClassFilters(w, q)
	if !ok {
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}
	limit := limitParam(r, 2000)

	// Unfiltered and unbounded in time: answer from the incremental table.
	if f.empty() && tr.from.IsZero() && tr.to.IsZero() {
		writeJSON(w, http.StatusOK, s.insight.Matrix(limit, ord))
		return
	}

	// Filtered: fold the newest window of stored flows, joined to their verdicts.
	rows := s.store.RecentFlows(matrixScanLimit)
	var verdict map[uint64]storage.Classification
	if !f.empty() {
		cls := s.store.RecentClassifications(matrixScanLimit)
		verdict = make(map[uint64]storage.Classification, len(cls))
		for _, c := range cls {
			// Newest first: keep the first verdict seen for a flow.
			if _, seen := verdict[c.FlowID]; !seen {
				verdict[c.FlowID] = c
			}
		}
	}

	acc := insight.NewMatrixAccumulator(0)
	for i := range rows {
		fr := &rows[i]
		if !tr.contains(fr.LastSeen) {
			continue
		}
		var cl *storage.Classification
		if verdict != nil {
			c, found := verdict[fr.ID]
			if !found || !f.match(c) {
				continue
			}
			cl = &c
		}
		acc.Add(fr, cl)
	}
	// The scanned window is itself capped, so a full scan means older traffic
	// exists that this answer does not cover. Say so rather than implying the
	// window is the whole history.
	writeJSON(w, http.StatusOK, acc.Matrix(limit, ord, len(rows) >= matrixScanLimit))
}
