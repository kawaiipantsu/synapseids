package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// The human review routes (PROJECT.md §16, §19.3; issues #42, #64).
//
//	GET  /api/v1/review/queue          flows still needing a human, ranked
//	GET  /api/v1/review                the review records, newest decision first
//	GET  /api/v1/review/stats          counts per §16 state
//	GET  /api/v1/review/{flow_id}      one review record
//	PUT  /api/v1/review/{flow_id}      record or correct a decision (POST too)
//
// PUT/POST are state-changing and unauthenticated for now — the same posture as
// POST /api/v1/datasets, POST /api/v1/replay, POST /api/v1/captures and the
// model activate/deactivate routes, where binding to loopback by default is the
// only control. A review write appends to the audit log and publishes
// events.ReviewUpdated.
// TODO(#58): gate behind auth/RBAC before exposing the API off loopback.
//
// The §16 invariant is visible on the wire: every response carries
// predicted_class / predicted_score / model_id next to human_label, and no
// request body has a field that could set them. review.Store owns that
// structurally; this layer simply has nothing to send.

// maxReviewBody bounds a review write. The body is a state, a class name and a
// note — well under a kilobyte in practice.
const maxReviewBody = 1 << 14

// reviewQueueScan is how many recent verdicts the queue walks before ranking.
// The memory store has no index, so this is a linear scan of the newest window,
// the same shape and size as classFilterScan. Ranking happens after the scan, so
// a wider window changes what can appear in the queue, not the order within it.
const reviewQueueScan = 20_000

// reviewWriteRequest is the PUT/POST /api/v1/review/{flow_id} body.
//
// Note what is absent: predicted_class, predicted_score and model_id. The
// original model prediction is captured by the daemon at first review and can
// never be supplied, corrected or overwritten by a client (PROJECT.md §16).
type reviewWriteRequest struct {
	State      string `json:"state"`
	HumanLabel string `json:"human_label"`
	Note       string `json:"note"`
}

// reviewStatus maps a review error to its HTTP status.
func reviewStatus(err error) int {
	switch {
	case errors.Is(err, review.ErrNoFlow):
		return http.StatusNotFound
	case errors.Is(err, review.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// reviewVocabulary is the enum block every review response carries, so the SPA
// never hardcodes the state list or the class picker.
func reviewVocabulary() map[string]any {
	return map[string]any{
		"states":  review.StateNames(),
		"classes": review.ClassNames(),
		"sorts":   review.SortNames(),
	}
}

// handleReviewQueue serves GET /api/v1/review/queue — the flows that still need
// a human, ranked (issue #64).
//
//	sort=uncertainty  smallest top1-top2 margin first (active learning)
//	sort=recent       newest verdict first (default)
//	sort=disagreement flows the ensemble disagreed on first
//
// class, model, min_confidence and disagreement are parsed by the shared
// parseClassFilters, so they mean exactly what they mean on
// GET /api/v1/classifications.
//
// Flows with a terminal review state (correct, incorrect, ignored_pattern) are
// excluded; `unsure` stays in the queue by design.
//
//	400 bad sort, bad class, bad min_confidence
//	503 no review store wired
func (s *Server) handleReviewQueue(w http.ResponseWriter, r *http.Request) {
	if s.rv == nil {
		http.Error(w, "review store not available", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()

	sortBy, ok := review.ParseSort(q.Get("sort"))
	if !ok {
		http.Error(w, fmt.Sprintf("unknown sort %q (want one of %s)", q.Get("sort"), strings.Join(review.SortNames(), ", ")), http.StatusBadRequest)
		return
	}
	f, ok := s.parseClassFilters(w, q)
	if !ok {
		return // parseClassFilters already wrote a 400
	}

	rows := s.store.RecentClassifications(reviewQueueScan)
	if !f.empty() {
		kept := make([]storage.Classification, 0, len(rows))
		for _, c := range rows {
			if f.match(c) {
				kept = append(kept, c)
			}
		}
		rows = kept
	}

	items := s.rv.Queue(rows, review.QueueOptions{Sort: sortBy, Limit: limitParam(r, 2000)})
	writeJSON(w, http.StatusOK, map[string]any{
		"queue":      items,
		"sort":       string(sortBy),
		"scanned":    len(rows),
		"vocabulary": reviewVocabulary(),
		// The ranking formula, served next to the ranking, so an operator can
		// read what "uncertainty 0.98" means without opening the source.
		"ranking": map[string]any{
			"uncertainty": "1 - (p_top1 - p_top2) over the authoritative model's 7-class probability vector; larger = review sooner",
			"entropy":     "normalised Shannon entropy over the 7 classes, 0 (certain) .. 1 (uniform)",
		},
	})
}

// handleReviews serves GET /api/v1/review — the stored decisions, most recently
// updated first, optionally filtered by state.
//
//	400 unknown state
//	503 no review store wired
func (s *Server) handleReviews(w http.ResponseWriter, r *http.Request) {
	if s.rv == nil {
		http.Error(w, "review store not available", http.StatusServiceUnavailable)
		return
	}
	f := review.Filter{Limit: limitParam(r, 5000)}
	if v := r.URL.Query().Get("state"); v != "" {
		st := review.State(v)
		if !st.Valid() {
			http.Error(w, badStateMessage(v), http.StatusBadRequest)
			return
		}
		f.State = st
	}
	list := s.rv.List(f)
	if list == nil {
		list = []review.Review{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reviews":    list,
		"stats":      s.rv.Stats(),
		"vocabulary": reviewVocabulary(),
	})
}

// handleReviewStats serves GET /api/v1/review/stats — counts per §16 state.
//
//	503 no review store wired
func (s *Server) handleReviewStats(w http.ResponseWriter, _ *http.Request) {
	if s.rv == nil {
		http.Error(w, "review store not available", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":      s.rv.Stats(),
		"vocabulary": reviewVocabulary(),
	})
}

// handleReview serves GET /api/v1/review/{flow_id} — one review record.
//
//	400 the path segment is not a flow id
//	404 the flow has never been reviewed
//	503 no review store wired
func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if s.rv == nil {
		http.Error(w, "review store not available", http.StatusServiceUnavailable)
		return
	}
	id, ok := reviewFlowID(w, r)
	if !ok {
		return
	}
	rec, found := s.rv.Get(id)
	if !found {
		http.Error(w, fmt.Sprintf("flow %d has not been reviewed", id), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"review":     rec,
		"vocabulary": reviewVocabulary(),
	})
}

// handleReviewWrite serves PUT and POST /api/v1/review/{flow_id}: it records an
// operator's decision, or corrects an earlier one.
//
//	200 + {"review": …} the flow already had a review (a correction)
//	201 + {"review": …} first review of this flow
//	400 bad body, unknown state, a human_label that is not a traffic-classes-v1
//	    class, or a state/label combination that contradicts itself
//	404 the flow has no stored classification — it was never classified, or its
//	    verdict has already been evicted from the bounded ring, so there is no
//	    prediction to review against
//	503 no review store wired
func (s *Server) handleReviewWrite(w http.ResponseWriter, r *http.Request) {
	if s.rv == nil {
		http.Error(w, "review store not available", http.StatusServiceUnavailable)
		return
	}
	id, ok := reviewFlowID(w, r)
	if !ok {
		return
	}

	var req reviewWriteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReviewBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	st := review.State(strings.TrimSpace(req.State))
	if !st.Valid() {
		http.Error(w, badStateMessage(req.State), http.StatusBadRequest)
		return
	}

	_, existed := s.rv.Get(id)
	rec, err := s.rv.Put(id, st, req.HumanLabel, req.Note)
	if err != nil {
		http.Error(w, err.Error(), reviewStatus(err))
		return
	}

	code := http.StatusCreated
	if existed {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{
		"review":     rec,
		"vocabulary": reviewVocabulary(),
	})
}

// badStateMessage echoes the valid set, which is the only useful thing to say.
func badStateMessage(got string) string {
	return fmt.Sprintf("unknown review state %q (PROJECT.md §16 states: %s)", got, strings.Join(review.StateNames(), ", "))
}

// reviewFlowID parses the {flow_id} path segment. On a bad value it writes a 400
// and returns ok=false.
func reviewFlowID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	raw := r.PathValue("flow_id")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		http.Error(w, fmt.Sprintf("bad flow id %q — want a positive integer", raw), http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
