package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/training"
)

// The training-run routes (PROJECT.md §19.8; issue #35; ADR 0019).
//
// The Go daemon does not run Python and does not launch training (PROJECT.md
// §5.4). synapse-trainer runs as a separate process, registers a run here, and
// POSTs one progress dict per epoch plus a terminal {"event":"done"} dict. The
// daemon mirrors that state and keeps a bounded history; the SPA polls
// GET /api/v1/training/{id} every ~1.5 s while a run is active. There is no
// Training* event-envelope: event-envelope-v1 is frozen and has no such member,
// so nothing is published on the event bus — the audit log is the record
// (ADR 0019, §28.5-6).
//
// The three POST routes are the trainer-facing write surface. They are
// unauthenticated and rely on the daemon binding to loopback by default, the
// same posture as POST /api/v1/datasets and the model activate routes.
// TODO(#58): a trainer on another host needs auth (a bearer token or mTLS)
// before these are exposed off loopback.

// maxTrainingRegisterBody bounds a register request: a name, a version string
// and the resolved recipe JSON — kilobytes.
const maxTrainingRegisterBody = 1 << 18

// maxTrainingProgressBody bounds one progress dict. The largest is the terminal
// dict: per-class metrics plus a 7x7 confusion matrix plus test metrics — still
// small, but allow room.
const maxTrainingProgressBody = 1 << 20

// trainingCreateRequest is the POST /api/v1/training body.
type trainingCreateRequest struct {
	Name           string          `json:"name"`
	Recipe         json.RawMessage `json:"recipe"`
	EpochsTotal    int             `json:"epochs_total"`
	TrainerVersion string          `json:"trainer_version"`
}

// trainingFailRequest is the POST /api/v1/training/{id}/fail body.
type trainingFailRequest struct {
	Reason string `json:"reason"`
}

// trainingStatus maps a training-store error to its HTTP status.
func trainingStatus(err error) int {
	switch {
	case errors.Is(err, training.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, training.ErrClosed):
		return http.StatusConflict
	case errors.Is(err, training.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// handleTrainings serves GET /api/v1/training — every run, newest first. With no
// training store wired it returns an empty list rather than 503, so the view
// always renders.
//
//	limit  newest N runs (default 100, max 500)
func (s *Server) handleTrainings(w http.ResponseWriter, r *http.Request) {
	runs := []training.Run{}
	if s.tr != nil {
		if got := s.tr.List(); got != nil {
			runs = got
		}
	}
	limit := limitParam(r, 500)
	if len(runs) > limit {
		runs = runs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"runs":                runs,
		"history_cap":         training.HistoryCap,
		"stale_after_seconds": int(training.StaleAfter.Seconds()),
	})
}

// handleTraining serves GET /api/v1/training/{id} — one run with its full
// history and final block. This is what the SPA polls.
//
//	404 unknown id
//	503 no training store wired
func (s *Server) handleTraining(w http.ResponseWriter, r *http.Request) {
	if s.tr == nil {
		http.Error(w, "training store not available", http.StatusServiceUnavailable)
		return
	}
	run, ok := s.tr.Get(r.PathValue("id"))
	if !ok {
		http.Error(w, "unknown training run "+r.PathValue("id"), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleTrainingCreate serves POST /api/v1/training — the trainer registers a
// run and gets back an id and the URL to POST progress to.
//
//	201 + {"id": …, "progress_url": …}
//	400 bad body / bad metadata
//	503 no training store wired
func (s *Server) handleTrainingCreate(w http.ResponseWriter, r *http.Request) {
	if s.tr == nil {
		http.Error(w, "training store not available", http.StatusServiceUnavailable)
		return
	}

	var req trainingCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTrainingRegisterBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Recipe) > 0 && !json.Valid(req.Recipe) {
		http.Error(w, "recipe is not valid JSON", http.StatusBadRequest)
		return
	}

	run, err := s.tr.Start(training.Meta{
		Name:           req.Name,
		Recipe:         req.Recipe,
		EpochsTotal:    req.EpochsTotal,
		TrainerVersion: req.TrainerVersion,
	})
	if err != nil {
		http.Error(w, err.Error(), trainingStatus(err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           run.ID,
		"progress_url": baseURL(r) + "/api/v1/training/" + run.ID + "/progress",
	})
}

// handleTrainingProgress serves POST /api/v1/training/{id}/progress — one JSON
// object per request (a single trailing newline is tolerated, so the trainer's
// JSON-line writer works unchanged). A dict whose "event" is "done" finishes the
// run and stores its "metrics" object as `final`; anything else is appended to
// the run's history.
//
//	202 accepted
//	400 body is not a JSON object
//	404 unknown id
//	409 the run has already finished
//	503 no training store wired
func (s *Server) handleTrainingProgress(w http.ResponseWriter, r *http.Request) {
	if s.tr == nil {
		http.Error(w, "training store not available", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTrainingProgressBody))
	if err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var dict map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(body), &dict); err != nil {
		http.Error(w, "progress body must be one JSON object: "+err.Error(), http.StatusBadRequest)
		return
	}

	var event string
	if raw, ok := dict["event"]; ok {
		_ = json.Unmarshal(raw, &event)
	}

	if event == "done" {
		final := dict["metrics"]
		if len(final) == 0 {
			// No "metrics" wrapper — store the whole dict so nothing is lost.
			final = bytes.TrimSpace(body)
		}
		if err := s.tr.Finish(id, final); err != nil {
			http.Error(w, err.Error(), trainingStatus(err))
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "completed"})
		return
	}

	if err := s.tr.AppendProgress(id, bytes.TrimSpace(body)); err != nil {
		http.Error(w, err.Error(), trainingStatus(err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// handleTrainingFail serves POST /api/v1/training/{id}/fail — the trainer
// reports that the run died.
//
//	202 accepted
//	400 bad body
//	404 unknown id
//	409 the run has already finished
//	503 no training store wired
func (s *Server) handleTrainingFail(w http.ResponseWriter, r *http.Request) {
	if s.tr == nil {
		http.Error(w, "training store not available", http.StatusServiceUnavailable)
		return
	}
	var req trainingFailRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.tr.Fail(r.PathValue("id"), req.Reason); err != nil {
		http.Error(w, err.Error(), trainingStatus(err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "failed"})
}

// baseURL reconstructs the scheme://host the request came in on, honouring a
// reverse proxy's X-Forwarded-Proto. It is only used to hand the trainer a
// convenient absolute progress_url; the trainer already knows the daemon's base
// URL (it was given --report-to), so this is a convenience, not a contract.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	}
	return scheme + "://" + r.Host
}
