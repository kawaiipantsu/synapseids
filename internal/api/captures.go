package api

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/capture"
)

// handleCaptures serves GET /api/v1/captures — the live capture manager's
// per-source status (PROJECT.md §18, §19.14). With no capture configured it
// returns an empty JSON array, never 503, so the capture-sources UI can always
// render.
func (s *Server) handleCaptures(w http.ResponseWriter, _ *http.Request) {
	list := []capture.SourceStatus{}
	if s.cap != nil {
		if got := s.cap.List(); got != nil {
			list = got
		}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleCapture serves GET /api/v1/captures/{name} — one source, or 404.
func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		http.Error(w, "capture source not found", http.StatusNotFound)
		return
	}
	st, ok := s.cap.Get(r.PathValue("name"))
	if !ok {
		http.Error(w, "capture source not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// TODO(#32): POST /api/v1/captures and DELETE /api/v1/captures/{name} for
// runtime add/remove, once the capture-sources UI needs them. capture.Manager
// already has Add/Remove.
