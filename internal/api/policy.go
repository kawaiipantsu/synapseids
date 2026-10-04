package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/policy"
	"github.com/kawaiipantsu/synapseids/internal/reputation"
)

// SetPolicy wires the daemon's shared policy and advisory reputation service.
func (s *Server) SetPolicy(p *policy.Store, rep *reputation.Service) {
	s.policy = p
	s.reputation = rep
}
func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"policy": s.policy.Get(), "providers": s.reputation.Status(), "suppression_direction": "initiator", "applies": "future classifications; retained history is unchanged"})
}
func (s *Server) handlePolicyWrite(w http.ResponseWriter, r *http.Request) {
	if s.policy == nil {
		http.Error(w, "policy store unavailable", http.StatusServiceUnavailable)
		return
	}
	var d policy.Document
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&d); e != nil {
		http.Error(w, "invalid policy document", http.StatusBadRequest)
		return
	}
	saved, e := s.policy.Replace(d)
	if e != nil {
		status := http.StatusBadRequest
		if errors.Is(e, policy.ErrConflict) {
			status = http.StatusConflict
		}
		http.Error(w, e.Error(), status)
		return
	}
	s.audit.LogSubject("PolicyUpdated", "local", "policy", "network-policy", "CIDR and reputation policy updated")
	writeJSON(w, http.StatusOK, saved)
}
