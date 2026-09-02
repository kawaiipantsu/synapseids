package api

import (
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/modelrun"
	"github.com/kawaiipantsu/synapseids/internal/registry"
)

// The model routes are state-changing and unauthenticated for now — the same
// posture as POST /api/v1/replay, where loopback-by-default is the only control.
// When auth.enabled, activate/deactivate require role `admin`; otherwise the
// loopback bind is the only control (issue #58).

// runtimeInfo says whether a registry entry is the model currently loaded in the
// live inference.Runtime, and in what role.
type runtimeInfo struct {
	Loaded bool   `json:"loaded"`
	Role   string `json:"role,omitempty"`
}

// modelView is a registry entry plus its live-runtime status (PROJECT.md §19.12).
type modelView struct {
	registry.Entry
	Runtime runtimeInfo `json:"runtime"`
}

// runtimeModel is one classifier currently loaded in the Runtime, registered or
// not (the heuristic never is).
type runtimeModel struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Role       string `json:"role"`
	Registered bool   `json:"registered"`
	// UnsupportedClasses names traffic-classes-v1 classes this model never emits,
	// so the UI can show a labelled gap rather than implying full coverage. The
	// Phase 1 heuristic reports "web_attack" here (issue #134). Omitted when the
	// model claims full coverage.
	UnsupportedClasses []string `json:"unsupported_classes,omitempty"`
}

// classCoverageReporter is implemented by a model that knows it cannot produce
// some traffic-classes-v1 classes (the Phase 1 heuristic and web_attack, issue
// #134). A model that does not implement it is assumed to cover the full vector.
type classCoverageReporter interface{ UnsupportedClasses() []string }

// loadedRoles maps model ID -> role for every model live in the Runtime:
// supervised classifiers, the anomaly-role autoencoder, and the sequence-role
// temporal peers.
func (s *Server) loadedRoles() map[string]string {
	out := map[string]string{}
	if s.rt == nil {
		return out
	}
	for _, m := range s.rt.Models() {
		out[m.ID()] = string(m.Role())
	}
	for _, m := range s.rt.AnomalyModels() {
		out[m.ID()] = string(m.Role())
	}
	for _, m := range s.rt.SequenceModels() {
		out[m.ID()] = string(m.Role())
	}
	return out
}

func (s *Server) view(e registry.Entry, loaded map[string]string) modelView {
	v := modelView{Entry: e}
	if role, ok := loaded[e.ModelID]; ok {
		v.Runtime = runtimeInfo{Loaded: true, Role: role}
	}
	return v
}

func (s *Server) registryEntries() []registry.Entry {
	if s.reg == nil {
		return nil
	}
	return s.reg.List()
}

// handleModels replaces the thin model list with the registry view plus the set
// of classifiers actually loaded in the Runtime (PROJECT.md §12, §19.12).
//
// GET /api/v1/models
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	loaded := s.loadedRoles()

	entries := s.registryEntries()
	views := make([]modelView, 0, len(entries))
	registered := map[string]bool{}
	for _, e := range entries {
		views = append(views, s.view(e, loaded))
		registered[e.ModelID] = true
	}

	rtModels := make([]runtimeModel, 0, len(loaded))
	for _, m := range s.rtModels() {
		rm := runtimeModel{
			ID: m.ID(), Family: m.Family(), Role: string(m.Role()),
			Registered: registered[m.ID()],
		}
		if cr, ok := m.(classCoverageReporter); ok {
			if u := cr.UnsupportedClasses(); len(u) > 0 {
				rm.UnsupportedClasses = u
			}
		}
		rtModels = append(rtModels, rm)
	}
	if s.rt != nil {
		for _, m := range s.rt.AnomalyModels() {
			rtModels = append(rtModels, runtimeModel{
				ID: m.ID(), Family: m.Family(), Role: string(m.Role()),
				Registered: registered[m.ID()],
			})
		}
		for _, m := range s.rt.SequenceModels() {
			rtModels = append(rtModels, runtimeModel{
				ID: m.ID(), Family: m.Family(), Role: string(m.Role()),
				Registered: registered[m.ID()],
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"models":  views,
		"runtime": rtModels,
	})
}

func (s *Server) rtModels() []inference.Classifier {
	if s.rt == nil {
		return nil
	}
	return s.rt.Models()
}

// handleModel returns one registry entry with its lineage chain (root -> id) and
// its direct children.
//
// GET /api/v1/models/{id}
func (s *Server) handleModel(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil {
		http.Error(w, "model registry not available", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	e, ok := s.reg.Get(id)
	if !ok {
		http.Error(w, "unknown model id", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entry":    s.view(e, s.loadedRoles()),
		"lineage":  s.reg.Lineage(id),
		"children": s.reg.Children(id),
	})
}

// handleModelLineage returns the derived-from chain for one model (root -> id),
// its direct children, and the whole registry lineage forest for context
// (PROJECT.md §15, §19.12).
//
// GET /api/v1/models/{id}/lineage
func (s *Server) handleModelLineage(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil {
		http.Error(w, "model registry not available", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if _, ok := s.reg.Get(id); !ok {
		http.Error(w, "unknown model id", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lineage":  s.reg.Lineage(id),
		"children": s.reg.Children(id),
		"tree":     s.reg.Tree(),
	})
}

// handleModelActivate validates the bundle again, builds the live classifier,
// swaps it into the Runtime, records the status change and the audit entry, and
// returns the updated entry.
//
// POST /api/v1/models/{id}/activate
//   - 404 unknown id
//   - 409 the bundle no longer loads / validates / compiles
//   - 503 no registry wired
func (s *Server) handleModelActivate(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil {
		http.Error(w, "model registry not available", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	e, ok := s.reg.Get(id)
	if !ok {
		http.Error(w, "unknown model id", http.StatusNotFound)
		return
	}

	b, err := model.Load(e.Dir)
	if err != nil {
		http.Error(w, "bundle no longer loads: "+err.Error(), http.StatusConflict)
		return
	}
	if err := b.Validate(); err != nil {
		http.Error(w, "bundle no longer validates: "+err.Error(), http.StatusConflict)
		return
	}
	live, err := modelrun.BuildLive(id, b)
	if err != nil {
		http.Error(w, "bundle cannot be run: "+err.Error(), http.StatusConflict)
		return
	}
	role := string(live.Role)

	// A model is only ever swapped for another in the same role: activating an
	// anomaly autoencoder leaves the primary classifier live and vice versa
	// (ADR 0037).
	prev, hadPrev := s.reg.ActiveByRole(role)

	updated, err := s.reg.SetStatus(id, registry.StatusActive)
	if err != nil {
		http.Error(w, "registry: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.rt.ActivateRole(live.Role, live.Model)

	detail := "role=" + role + "; hash=" + e.ContentHash
	replaced := ""
	if hadPrev && prev.ModelID != id {
		replaced = prev.ModelID
		detail += "; replaced=" + replaced
		// Activating one model implicitly deactivates the previous one in the
		// same role (registry.SetStatus enforces one Active per role). Audit
		// that demotion under the *previous* model's own subject, and before
		// this activation, so reading the log per model gives the right answer:
		// without this line the previous model's most recent record still
		// claims it is active (PROJECT.md §21).
		s.audit.Log(audit.EventModelDeactivated, audit.ActorLocal, replaced,
			"implicitly deactivated: replaced as active "+role+" by "+id)
	}
	s.audit.Log(audit.EventModelActivated, audit.ActorLocal, id, detail)
	if s.bus != nil {
		s.bus.Publish(events.ModelActivated, map[string]any{
			"model_id": id, "content_hash": e.ContentHash, "replaced": replaced, "role": role,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entry": s.view(updated, s.loadedRoles()),
	})
}

// handleModelDeactivate turns a model off: it restores the heuristic as the live
// primary, records the status change and the audit entry.
//
// POST /api/v1/models/{id}/deactivate
//   - 404 unknown id
//   - 503 no registry wired
func (s *Server) handleModelDeactivate(w http.ResponseWriter, r *http.Request) {
	if s.reg == nil {
		http.Error(w, "model registry not available", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	before, ok := s.reg.Get(id)
	if !ok {
		http.Error(w, "unknown model id", http.StatusNotFound)
		return
	}
	wasActive := before.Status == registry.StatusActive
	role := before.Role
	if role == "" {
		role = "primary"
	}

	updated, err := s.reg.SetStatus(id, registry.StatusDeactivated)
	if err != nil {
		http.Error(w, "registry: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.rt.DeactivateRole(inference.Role(role))
	// Only claim something was restored when this model actually was live in its
	// role. Deactivating an already-inactive entry is a legal no-op and the
	// audit line must not overstate what changed.
	restored := "restored heuristic as primary"
	if role == "anomaly" {
		restored = "anomaly scoring disabled"
	}
	detail := restored
	if !wasActive {
		detail = "no-op: was already " + string(before.Status)
	}
	s.audit.Log(audit.EventModelDeactivated, audit.ActorLocal, id, detail)
	if s.bus != nil {
		s.bus.Publish(events.ModelDeactivated, map[string]any{"model_id": id})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entry": s.view(updated, s.loadedRoles()),
	})
}
