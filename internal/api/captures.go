package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capturewire"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
)

// POST /api/v1/captures and DELETE /api/v1/captures/{name} start and stop a
// capture source at runtime (issue #32). They are state-changing and
// unauthenticated for now — the same posture as POST /api/v1/replay and the
// model activate/deactivate routes, where binding to loopback by default is the
// only control. Starting a capture spawns a raw socket, a tcpdump subprocess, an
// SSH session or a TLS client, so this is a powerful endpoint.
// TODO(#58): gate behind auth/RBAC before exposing the API off loopback.

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

// handleCaptureCreate serves POST /api/v1/captures. The body is a
// config.CaptureSource JSON object. The source is validated with the exact same
// config.ValidateCaptureSource the file loader uses, built through the shared
// capturewire.Build, then handed to the Manager, which starts its forwarder
// immediately (the pipeline is already draining the merged channel).
//
//	201 + the new SourceStatus  on success
//	400  bad body / failed per-kind validation / inline token
//	409  a source with that name already exists
//	422  a local source (nic, tcpdump) could not be opened
//	502  a remote source (ssh, pcap-over-ip) could not be opened
//	503  no capture manager is wired
func (s *Server) handleCaptureCreate(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		http.Error(w, "runtime capture management is not available", http.StatusServiceUnavailable)
		return
	}

	var cs config.CaptureSource
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cs); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// An inline bearer token is refused exactly like config (§23), for every
	// kind, before anything else touches it.
	if cs.Token != "" {
		http.Error(w, "an inline token is not allowed — use token_file or the SYNAPSE_POIP_TOKEN env var", http.StatusBadRequest)
		return
	}
	if err := config.ValidateCaptureSource(cs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists := s.cap.Get(cs.Name); exists {
		http.Error(w, "a capture source named "+strconv.Quote(cs.Name)+" already exists", http.StatusConflict)
		return
	}

	src, target, err := capturewire.Build(cs, log.Printf)
	if err != nil {
		http.Error(w, "capture source could not be opened: "+err.Error(), openFailureCode(cs.Kind))
		return
	}
	meta := capturewire.Meta(cs)
	meta.Origin = "api"
	if err := s.cap.Add(cs.Name, src, meta); err != nil {
		_ = src.Close()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	log.Printf("api: capture source %q (%s) added at runtime via POST /api/v1/captures (target %s)", cs.Name, cs.Kind, target)
	if s.bus != nil {
		s.bus.Publish(events.CaptureSourceConnected, map[string]any{
			"name": cs.Name, "kind": cs.Kind, "interface": cs.Interface,
			"destination": cs.Destination, "addr": cs.Addr, "filter": cs.Filter,
			"origin": "api",
		})
	}

	st, _ := s.cap.Get(cs.Name)
	writeJSON(w, http.StatusCreated, st)
}

// handleCaptureDelete serves DELETE /api/v1/captures/{name}: it stops and
// deregisters the source (closing its socket / killing its subprocess / ending
// its SSH or TLS session). 200 on success, 404 if the name is unknown. A
// source added from config and one added from the API are both removable.
func (s *Server) handleCaptureDelete(w http.ResponseWriter, r *http.Request) {
	if s.cap == nil {
		http.Error(w, "capture source not found", http.StatusNotFound)
		return
	}
	name := r.PathValue("name")
	if !s.cap.Remove(name) {
		http.Error(w, "capture source not found", http.StatusNotFound)
		return
	}

	log.Printf("api: capture source %q removed at runtime via DELETE /api/v1/captures/%s", name, name)
	if s.bus != nil {
		s.bus.Publish(events.CaptureSourceDisconnected, map[string]any{
			"name": name, "origin": "api",
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"removed": name})
}

// openFailureCode maps a source kind to the HTTP status used when the source
// cannot be opened: a local kind is the client's unprocessable request (422); a
// remote kind is an upstream failure (502).
func openFailureCode(kind string) int {
	switch kind {
	case "ssh", "pcap-over-ip":
		return http.StatusBadGateway
	default:
		return http.StatusUnprocessableEntity
	}
}
