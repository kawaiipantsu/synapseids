package api

import (
	"encoding/json"
	"net/http"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// archEstimateResponse is the body of POST /api/v1/architecture/estimate: the
// validity of the submitted hidden stack plus the parameter, size and FLOP math
// (all ported from the trainer's architecture.py so the two agree).
type archEstimateResponse struct {
	Valid          bool                 `json:"valid"`
	Error          string               `json:"error,omitempty"`
	ParameterCount int                  `json:"parameter_count"`
	ApproxBytes    int                  `json:"approx_bytes"`
	RoughFLOPs     int                  `json:"rough_flops"`
	Layers         []schema.LayerParams `json:"layers"`
}

// handleArchitectureEstimate scores a candidate flow-classifier-v1 architecture
// for the ML ▸ Architecture builder (PROJECT.md §10, §19.9). The request body is
// a schema.Architecture JSON document; only its hidden stack is read. The input
// and output layers are LOCKED to the frozen feature and output schemas (48 /
// 7) and are forced server-side regardless of what the client sends. The
// endpoint is pure compute — no auth, no state.
func (s *Server) handleArchitectureEstimate(w http.ResponseWriter, r *http.Request) {
	var arch schema.Architecture
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&arch); err != nil {
		http.Error(w, "bad request body: expected a schema.Architecture JSON object", http.StatusBadRequest)
		return
	}

	// The edge layers are not editable (PROJECT.md §10): pin them before any math
	// so the estimate always reflects the real family contract.
	arch.InputSize = schema.FlowFeaturesV1().InputSize
	arch.OutputSize = schema.TrafficClassesV1().OutputSize

	resp := archEstimateResponse{
		ParameterCount: arch.ParameterCount(),
		ApproxBytes:    arch.ApproxBytes(),
		RoughFLOPs:     arch.RoughFLOPs(),
		Layers:         arch.LayerBreakdown(),
	}
	if err := schema.ValidateArchitecture(arch); err != nil {
		resp.Valid, resp.Error = false, err.Error()
	} else {
		resp.Valid = true
	}
	writeJSON(w, http.StatusOK, resp)
}
