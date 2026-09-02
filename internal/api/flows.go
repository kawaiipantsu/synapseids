package api

// Flow Inspector read paths (PROJECT.md §19.3, issue #38).
//
// Two sibling routes rather than a fatter GET /api/v1/flows/{id}: that route's
// documented contract is "a single storage.FlowRecord", several views already
// depend on that exact shape, and the two additions answer genuinely different
// questions ("why this verdict" and "how did this flow evolve").
//
//	GET /api/v1/flows/{id}/explain    — per-model inputs and the verdict's rationale
//	GET /api/v1/flows/{id}/snapshots  — the retained version history of one flow
//
// The honesty rules this file exists to enforce (PROJECT.md §13, §19.3):
//
//   - Normalization is a *per-model* concern. There is no global normalizer and
//     this file must never introduce one. The heuristic reads raw values and says
//     so; a trained model's normalized inputs come from its own bundle.
//   - No baseline column. Behavioural baselines are Phase 7; `insight` and
//     `report` already report baseline_available:false and so does this.
//   - The anomaly section is populated from the stored ensemble verdict when a
//     flow-anomaly-v1 autoencoder scored the flow (ADR 0037); when the model
//     that produced it is still loaded, the largest per-feature reconstruction
//     gaps are recomputed on demand from the stored vector. With no anomaly
//     model it is an explicit available:false, never a fabricated number.
//   - No fabricated per-feature attribution for trained models. See
//     inference.UnavailableExplanation.

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Input kinds for a model's view of a flow's features.
const (
	inputRaw        = "raw"        // the model scores raw flow-features-v1 values
	inputNormalized = "normalized" // the model applies its bundle's normalizer
	inputUnknown    = "unknown"    // cannot be determined — say so, show nothing
)

// phase7Note is the wording for the behavioural-baseline gap, deliberately
// consistent with insight.Profile and report.Coverage. (Anomaly scoring is no
// longer a Phase-7 stub — see anomalySection — so only the baseline still uses
// this.)
const phase7Note = "Not available in this build. " +
	"Behavioural baselines are Phase 7 work (PROJECT.md §13, §19.3). " +
	"The field exists so a client can label the gap rather than plot an invented number."

// anomalyUnavailableNote is shown when no flow-anomaly-v1 autoencoder scored the
// flow — a labelled gap, not a fabricated zero (PROJECT.md §16).
const anomalyUnavailableNote = "No anomaly model scored this flow. Activate a " +
	"flow-anomaly-v1 autoencoder bundle to score flows for novelty (PROJECT.md §13, ADR 0037)."

// stubSection is an explicitly-unavailable part of the inspector.
type stubSection struct {
	Available bool   `json:"available"`
	Note      string `json:"note"`
}

// anomalySection is the autoencoder novelty view of a flow. Available is false
// when no anomaly model scored it. Score is a bounded 0..1 reconstruction-error
// signal; Exceeds is its raw error crossing the bundle's calibrated threshold.
// TopDeltas — the largest per-feature reconstruction gaps — are present only
// when the model that produced the verdict is still loaded and can be re-run.
type anomalySection struct {
	Available  bool                     `json:"available"`
	ModelID    string                   `json:"model_id,omitempty"`
	Score      float64                  `json:"score,omitempty"`
	ReconError float64                  `json:"recon_error,omitempty"`
	Threshold  float64                  `json:"threshold,omitempty"`
	Exceeds    bool                     `json:"exceeds,omitempty"`
	TopDeltas  []inference.FeatureDelta `json:"top_deltas,omitempty"`
	Note       string                   `json:"note,omitempty"`
}

// normFeature is one feature as a specific model sees it.
type normFeature struct {
	Index      int     `json:"index"`
	Name       string  `json:"name"`
	Unit       string  `json:"unit"`
	Raw        float64 `json:"raw"`
	Normalized float64 `json:"normalized"`
}

// modelInput describes what one model actually received.
type modelInput struct {
	Kind         string        `json:"kind"`
	NormalizerID string        `json:"normalizer_id,omitempty"`
	Note         string        `json:"note"`
	Features     []normFeature `json:"features,omitempty"`
}

// explainModel is one model's account of one flow.
type explainModel struct {
	ModelID string           `json:"model_id"`
	Role    inference.Role   `json:"role"`
	Class   string           `json:"class"`
	ClassID int              `json:"class_id"`
	Score   float64          `json:"score"`
	Scores  inference.Scores `json:"scores"`

	// Loaded reports whether the model that produced this verdict is still in
	// the live runtime. When false its inputs and rationale cannot be
	// reconstructed and both sections say so.
	Loaded bool `json:"loaded"`

	Input       modelInput            `json:"input"`
	Explanation inference.Explanation `json:"explanation"`
}

// explainVerdict is the stored ensemble verdict being explained.
type explainVerdict struct {
	TS           time.Time `json:"ts"`
	Sensor       string    `json:"sensor"`
	Class        string    `json:"class"`
	ClassID      int       `json:"class_id"`
	Score        float64   `json:"score"`
	Disagreement bool      `json:"disagreement"`
}

// flowExplain is the GET /api/v1/flows/{id}/explain payload.
type flowExplain struct {
	FlowID        uint64 `json:"flow_id"`
	SnapshotIndex int    `json:"snapshot_index"`

	// VerdictAvailable is false when no classification for this flow is still
	// retained in the bounded ring. Models is then empty: without the stored
	// verdict there is no honest way to say which models scored this flow.
	VerdictAvailable bool            `json:"verdict_available"`
	Verdict          *explainVerdict `json:"verdict,omitempty"`

	Models []explainModel `json:"models"`

	Anomaly  anomalySection `json:"anomaly"`
	Baseline stubSection    `json:"baseline"`

	Notes []string `json:"notes,omitempty"`
}

// handleFlowExplain serves GET /api/v1/flows/{id}/explain.
func (s *Server) handleFlowExplain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad flow id", http.StatusBadRequest)
		return
	}
	hist := s.store.FlowHistory(id)
	if len(hist) == 0 {
		http.Error(w, "flow not found", http.StatusNotFound)
		return
	}

	out := flowExplain{
		FlowID:   id,
		Anomaly:  anomalySection{Available: false, Note: anomalyUnavailableNote},
		Baseline: stubSection{Available: false, Note: phase7Note},
		Models:   []explainModel{},
	}

	// The verdict to explain is the newest retained one for this flow. Pair it
	// with the flow version it was computed from — the pipeline stamps
	// Classification.TS from the record's LastSeen, so this is an exact join
	// rather than a guess.
	cl, okCl := s.latestClassification(id)
	rec := hist[len(hist)-1]
	if okCl {
		if m, ok := versionAt(hist, cl.TS); ok {
			rec = m
		} else {
			out.Notes = append(out.Notes,
				"The flow version this verdict was computed from is no longer retained; "+
					"feature values below come from the newest retained version instead.")
		}
	}
	out.SnapshotIndex = rec.SnapshotIndex

	if !okCl {
		out.Notes = append(out.Notes,
			"No classification for this flow is still retained, so no model outputs, "+
				"normalized inputs or rationale can be shown. The verdict has aged out of "+
				"the bounded in-memory ring (PROJECT.md §20).")
		writeJSON(w, http.StatusOK, out)
		return
	}

	out.VerdictAvailable = true
	out.Verdict = &explainVerdict{
		TS: cl.TS, Sensor: cl.Sensor,
		Class: cl.Result.Class, ClassID: cl.Result.ClassID,
		Score: cl.Result.Score, Disagreement: cl.Result.Disagreement,
	}

	live := s.liveModels()
	for _, mo := range cl.Result.Models {
		em := explainModel{
			ModelID: mo.ModelID, Role: mo.Role,
			Class: mo.Class, ClassID: mo.ClassID, Score: mo.Score, Scores: mo.Scores,
		}
		c, loaded := live[mo.ModelID]
		em.Loaded = loaded
		if !loaded {
			why := fmt.Sprintf("Model %q produced this verdict but is no longer loaded in the "+
				"runtime, so neither its inputs nor its rationale can be reconstructed.", mo.ModelID)
			em.Input = modelInput{Kind: inputUnknown, Note: why}
			em.Explanation = inference.UnavailableExplanation(mo.ModelID, mo.Role, why)
		} else {
			em.Input = s.modelInputFor(c, rec.Features)
			em.Explanation = explanationFor(c, rec.Features)
		}
		out.Models = append(out.Models, em)
	}

	out.Anomaly = s.anomalyExplain(cl.Result.Anomaly, rec.Features)

	writeJSON(w, http.StatusOK, out)
}

// anomalyExplain turns the stored ensemble anomaly verdict into the inspector
// section. The scalars are always the ones recorded at classification time; the
// per-feature reconstruction gaps are recomputed from the stored vector only
// when the model that produced the verdict is still loaded (otherwise the gaps
// cannot be honestly reconstructed).
func (s *Server) anomalyExplain(ar *inference.AnomalyResult, v features.Vector) anomalySection {
	if ar == nil || !ar.Available {
		note := anomalyUnavailableNote
		if ar != nil {
			note = "The anomaly model that scored this flow abstained (the network failed to run)."
		}
		return anomalySection{Available: false, Note: note}
	}

	as := anomalySection{
		Available:  true,
		ModelID:    ar.ModelID,
		Score:      ar.Score,
		ReconError: ar.ReconError,
		Threshold:  ar.Threshold,
		Exceeds:    ar.Exceeds,
	}
	if am := s.liveAnomalyModel(); am != nil && am.ID() == ar.ModelID {
		as.TopDeltas = am.ScoreAnomaly(v).TopDeltas
		as.Note = "Reconstruction error and the largest per-feature gaps from the loaded " +
			"autoencoder, in its normalized input space."
	} else {
		as.Note = "Stored reconstruction score. The autoencoder that produced it is no longer " +
			"loaded, so the per-feature gaps cannot be reconstructed."
	}
	return as
}

// explanationFor asks a classifier to account for its verdict, falling back to an
// explicit "unavailable" when it cannot. It never substitutes an approximation.
func explanationFor(c inference.Classifier, v features.Vector) inference.Explanation {
	if ex, ok := c.(inference.Explainer); ok {
		return ex.Explain(v)
	}
	return inference.UnavailableExplanation(c.ID(), c.Role(),
		"Per-feature attribution is not implemented for trained models in this build. "+
			"An exact attribution needs gradients or SHAP over the network, which this "+
			"daemon's stdlib-only inference path does not compute, and no cheap linear "+
			"proxy is presented here because a proxy is not an explanation. "+
			"The full class-probability vector above is this model's complete output.")
}

// modelInputFor reports what a model actually saw: raw values for a model that
// reads them raw, or raw→normalized pairs sourced from the model's own bundle.
//
// Normalization is per-model by design (CLAUDE.md, PROJECT.md §8): there is no
// pipeline-wide normalizer to report, and inventing one here would misrepresent
// what was scored.
func (s *Server) modelInputFor(c inference.Classifier, v features.Vector) modelInput {
	if _, isHeuristic := c.(*inference.Heuristic); isHeuristic {
		return modelInput{
			Kind: inputRaw,
			Note: "This model reads raw flow-features-v1 values — there is no " +
				"transformation to show. Normalization is a per-model concern: only a " +
				"trained model applies its bundle's normalizer.json.",
		}
	}

	norm, normID, err := s.activeNormalizer(c.ID())
	if err != nil {
		return modelInput{
			Kind: inputUnknown,
			Note: fmt.Sprintf("This model does not read raw values, but its normalizer "+
				"could not be resolved from the registry: %v. No transformation is shown "+
				"rather than a guessed one.", err),
		}
	}

	nv := norm.Normalize(v)
	fs := schema.FlowFeaturesV1().Features
	out := make([]normFeature, 0, len(fs))
	for i, f := range fs {
		out = append(out, normFeature{
			Index: i, Name: f.Name, Unit: f.Unit,
			Raw: v.Values[i], Normalized: nv.Values[i],
		})
	}

	note := fmt.Sprintf("Raw flow-features-v1 values as this model received them, and the "+
		"result of the %q transform from its own bundle's normalizer.json — the exact input "+
		"the network scored.", normID)
	if normID == "identity" {
		note = "This model's bundle declares the identity normalizer, so its normalized " +
			"input is the raw vector unchanged."
	}
	return modelInput{Kind: inputNormalized, NormalizerID: normID, Note: note, Features: out}
}

// activeNormalizer resolves the fitted normalizer for a model id via the
// registry's active entry and its on-disk bundle.
//
// The bundle is cached per (model id, content hash) for the process lifetime —
// model.Load reads and hashes model.onnx, which is far too heavy to repeat per
// inspector request, and a registered bundle is immutable so the hash is a sound
// cache key (the same reasoning as dataset.Stats).
func (s *Server) activeNormalizer(modelID string) (features.Normalizer, string, error) {
	if s.reg == nil {
		return nil, "", fmt.Errorf("no model registry is configured")
	}
	e, ok := s.reg.Active()
	if !ok {
		return nil, "", fmt.Errorf("no model is active in the registry")
	}
	if e.ModelID != modelID {
		return nil, "", fmt.Errorf("model %q is not the active registry entry (%q)", modelID, e.ModelID)
	}

	key := e.ModelID + "@" + e.ContentHash
	s.normMu.Lock()
	defer s.normMu.Unlock()
	if s.normCache == nil {
		s.normCache = map[string]cachedNormalizer{}
	}
	if hit, ok := s.normCache[key]; ok {
		return hit.norm, hit.id, nil
	}

	norm, id, err := loadBundleNormalizer(e)
	if err != nil {
		return nil, "", err
	}
	s.normCache[key] = cachedNormalizer{norm: norm, id: id}
	return norm, id, nil
}

// cachedNormalizer is one resolved bundle normalizer.
type cachedNormalizer struct {
	norm features.Normalizer
	id   string
}

func loadBundleNormalizer(e registry.Entry) (features.Normalizer, string, error) {
	b, err := model.Load(e.Dir)
	if err != nil {
		return nil, "", fmt.Errorf("load bundle: %w", err)
	}
	norm, err := b.Normalizer()
	if err != nil {
		return nil, "", fmt.Errorf("normalizer.json: %w", err)
	}
	return norm, norm.ID(), nil
}

// liveModels indexes the runtime's current classifiers by id.
func (s *Server) liveModels() map[string]inference.Classifier {
	out := map[string]inference.Classifier{}
	if s.rt == nil {
		return out
	}
	for _, c := range s.rt.Models() {
		out[c.ID()] = c
	}
	return out
}

// liveAnomalyModel returns the anomaly-role model currently loaded in the
// runtime, or nil when none is. In practice there is at most one.
func (s *Server) liveAnomalyModel() inference.AnomalyScorer {
	if s.rt == nil {
		return nil
	}
	ms := s.rt.AnomalyModels()
	if len(ms) == 0 {
		return nil
	}
	return ms[0]
}

// latestClassification returns the newest retained verdict for a flow.
func (s *Server) latestClassification(id uint64) (storage.Classification, bool) {
	// RecentClassifications is newest-first, so the first match wins.
	for _, c := range s.store.RecentClassifications(0) {
		if c.FlowID == id {
			return c, true
		}
	}
	return storage.Classification{}, false
}

// versionAt finds the flow version whose LastSeen equals ts.
func versionAt(hist []storage.FlowRecord, ts time.Time) (storage.FlowRecord, bool) {
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].LastSeen.Equal(ts) {
			return hist[i], true
		}
	}
	return storage.FlowRecord{}, false
}
