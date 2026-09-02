package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// driftScan bounds how many recent stored flow vectors GET /api/v1/drift folds
// into the current feature distribution. Like classFilterScan it stands in for
// an index the memory store does not have.
const driftScan = 5000

// driftStdEps floors training_std in the standardized mean shift
// z = |current_mean - training_mean| / max(training_std, driftStdEps).
const driftStdEps = 1e-9

// The per-feature bands (warn / drift) and the retraining-suggestion trips come
// from config.Drift (ADR 0036 documented them as constants; ADR 0038 / issue #65
// make them tunable and add the advisory). Nothing here retrains or activates a
// model — the suggestion is advisory only (PROJECT.md §19.13, §28.10).

// handleDrift serves GET /api/v1/drift (issue #49, PROJECT.md §19.13): it
// compares the current flow-features-v1 distribution against the active model's
// *training* distribution and reports the shift per feature and an overall
// state.
//
// The reference is the active bundle's normalizer.json: a "standard" normalizer
// carries the per-feature training mean and std directly. Without an active
// model, or when its normalizer is not "standard" (identity / minmax carry no
// mean+std pair), there is no training distribution to compare against and the
// route returns state "no_baseline" — still with the current window's per-feature
// mean/std so the distribution view has something to render.
//
// It is a read-side fold of stored vectors, like GET /api/v1/matrix: no
// packet-path work, no new storage. Drift is informational only — the daemon
// never retrains or activates a model on its own (PROJECT.md §19.13, §28.10).
//
// Query parameters: from, to (RFC3339 window bounds) and the sensor / location
// scope shared with the flow and classification lists.
func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	scope, ok := s.parseSensorScope(w, q)
	if !ok {
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}

	dcfg := s.cfg.Drift
	warnZ, driftBandZ := dcfg.WarnZ, dcfg.DriftZ

	rows := s.store.RecentFlows(driftScan)

	// Welford, one pass, per feature: mean and M2 (sum of squared deviations).
	var n int
	var mean, m2 [features.Size]float64
	var firstSeen, lastSeen time.Time
	for i := range rows {
		fr := &rows[i]
		if !tr.contains(fr.LastSeen) {
			continue
		}
		if scope != nil && !scope[fr.Sensor] {
			continue
		}
		n++
		for j := 0; j < features.Size; j++ {
			x := fr.Features.Values[j]
			d := x - mean[j]
			mean[j] += d / float64(n)
			m2[j] += d * (x - mean[j])
		}
		if firstSeen.IsZero() || fr.FirstSeen.Before(firstSeen) {
			firstSeen = fr.FirstSeen
		}
		if fr.LastSeen.After(lastSeen) {
			lastSeen = fr.LastSeen
		}
	}
	var std [features.Size]float64
	if n > 0 {
		for j := 0; j < features.Size; j++ {
			std[j] = math.Sqrt(m2[j] / float64(n))
		}
	}

	base, baseErr := s.driftBaseline()
	haveBaseline := baseErr == nil && base != nil

	feats := make([]driftFeature, features.Size)
	warnN, driftN := 0, 0
	maxZ, sumZ := 0.0, 0.0
	for j := 0; j < features.Size; j++ {
		df := driftFeature{
			Index:       j,
			Name:        schema.FeatureName(j),
			CurrentMean: mean[j],
			CurrentStd:  std[j],
			State:       "no_baseline",
		}
		if haveBaseline {
			bm := base.mean[j]
			bs := math.Max(base.std[j], driftStdEps)
			z := math.Abs(mean[j]-bm) / bs
			ratio := std[j] / bs
			df.BaselineMean = &base.mean[j]
			df.BaselineStd = &base.std[j]
			df.Z = ptrFloat(z)
			df.StdRatio = ptrFloat(ratio)
			switch {
			case z >= driftBandZ:
				df.State = "drift"
				driftN++
			case z >= warnZ:
				df.State = "warn"
				warnN++
			default:
				df.State = "stable"
			}
			if z > maxZ {
				maxZ = z
			}
			sumZ += z
		}
		feats[j] = df
	}

	// Worst offenders first when there is a baseline; schema order otherwise.
	if haveBaseline {
		sort.SliceStable(feats, func(a, b int) bool { return *feats[a].Z > *feats[b].Z })
	}

	state := "no_baseline"
	baseline := map[string]any{"source": "none"}
	if haveBaseline {
		switch {
		case n == 0:
			state = "no_baseline"
		case driftN > 0:
			state = "drift"
		case warnN > 0:
			state = "warn"
		default:
			state = "stable"
		}
		baseline = map[string]any{
			"source":   "model_normalizer",
			"model_id": base.modelID,
			"method":   "standard",
		}
	}

	resp := map[string]any{
		"state":    state,
		"baseline": baseline,
		"window": map[string]any{
			"flows":      n,
			"scanned":    len(rows),
			"truncated":  len(rows) >= driftScan,
			"first_seen": nilIfZeroTime(firstSeen),
			"last_seen":  nilIfZeroTime(lastSeen),
		},
		"thresholds": map[string]any{
			"warn":                     warnZ,
			"drift":                    driftBandZ,
			"retrain_suggest_z":        dcfg.RetrainSuggestZ,
			"retrain_suggest_features": dcfg.RetrainSuggestFeatures,
		},
		"features": feats,
		"advisory": "Drift is informational. The daemon never retrains or activates a " +
			"model automatically (PROJECT.md §19.13, §28.10).",
	}
	if haveBaseline {
		resp["overall"] = map[string]any{
			"max_z":          maxZ,
			"mean_z":         sumZ / float64(features.Size),
			"features_warn":  warnN,
			"features_drift": driftN,
		}
		resp["suggestion"] = driftSuggestion(dcfg, maxZ, driftN, base.modelID)
	}
	if baseErr != nil {
		resp["baseline_note"] = baseErr.Error()
	}

	writeJSON(w, http.StatusOK, resp)
}

// driftSuggestion turns the overall drift picture into an advisory retraining
// suggestion when the configured band is crossed (issue #65, ADR 0038). It is
// suggestion only: the daemon never retrains or activates a model on its own
// (PROJECT.md §19.13, §28.10). Only called when a training baseline exists.
func driftSuggestion(d config.Drift, maxZ float64, driftN int, modelID string) map[string]any {
	byZ := maxZ >= d.RetrainSuggestZ
	byN := driftN >= d.RetrainSuggestFeatures
	s := map[string]any{
		"retrain_suggested": byZ || byN,
		"advisory": "Suggestion only. Retraining and activation are always an explicit " +
			"operator decision (PROJECT.md §19.13, §28.10).",
	}
	switch {
	case byZ && byN:
		s["reason"] = fmt.Sprintf("%d feature(s) past the drift band and overall max z %.1f ≥ %.1f "+
			"against the active model %q's training distribution", driftN, maxZ, d.RetrainSuggestZ, modelID)
	case byZ:
		s["reason"] = fmt.Sprintf("overall max z %.1f ≥ %.1f against the active model %q's training distribution",
			maxZ, d.RetrainSuggestZ, modelID)
	case byN:
		s["reason"] = fmt.Sprintf("%d feature(s) past the drift band (threshold %d) against the active model %q",
			driftN, d.RetrainSuggestFeatures, modelID)
	default:
		s["reason"] = fmt.Sprintf("drift is within tolerance (max z %.1f < %.1f, %d/%d feature(s) in the drift band)",
			maxZ, d.RetrainSuggestZ, driftN, d.RetrainSuggestFeatures)
	}
	return s
}

func ptrFloat(f float64) *float64 { return &f }

// nilIfZeroTime renders an optional timestamp: the value, or nil when unset, so a
// response object never carries a zero time.
func nilIfZeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// driftFeature is one feature's current distribution and, when a training
// baseline exists, its shift from it.
type driftFeature struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	CurrentMean  float64  `json:"current_mean"`
	CurrentStd   float64  `json:"current_std"`
	BaselineMean *float64 `json:"baseline_mean,omitempty"`
	BaselineStd  *float64 `json:"baseline_std,omitempty"`
	Z            *float64 `json:"z,omitempty"`
	StdRatio     *float64 `json:"std_ratio,omitempty"`
	State        string   `json:"state"`
}

// driftRef is the training distribution recovered from a "standard" normalizer.
type driftRef struct {
	modelID string
	mean    [features.Size]float64
	std     [features.Size]float64
}

// driftBaseline reads the active model bundle's normalizer.json and, if it is a
// "standard" spec, returns its per-feature training mean/std. A nil ref with a
// nil error means "no active model"; a non-nil error explains why a present
// model could not serve as a baseline (wrong method, unreadable file).
func (s *Server) driftBaseline() (*driftRef, error) {
	if s.reg == nil {
		return nil, nil
	}
	e, ok := s.reg.Active()
	if !ok {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(e.Dir, model.FileNormalizer))
	if err != nil {
		return nil, driftBaselineErr("active model " + e.ModelID + ": normalizer.json unreadable")
	}
	var spec model.NormalizerSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, driftBaselineErr("active model " + e.ModelID + ": normalizer.json unparseable")
	}
	if spec.Method != "standard" {
		return nil, driftBaselineErr("active model " + e.ModelID + " uses a \"" + spec.Method +
			"\" normalizer, which carries no training mean/std; drift needs a \"standard\" model")
	}
	if len(spec.PerFeature) != features.Size {
		return nil, driftBaselineErr("active model " + e.ModelID + ": normalizer.json has the wrong feature count")
	}
	ref := &driftRef{modelID: e.ModelID}
	for _, pf := range spec.PerFeature {
		if pf.Index < 0 || pf.Index >= features.Size {
			return nil, driftBaselineErr("active model " + e.ModelID + ": normalizer.json feature index out of range")
		}
		ref.mean[pf.Index] = pf.Mean
		ref.std[pf.Index] = pf.Std
	}
	return ref, nil
}

type driftBaselineErr string

func (e driftBaselineErr) Error() string { return string(e) }
