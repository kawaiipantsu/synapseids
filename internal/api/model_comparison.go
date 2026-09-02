package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// comparisonScan bounds how many recent verdicts GET /api/v1/models/comparison
// folds. Like classFilterScan / matrixScanLimit it is the memory store's
// stand-in for an index; a predicate-pushdown backend will replace it.
const comparisonScan = 5000

// handleModelComparison serves GET /api/v1/models/comparison (issue #48,
// PROJECT.md §12, §19.7): side-by-side agreement of every model that scored the
// same flows, folded on demand from the newest window of stored verdicts.
//
// The runtime already records each model's individual output on every
// Classification (PROJECT.md §12), so this route needs no packet-path work and
// no new storage — it is the same read-side fold GET /api/v1/matrix does.
//
// It answers three of the §19.7 comparisons directly from stored data:
// predictions, confidence and disagreement, plus a per-pair class-vs-class
// matrix. Accuracy / F1 need ground-truth labels, which live in the review store
// and the datasets, not on a live verdict — that comparison belongs to an
// offline evaluation run and is out of scope here (stated in `notes`).
//
// Query parameters are the shared class filters and time range (see
// parseClassFilters / parseTimeRange): class, model, min_confidence,
// disagreement, sensor, location, from, to. `model=` narrows the window to rows
// that model scored; the comparison is then within that subset.
func (s *Server) handleModelComparison(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f, ok := s.parseClassFilters(w, q)
	if !ok {
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}

	rows := s.store.RecentClassifications(comparisonScan)

	classes := schema.TrafficClassesV1().Classes
	nClasses := len(classes)
	classNames := make([]string, nClasses)
	for i, c := range classes {
		classNames[i] = c.Name
	}

	perModel := map[string]*cmpModelAcc{}
	perPair := map[[2]string]*cmpPairAcc{}

	var matched, comparedRows, singleModelRows, disagreeRows int

	for i := range rows {
		c := rows[i]
		if !tr.contains(c.TS) {
			continue
		}
		if !f.empty() && !f.match(c) {
			continue
		}
		matched++
		if c.Result.Disagreement {
			disagreeRows++
		}

		outs := c.Result.Models
		if len(outs) < 2 {
			singleModelRows++
		} else {
			comparedRows++
		}

		for _, mo := range outs {
			acc := perModel[mo.ModelID]
			if acc == nil {
				acc = &cmpModelAcc{role: string(mo.Role), dist: map[string]int{}}
				perModel[mo.ModelID] = acc
			}
			acc.rows++
			acc.confSum += mo.Score
			acc.dist[mo.Class]++
		}

		// Every unordered pair of distinct model outputs on this row.
		for a := 0; a < len(outs); a++ {
			for b := a + 1; b < len(outs); b++ {
				ma, mb := outs[a], outs[b]
				ka, kb := ma.ModelID, mb.ModelID
				if ka == kb {
					continue // two outputs from the same model id: nothing to compare
				}
				if kb < ka {
					ma, mb = mb, ma
					ka, kb = kb, ka
				}
				key := [2]string{ka, kb}
				pa := perPair[key]
				if pa == nil {
					pa = &cmpPairAcc{matrix: newIntMatrix(nClasses)}
					perPair[key] = pa
				}
				pa.both++
				if ma.ClassID == mb.ClassID {
					pa.agree++
				}
				pa.absConfDeltaSum += absFloat(ma.Score - mb.Score)
				if inRange(ma.ClassID, nClasses) && inRange(mb.ClassID, nClasses) {
					pa.matrix[ma.ClassID][mb.ClassID]++
				}
			}
		}
	}

	models := make([]cmpModelOut, 0, len(perModel))
	for id, acc := range perModel {
		mo := cmpModelOut{
			ModelID:           id,
			Role:              acc.role,
			Rows:              acc.rows,
			ClassDistribution: acc.dist,
		}
		if acc.rows > 0 {
			mo.MeanConfidence = acc.confSum / float64(acc.rows)
		}
		if u := s.unsupportedClassesFor(id); len(u) > 0 {
			mo.UnsupportedClasses = u
		}
		models = append(models, mo)
	}
	sort.Slice(models, func(i, j int) bool {
		ri, rj := roleSortRank(models[i].Role), roleSortRank(models[j].Role)
		if ri != rj {
			return ri < rj
		}
		return models[i].ModelID < models[j].ModelID
	})

	pairs := make([]cmpPairOut, 0, len(perPair))
	for key, pa := range perPair {
		po := cmpPairOut{
			A:           key[0],
			B:           key[1],
			BothScored:  pa.both,
			Agree:       pa.agree,
			Disagree:    pa.both - pa.agree,
			ClassMatrix: pa.matrix,
		}
		if pa.both > 0 {
			po.AgreementRate = float64(pa.agree) / float64(pa.both)
			po.MeanAbsConfidenceDelta = pa.absConfDeltaSum / float64(pa.both)
		}
		pairs = append(pairs, po)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].A != pairs[j].A {
			return pairs[i].A < pairs[j].A
		}
		return pairs[i].B < pairs[j].B
	})

	var disagreementRate float64
	if matched > 0 {
		disagreementRate = float64(disagreeRows) / float64(matched)
	}

	notes := []string{
		"class_matrix rows are model A's class, columns model B's class, in the `classes` order.",
		"accuracy / F1 need ground-truth labels and are produced by an offline evaluation run, not this live view.",
		"per-model inference latency is not recorded per verdict; see GET /metrics for aggregate scoring latency.",
	}
	if len(models) < 2 {
		notes = append(notes, "fewer than two models have scored traffic in this window — load and activate a second model, or run one as a shadow, to get a comparison.")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window": map[string]any{
			"scanned":   len(rows),
			"matched":   matched,
			"truncated": len(rows) >= comparisonScan,
			"from":      timePtr(tr.from),
			"to":        timePtr(tr.to),
		},
		"classes":           classNames,
		"flows_compared":    comparedRows,
		"single_model_rows": singleModelRows,
		"disagreement_rate": disagreementRate,
		"models":            models,
		"pairs":             pairs,
		"notes":             notes,
	})
}

type cmpModelAcc struct {
	role    string
	rows    int
	confSum float64
	dist    map[string]int
}

type cmpPairAcc struct {
	both            int
	agree           int
	absConfDeltaSum float64
	matrix          [][]int
}

type cmpModelOut struct {
	ModelID            string         `json:"model_id"`
	Role               string         `json:"role,omitempty"`
	Rows               int            `json:"rows"`
	MeanConfidence     float64        `json:"mean_confidence"`
	ClassDistribution  map[string]int `json:"class_distribution"`
	UnsupportedClasses []string       `json:"unsupported_classes,omitempty"`
}

type cmpPairOut struct {
	A                      string  `json:"a"`
	B                      string  `json:"b"`
	BothScored             int     `json:"both_scored"`
	Agree                  int     `json:"agree"`
	Disagree               int     `json:"disagree"`
	AgreementRate          float64 `json:"agreement_rate"`
	MeanAbsConfidenceDelta float64 `json:"mean_abs_confidence_delta"`
	ClassMatrix            [][]int `json:"class_matrix"`
}

// unsupportedClassesFor reports the traffic-classes-v1 classes a currently
// loaded classifier says it never emits (issue #134), so the comparison can show
// a labelled gap rather than implying full coverage. An id that is not loaded,
// or a model that claims full coverage, returns nil.
func (s *Server) unsupportedClassesFor(id string) []string {
	for _, m := range s.rtModels() {
		if m.ID() != id {
			continue
		}
		if cr, ok := m.(classCoverageReporter); ok {
			return cr.UnsupportedClasses()
		}
		return nil
	}
	return nil
}

func newIntMatrix(n int) [][]int {
	m := make([][]int, n)
	for i := range m {
		m[i] = make([]int, n)
	}
	return m
}

func inRange(i, n int) bool { return i >= 0 && i < n }

func absFloat(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// roleSortRank orders the model list primary-first, matching the runtime's own
// roleRank without importing its unexported helper.
func roleSortRank(role string) int {
	switch role {
	case "primary":
		return 0
	case "global":
		return 1
	case "location":
		return 2
	case "experimental":
		return 3
	case "anomaly":
		return 4
	default:
		return 5
	}
}

// timePtr renders an optional bound: the timestamp, or nil when unset, so the
// window object never carries a zero time.
func timePtr(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
