package dataset

import (
	"fmt"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// The curated (human-reviewed) build path — PROJECT.md §16's "reviewed flows can
// be exported into a curated dataset", closing the honesty gap the package
// comment used to describe.
//
// A default cut asks the classification ring "what did the model say?" and
// writes that as the label. A `reviewed` cut asks the review store "what did a
// person say?" and writes *that*. It is the only path in this package that may
// set labeling_source to "human_review", and it does so because the label column
// genuinely came from a human decision — not because a caller asked for the
// string.
//
// Eligibility, from §16's five states:
//
//	correct         → label = the prediction the human confirmed  (human)
//	incorrect       → label = the human's correction              (human)
//	ignored_pattern → excluded; with include_ignored, label = the model's
//	                  unconfirmed prediction                      (model)
//	unsure          → excluded: "I don't know" is not a label
//	unreviewed      → excluded: there is no decision to export
//
// Everything else is unchanged from the default path: the same 48 feature
// columns in frozen schema order, the same one-row-per-flow rule, the same sort
// by flow id, the same content hash over the CSV bytes, the same zero-rows /
// one-class / MinRows refusals, and the same immutability and parent_datasets
// lineage.

// ReviewSource is the read side of internal/review that a `reviewed` selection
// needs. *review.Store satisfies it. It is an interface only so a test can feed
// a fixed set of reviews without a directory on disk.
type ReviewSource interface {
	List(f review.Filter) []review.Review
}

// buildReviewed materialises a curated dataset from the review store.
func buildReviewed(src FlowSource, rv ReviewSource, sel Selection) (*built, error) {
	if rv == nil {
		return nil, fmt.Errorf("%w: reviewed:true needs the review store, and none is wired", ErrInvalid)
	}

	// Newest decision first, so Limit keeps the freshest reviews — the same
	// "newest wins" posture the default path has.
	reviews := rv.List(review.Filter{Labelled: true, IncludeIgnored: sel.IncludeIgnored})

	rows := make([]row, 0, 256)
	models := map[string]bool{}
	var humanRows, modelRows, missingFlow, nonFinite, unlabelled int
	var minTS, maxTS time.Time

	for _, r := range reviews {
		label, human := reviewedLabel(r)
		if label == "" || !validClass(label) {
			// A review whose state asserts no class, or whose captured prediction
			// predates a class rename. Neither can become a training row.
			unlabelled++
			continue
		}
		if sel.Class != "" && label != sel.Class {
			continue
		}
		if sel.Model != "" && r.ModelID() != sel.Model {
			continue
		}
		if sel.MinConfidence > 0 && r.PredictedScore() < sel.MinConfidence {
			continue
		}

		fr, ok := src.Flow(r.FlowID)
		if !ok {
			// The decision outlived its flow record in the bounded ring. Without
			// the 48 features there is no row to write — and unlike a model-labelled
			// row this one cost a human their attention, so it is worth saying out
			// loud in the manifest.
			missingFlow++
			continue
		}
		if !matchFlow(fr, sel) {
			continue
		}

		rw := row{flowID: r.FlowID, label: label, values: fr.Features.Values}
		for i := range rw.values {
			if !isFinite(rw.values[i]) {
				rw.values[i] = schema.FlowFeaturesV1().DefaultMissing
				nonFinite++
			}
		}
		rows = append(rows, rw)

		if human {
			humanRows++
		} else {
			modelRows++
			if id := r.ModelID(); id != "" {
				models[id] = true
			}
		}
		if minTS.IsZero() || fr.LastSeen.Before(minTS) {
			minTS = fr.LastSeen
		}
		if maxTS.IsZero() || fr.LastSeen.After(maxTS) {
			maxTS = fr.LastSeen
		}

		if sel.Limit > 0 && len(rows) >= sel.Limit {
			break
		}
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: no reviewed flow matched (%d eligible review(s) walked, %d carried no human class, %d had lost their flow record to the bounded store) — review some flows first, or widen the selection",
			ErrUnusable, len(reviews), unlabelled, missingFlow)
	}
	return finish(rows,
		reviewedLabelingSource(humanRows, modelRows, models),
		TimeRange{From: rfc3339(minTS), To: rfc3339(maxTS)},
		missingFlow, nonFinite,
		reviewedWarnings(humanRows, modelRows, missingFlow),
	)
}

// reviewedLabel is the label a review contributes and whether a human actually
// asserted it. It is the single place the state→label mapping lives.
func reviewedLabel(r review.Review) (label string, human bool) {
	if l := r.EffectiveLabel(); l != "" {
		// correct → the confirmed prediction; incorrect → the correction. Either
		// way a person put their name to this class.
		return l, true
	}
	if r.State == review.StateIgnoredPattern {
		// Opted in (List already filtered on that). The operator muted the
		// pattern without disputing the class, so the label is the model's — and
		// the manifest will say so.
		return r.PredictedClass(), false
	}
	return "", false
}

// matchFlow applies the selection predicates that a reviewed cut evaluates
// against the stored flow record rather than a classification: the time bounds
// (the flow's last-seen time — a review record has no classification timestamp)
// and the tuple filters.
func matchFlow(fr storage.FlowRecord, sel Selection) bool {
	if !sel.From.IsZero() && fr.LastSeen.Before(sel.From) {
		return false
	}
	if !sel.To.IsZero() && fr.LastSeen.After(sel.To) {
		return false
	}
	if sel.Proto != "" && !strings.EqualFold(fr.Proto, sel.Proto) {
		return false
	}
	if sel.InitiatorIP != "" && fr.InitiatorIP != sel.InitiatorIP {
		return false
	}
	if sel.ResponderIP != "" && fr.ResponderIP != sel.ResponderIP {
		return false
	}
	return true
}

// reviewedLabelingSource is the gate §16 asked for. "human_review" is written
// only when every row's label was asserted by a person; a cut that also carries
// opted-in ignored_pattern rows is honest about being mixed, and names the models
// whose predictions labelled that part.
func reviewedLabelingSource(humanRows, modelRows int, models map[string]bool) string {
	switch {
	case humanRows > 0 && modelRows == 0:
		return "human_review"
	case humanRows > 0:
		return "human_review+" + labelingSource(models)
	default:
		// An ignored-only cut asserts nothing human; it is a model-labelled
		// dataset that happens to have been selected by hand.
		return labelingSource(models)
	}
}

// reviewedWarnings says out loud what an operator needs to know about a curated
// cut before they train on it.
func reviewedWarnings(humanRows, modelRows, missingFlow int) []string {
	total := humanRows + modelRows
	var out []string
	if modelRows > 0 {
		out = append(out, fmt.Sprintf("%d of %d rows are ignored_pattern reviews labelled with the model's *unconfirmed* prediction (include_ignored) — a person muted the pattern, nobody agreed it is that class", modelRows, total))
	}
	if missingFlow > 0 {
		out = append(out, fmt.Sprintf("%d human review(s) could not be exported: the flow record had already been evicted from the bounded store, so its 48 features were gone — hand-labelled work was lost, consider a larger storage.max_flows", missingFlow))
	}
	return out
}
