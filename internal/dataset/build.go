package dataset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Build guard rails. A dataset that cannot teach anything is a bug an operator
// should hear about immediately, not a file they discover is useless three
// training runs later (PROJECT.md §14).
const (
	// MinRows is the floor below which a selection is refused. Two classes and
	// twenty rows is already a toy, but it is enough to prove a pipeline; below
	// it, a split (70/15/15) cannot even put one row of every class in every
	// part.
	MinRows = 20

	// ImbalanceThreshold is the share of one class above which the manifest
	// carries a class-imbalance warning (PROJECT.md §14, §19.10).
	ImbalanceThreshold = 0.90

	// defaultScan is how many recent classifications a selection walks when the
	// spec does not say. The memory store has no indexes, so a selection is a
	// linear scan of the newest window — the same shape as the classFilterScan
	// the /api/v1/classifications filters use, just far larger because a dataset
	// wants history, not a page.
	defaultScan = 200_000
	maxScan     = 2_000_000
)

// Selection picks the classifications that become dataset rows. The predicates
// that also exist on GET /api/v1/classifications (class, model, min_confidence,
// disagreement) carry exactly the same meaning there and here, so an operator
// can preview a selection in the flow log and then materialise it. from/to,
// proto, initiator_ip, responder_ip and limit extend that set for dataset work.
//
// Every field is optional; the zero Selection means "everything the store
// holds".
type Selection struct {
	// From/To bound Classification.TS inclusively. Zero means unbounded.
	From time.Time `json:"from,omitempty"`
	To   time.Time `json:"to,omitempty"`
	// Class keeps only rows whose ensemble verdict is this traffic-classes-v1
	// class. Note that a single-class selection is refused: this is for
	// excluding a class by building the complement, not for making one.
	Class string `json:"class,omitempty"`
	// Model keeps rows where any model in the ensemble has this model_id.
	Model string `json:"model,omitempty"`
	// Proto matches packet.Proto.String() case-insensitively: TCP, UDP, ICMP,
	// ICMPv6, IP.
	Proto string `json:"proto,omitempty"`
	// InitiatorIP / ResponderIP match the stored tuple string exactly.
	InitiatorIP string `json:"initiator_ip,omitempty"`
	ResponderIP string `json:"responder_ip,omitempty"`
	// MinConfidence keeps rows whose ensemble score is >= this, 0..1.
	MinConfidence float64 `json:"min_confidence,omitempty"`
	// Disagreement keeps only rows the ensemble disagreed on.
	Disagreement bool `json:"disagreement,omitempty"`
	// Limit caps the result at the newest N matching flows (0 = no cap).
	Limit int `json:"limit,omitempty"`
	// Scan is how many recent classifications to walk (0 = defaultScan). It has
	// no meaning with Reviewed: reviews are not a ring, they are all walked.
	Scan int `json:"scan,omitempty"`

	// Reviewed switches the build to the curated path (PROJECT.md §16; issues
	// #42, #64): the rows come from human review decisions instead of from the
	// classification ring, and the CSV label column carries the *human's* label,
	// not the model's prediction. This is the only way labeling_source can say
	// "human_review" — see reviewed.go.
	Reviewed bool `json:"reviewed,omitempty"`
	// IncludeIgnored opts ignored_pattern reviews into a reviewed cut. They are
	// excluded by default: "stop showing me this" is a judgement about the review
	// queue, not the claim "this traffic is class X". Included, they are labelled
	// with the model's unconfirmed prediction and the cut becomes mixed
	// ("human_review+model_prediction:…"). It requires Reviewed.
	IncludeIgnored bool `json:"include_ignored,omitempty"`
}

// MarshalJSON omits the two time bounds when they are unset. time.Time has no
// useful `omitempty`, and a manifest that records the selection as reaching back
// to "0001-01-01T00:00:00Z" reads like a real bound rather than "no bound".
func (s Selection) MarshalJSON() ([]byte, error) {
	type plain Selection // shed the method so this does not recurse
	aux := struct {
		plain
		From *time.Time `json:"from,omitempty"`
		To   *time.Time `json:"to,omitempty"`
	}{plain: plain(s)}
	if !s.From.IsZero() {
		aux.From = &s.From
	}
	if !s.To.IsZero() {
		aux.To = &s.To
	}
	return json.Marshal(aux)
}

// knownProtos mirrors packet.Proto.String(). config-style duplication: dataset
// is above packet in the layering and must not import it for one string set.
var knownProtos = []string{"TCP", "UDP", "ICMP", "ICMPv6", "IP"}

// validate rejects a selection that cannot mean anything before any I/O.
func (s Selection) validate() error {
	if s.Class != "" && !validClass(s.Class) {
		return fmt.Errorf("%w: unknown class %q (traffic-classes-v1: %s)", ErrInvalid, s.Class, strings.Join(classNames(), ", "))
	}
	if s.Proto != "" && !validProto(s.Proto) {
		return fmt.Errorf("%w: unknown proto %q (want one of %s)", ErrInvalid, s.Proto, strings.Join(knownProtos, ", "))
	}
	if s.MinConfidence < 0 || s.MinConfidence > 1 {
		return fmt.Errorf("%w: min_confidence %g is outside 0..1", ErrInvalid, s.MinConfidence)
	}
	if !s.From.IsZero() && !s.To.IsZero() && s.From.After(s.To) {
		return fmt.Errorf("%w: time range from %s is after to %s", ErrInvalid, s.From.UTC().Format(time.RFC3339), s.To.UTC().Format(time.RFC3339))
	}
	if s.Limit < 0 {
		return fmt.Errorf("%w: limit %d is negative", ErrInvalid, s.Limit)
	}
	if s.Scan < 0 {
		return fmt.Errorf("%w: scan %d is negative", ErrInvalid, s.Scan)
	}
	if s.IncludeIgnored && !s.Reviewed {
		return fmt.Errorf("%w: include_ignored only means something with reviewed:true — it opts ignored_pattern reviews into a curated cut", ErrInvalid)
	}
	if s.Reviewed && s.Disagreement {
		return fmt.Errorf("%w: disagreement cannot be combined with reviewed:true — a review record keeps the model's class, score and id, not the ensemble's disagreement flag, so there is nothing to filter on", ErrInvalid)
	}
	return nil
}

func (s Selection) match(c storage.Classification) bool {
	if !s.From.IsZero() && c.TS.Before(s.From) {
		return false
	}
	if !s.To.IsZero() && c.TS.After(s.To) {
		return false
	}
	if s.Class != "" && c.Result.Class != s.Class {
		return false
	}
	if s.Disagreement && !c.Result.Disagreement {
		return false
	}
	if s.MinConfidence > 0 && c.Result.Score < s.MinConfidence {
		return false
	}
	if s.Proto != "" && !strings.EqualFold(c.Proto, s.Proto) {
		return false
	}
	if s.InitiatorIP != "" && c.InitiatorIP != s.InitiatorIP {
		return false
	}
	if s.ResponderIP != "" && c.ResponderIP != s.ResponderIP {
		return false
	}
	if s.Model != "" {
		found := false
		for _, m := range c.Result.Models {
			if m.ModelID == s.Model {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validClass(name string) bool {
	for _, c := range schema.TrafficClassesV1().Classes {
		if c.Name == name {
			return true
		}
	}
	return false
}

func classNames() []string {
	cs := schema.TrafficClassesV1().Classes
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func validProto(p string) bool {
	for _, k := range knownProtos {
		if strings.EqualFold(k, p) {
			return true
		}
	}
	return false
}

// Columns returns the dataset CSV header: the 48 flow-features-v1 names in
// frozen schema order, then "label". This is the trainer contract — the exact
// header trainer/synapse_trainer/dataset.load_csv expects.
func Columns() []string {
	fs := schema.FlowFeaturesV1()
	out := make([]string, 0, len(fs.Features)+1)
	for i := range fs.Features {
		out = append(out, schema.FeatureName(i))
	}
	return append(out, LabelColumn)
}

// built is everything a selection produced, before it becomes a Manifest.
type built struct {
	csv            []byte
	columns        []string
	rows           int
	labelCounts    map[string]int
	labelingSource string
	timeRange      TimeRange
	contentHash    string
	warnings       []string
}

// row is one selected flow: its id, its 48 features and the label.
type row struct {
	flowID uint64
	values [features.Size]float64
	label  string
}

// build reads the flow store, applies the selection, and renders the CSV plus
// everything the manifest reports about it. A Reviewed selection takes the
// curated path in reviewed.go instead.
func build(src FlowSource, rv ReviewSource, sel Selection) (*built, error) {
	if sel.Reviewed {
		return buildReviewed(src, rv, sel)
	}
	scan := sel.Scan
	if scan == 0 {
		scan = defaultScan
	}
	if scan > maxScan {
		scan = maxScan
	}

	// Classifications come back newest first. A flow can be classified more than
	// once (periodic snapshots of a long flow), and a dataset wants one row per
	// flow, so the first verdict seen — the newest — wins. Limit then caps the
	// newest N matching flows, exactly as the API's limit does.
	candidates := src.RecentClassifications(scan)
	seen := make(map[uint64]bool, len(candidates))
	rows := make([]row, 0, 256)
	models := map[string]bool{}
	var missingFlow, nonFinite int
	var minTS, maxTS time.Time

	for _, c := range candidates {
		if !sel.match(c) {
			continue
		}
		if seen[c.FlowID] {
			continue
		}
		seen[c.FlowID] = true

		fr, ok := src.Flow(c.FlowID)
		if !ok {
			// The verdict outlived its flow record in the bounded ring. Without
			// the 48 features there is no row to write; count it and say so.
			missingFlow++
			continue
		}

		r := row{flowID: c.FlowID, label: c.Result.Class}
		r.values = fr.Features.Values
		for i := range r.values {
			if !isFinite(r.values[i]) {
				r.values[i] = schema.FlowFeaturesV1().DefaultMissing
				nonFinite++
			}
		}
		rows = append(rows, r)

		for _, m := range c.Result.Models {
			if m.ModelID != "" {
				models[m.ModelID] = true
			}
		}
		if minTS.IsZero() || c.TS.Before(minTS) {
			minTS = c.TS
		}
		if maxTS.IsZero() || c.TS.After(maxTS) {
			maxTS = c.TS
		}

		if sel.Limit > 0 && len(rows) >= sel.Limit {
			break
		}
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: the selection matched no classifications (scanned %d, %d matched a verdict whose flow record had already been evicted)", ErrUnusable, len(candidates), missingFlow)
	}
	return finish(rows, labelingSource(models), TimeRange{From: rfc3339(minTS), To: rfc3339(maxTS)}, missingFlow, nonFinite, nil)
}

// finish is the shared tail of both build paths: it enforces the guard rails,
// renders the CSV deterministically and fills in everything the manifest
// reports. Keeping it in one place is what guarantees a reviewed cut inherits
// every existing promise — the content hash over the CSV bytes and the
// one-class / too-few-rows refusals.
func finish(rows []row, labelSource string, tr TimeRange, missingFlow, nonFinite int, extraWarnings []string) (*built, error) {
	// Deterministic row order so the content hash is reproducible: two builds
	// from the same store must produce byte-identical CSVs.
	sort.Slice(rows, func(i, j int) bool { return rows[i].flowID < rows[j].flowID })

	counts := map[string]int{}
	for _, r := range rows {
		counts[r.label]++
	}
	if len(counts) < 2 {
		only := ""
		for k := range counts {
			only = k
		}
		return nil, fmt.Errorf("%w: all %d selected flows are class %q — a classifier cannot learn a decision boundary from one class; widen the selection", ErrUnusable, len(rows), only)
	}
	if len(rows) < MinRows {
		return nil, fmt.Errorf("%w: %d flows is below the %d-row floor; widen the time range or the filters", ErrUnusable, len(rows), MinRows)
	}

	columns := Columns()
	csv, dupes := renderCSV(columns, rows)

	b := &built{
		csv:            csv,
		columns:        columns,
		rows:           len(rows),
		labelCounts:    counts,
		labelingSource: labelSource,
		timeRange:      tr,
		contentHash:    contentHash(csv),
	}
	b.warnings = append(extraWarnings, warningsFor(counts, len(rows), dupes, missingFlow, nonFinite)...)
	return b, nil
}

// warningsFor collects everything an operator should know about a dataset that
// was still built (PROJECT.md §19.10: class-imbalance and duplicate warnings).
func warningsFor(counts map[string]int, total, dupes, missingFlow, nonFinite int) []string {
	var out []string

	// Class imbalance. Report the dominant class and the whole distribution
	// rather than a bare "imbalanced": the operator needs to know which way.
	top, topN := "", 0
	for k, n := range counts {
		if n > topN || (n == topN && k < top) {
			top, topN = k, n
		}
	}
	if share := float64(topN) / float64(total); share >= ImbalanceThreshold {
		out = append(out, fmt.Sprintf("class imbalance: %q is %.1f%% of %d flows — a model trained on this will mostly learn to say %q",
			top, share*100, total, top))
	}
	if len(counts) < len(classNames()) {
		var absent []string
		for _, name := range classNames() {
			if counts[name] == 0 {
				absent = append(absent, name)
			}
		}
		out = append(out, fmt.Sprintf("%d of %d traffic-classes-v1 classes have no rows (%s) — the model cannot learn them",
			len(absent), len(classNames()), strings.Join(absent, ", ")))
	}
	if dupes > 0 {
		out = append(out, fmt.Sprintf("%d of %d rows duplicate an earlier row exactly (same 48 features and label) — they add weight, not information", dupes, total))
	}
	if missingFlow > 0 {
		out = append(out, fmt.Sprintf("%d matching classification(s) were skipped: their flow record had already been evicted from the bounded store, so the 48 features were gone", missingFlow))
	}
	if nonFinite > 0 {
		out = append(out, fmt.Sprintf("%d feature value(s) were not finite and were written as the schema default_missing (%g)", nonFinite, schema.FlowFeaturesV1().DefaultMissing))
	}
	return out
}

// renderCSV writes the header and one line per row, and counts exact duplicate
// rows on the way past. The value format is Go's shortest round-tripping
// representation, which Python's float() parses unchanged.
func renderCSV(columns []string, rows []row) (csv []byte, dupes int) {
	var sb strings.Builder
	sb.Grow(len(rows) * 512)
	sb.WriteString(strings.Join(columns, ","))
	sb.WriteByte('\n')

	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		start := sb.Len()
		for i := range r.values {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(strconv.FormatFloat(r.values[i], 'g', -1, 64))
		}
		sb.WriteByte(',')
		sb.WriteString(r.label)
		// Clone: a slice of sb.String() aliases the builder's buffer, which the
		// next Grow would move out from under the map key.
		line := strings.Clone(sb.String()[start:])
		if seen[line] {
			dupes++
		} else {
			seen[line] = true
		}
		sb.WriteByte('\n')
	}
	return []byte(sb.String()), dupes
}

// hashPrefix is the domain separator the content hash is computed over. It
// binds the digest to this dataset format and to the frozen schema pair, so the
// same rows under a different schema could never hash the same.
const hashPrefix = "synapseids-dataset-v1\n"

// contentHash is sha256 over the schema identity plus the exact CSV bytes. The
// CSV carries the 48 feature values, the label column and the column header, so
// the digest covers the data, the labels and the schema — and nothing else. Two
// datasets built from the same rows and labels hash identically no matter what
// they are called, who built them or when (PROJECT.md §14).
func contentHash(csv []byte) string {
	h := sha256.New()
	h.Write([]byte(hashPrefix))
	h.Write([]byte("feature_schema:" + schema.FlowFeaturesV1().Schema + "\n"))
	h.Write([]byte("output_schema:" + schema.TrafficClassesV1().Schema + "\n"))
	h.Write(csv)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// labelingSource states, literally, where the labels came from.
//
// A default (non-Reviewed) cut is labelled by the daemon's own model predictions
// — the daemon grading its own homework. Training on it teaches a new model to
// imitate the old one, which is a real and useful thing to do (distillation,
// bootstrapping a location model) and is not the same thing as ground truth. The
// manifest says so in a field the UI shows on every row, so no one can mistake
// one for the other.
//
// A Reviewed cut is the other case and the only one that may write
// "human_review": see reviewedLabelingSource in reviewed.go.
func labelingSource(models map[string]bool) string {
	if len(models) == 0 {
		return "model_prediction:unknown"
	}
	ids := make([]string, 0, len(models))
	for id := range models {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return "model_prediction:" + strings.Join(ids, "+")
}

func isFinite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
