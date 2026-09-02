// Package report builds a self-contained investigation artefact out of the
// daemon's live read models, and renders it as JSON or as one standalone HTML
// file (PROJECT.md §19.3, §19.4; issue #66).
//
// # Why a package and not a handler
//
// An operator investigating a host or a time window needs something they can
// hand to someone else: attach to a ticket, mail to a peer team, keep next to an
// incident write-up. Everything that would go in it already exists behind the
// live API — internal/insight has the host profile and the timeline,
// storage.Store has the flow records and verdicts, internal/schema names the
// features, inference.Runtime knows which models were scoring. Nothing here
// measures anything new: Build is an aggregation and Render is a projection.
// Keeping both out of internal/api means the selection rules are unit-testable
// without an HTTP round trip, and the handlers stay one mux line each.
//
// # Honesty rules
//
// A report is an artefact someone may act on, possibly days later and without
// access to the daemon that produced it. Completeness matters less than not
// misleading the reader, so three rules are structural rather than best-effort:
//
//  1. **Say what is unavailable.** Behavioural baselines and anomaly scores are
//     Phase 7 (§13, §19.4-6). The report always carries an explicit
//     "not available in this build" note while insight reports
//     baseline_available/anomaly_available false. It never emits an empty chart
//     that a reader could mistake for "nothing anomalous here".
//  2. **Say when the view is partial.** storage.Mem is a bounded ring that
//     evicts, and insight's host map and per-host top-N lists are capped with
//     eviction counters. Whenever a counter is non-zero, or a scan hit its
//     limit, or the notable-flow list was truncated, the report says so and
//     names the limit. Coverage carries the numbers; Notes carries the prose.
//  3. **Say how stale it is.** Every report is stamped with the exact daemon
//     version, commit and build date, plus the generation time.
//
// # Untrusted input
//
// Every string in a report — addresses, protocol names, sensor names, close
// reasons, the filter description echoed back from the query — is packet- or
// request-derived and therefore untrusted (§21, §28.11). The HTML renderer uses
// html/template, whose contextual escaping is the control that stops a crafted
// value from injecting markup into a document an operator opens in a browser.
// See html.go and ADR 0023.
package report

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

// SchemaID names this report contract. It is versioned like every other
// document the daemon emits (§28.14): a breaking change gets v2.
const SchemaID = "investigation-report-v1"

// Bounds. A report is a download, not a database export: it must be generated
// from a bounded scan and must fit in a document a human will actually read.
const (
	// DefaultMaxFlows caps the notable-flow table. When more candidates match,
	// the highest-ranked DefaultMaxFlows are kept and the report says the list
	// was truncated (Coverage.NotableFlowsTruncated, note "flows_truncated").
	DefaultMaxFlows = 500
	// MaxFlowsCap is the ceiling on a caller-supplied MaxFlows.
	MaxFlowsCap = 2000
	// DefaultScanLimit is how many of the newest stored verdicts a report walks.
	// storage.Mem has no index beyond flow ID, so scope selection is a linear
	// scan of the newest window — the same substitute for an index that the
	// filtered /api/v1/classifications query uses.
	DefaultScanLimit = 5000
	// DefaultBucketSec is the timeline resolution when the caller does not pick.
	DefaultBucketSec = 10
)

// ErrUnknownHost is returned by Build for a host scope whose address the
// insight index has never observed. The API turns it into a 404.
var ErrUnknownHost = errors.New("report: host not observed")

// ScopeKind selects what a report is about.
type ScopeKind string

// The two supported scopes.
const (
	// ScopeHost pivots the whole report around one address (§19.4).
	ScopeHost ScopeKind = "host"
	// ScopeRange covers every observed conversation in a time window (§19.6).
	ScopeRange ScopeKind = "range"
)

// Sources is the live state a report is built from. Every field is optional:
// a nil Store, Insight or Runtime degrades to an empty section plus a note,
// never a panic.
type Sources struct {
	Store   storage.Store
	Insight *insight.Index
	Runtime *inference.Runtime
}

// Options configure one Build. The zero value is not useful — Scope is
// required — but every other field has a documented default.
type Options struct {
	// Scope is ScopeHost or ScopeRange.
	Scope ScopeKind
	// Host is the canonical address for ScopeHost. The caller (the API) has
	// already validated it with net/netip.
	Host string
	// From and To bound the window, inclusive. A zero time means unbounded.
	From, To time.Time
	// BucketSec is the timeline resolution: 1, 10 or 60. Anything else falls
	// back to DefaultBucketSec.
	BucketSec int
	// MaxFlows caps the notable-flow table; <= 0 selects DefaultMaxFlows and
	// anything above MaxFlowsCap is clamped.
	MaxFlows int
	// ScanLimit is how many stored verdicts to walk; <= 0 selects
	// DefaultScanLimit.
	ScanLimit int
	// Keep is an optional verdict predicate. The API builds it from
	// parseClassFilters so a report speaks exactly the same filter dialect as
	// /api/v1/classifications. A nil Keep keeps everything.
	Keep func(storage.Classification) bool
	// FilterDesc is the human-readable echo of Keep, e.g. `class=scan
	// disagreement=true`. It is request-derived and therefore untrusted; the
	// HTML renderer escapes it like every other value.
	FilterDesc string
	// GeneratedAt stamps the report. A zero value means time.Now().UTC(), which
	// is what the daemon passes; tests pass a fixed instant so the output is
	// byte-for-byte deterministic.
	GeneratedAt time.Time
}

func (o Options) withDefaults() Options {
	if !insight.ValidBucketSec(o.BucketSec) {
		o.BucketSec = DefaultBucketSec
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = DefaultMaxFlows
	}
	if o.MaxFlows > MaxFlowsCap {
		o.MaxFlows = MaxFlowsCap
	}
	if o.ScanLimit <= 0 {
		o.ScanLimit = DefaultScanLimit
	}
	if o.GeneratedAt.IsZero() {
		o.GeneratedAt = time.Now()
	}
	o.GeneratedAt = o.GeneratedAt.UTC()
	return o
}

// ------------------------------------------------------------------ documents

// Generator is the build stamp: which binary produced this artefact, and when.
// A reader with only the file needs this to tell how stale it is and which code
// computed the verdicts (§24).
type Generator struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Dirty   bool   `json:"dirty"`
	// FeatureSchema and OutputSchema are the frozen contracts this build speaks
	// (§8, §9), so a reader can tell whether two reports are comparable.
	FeatureSchema string `json:"feature_schema"`
	OutputSchema  string `json:"output_schema"`
}

func generator() Generator {
	return Generator{
		Product:       "synapseids",
		Version:       version.Version,
		Commit:        version.Commit,
		BuiltAt:       version.Date,
		Dirty:         version.Dirty == "true",
		FeatureSchema: schema.FlowFeaturesV1().Schema,
		OutputSchema:  schema.TrafficClassesV1().Schema,
	}
}

// Scope records exactly what was asked for, so a reader never has to guess
// whether an absent finding means "nothing there" or "not looked at".
type Scope struct {
	Kind ScopeKind `json:"kind"`
	Host string    `json:"host,omitempty"`
	From time.Time `json:"from,omitzero"`
	To   time.Time `json:"to,omitzero"`
	// Unbounded is true when neither From nor To was supplied: the window is
	// "whatever the daemon still retains", which is not the same as "all time".
	Unbounded bool `json:"unbounded"`
	// Filter echoes the classification predicates the report was generated
	// with; empty means none were applied.
	Filter string `json:"filter,omitempty"`
}

// ModelRef is one classifier that was live when the report was generated
// (§12: the active model set is part of the evidence, not an aside).
type ModelRef struct {
	ID     string `json:"id"`
	Family string `json:"family"`
	Role   string `json:"role"`
}

// FeatureMeta is one entry of the feature legend carried with the report, so an
// outside reader can interpret a raw value without the daemon (§19.3).
type FeatureMeta struct {
	Name string `json:"name"`
	Unit string `json:"unit"`
	Calc string `json:"calc"`
}

// FeatureValue is one named raw flow-features-v1 value for one flow. Raw, not
// normalized: the Phase-1 heuristic scores raw values, and a trained model's
// normalizer is a per-model concern the report does not own.
type FeatureValue struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

// ClassCount is one traffic class and how many in-scope verdicts chose it.
type ClassCount struct {
	Class   string  `json:"class"`
	ClassID int     `json:"class_id"`
	Count   uint64  `json:"count"`
	Share   float64 `json:"share"`
}

// Notable-flow reasons. A flow can carry both.
const (
	// ReasonDisagreement — the ensemble's models did not agree (§12).
	ReasonDisagreement = "model_disagreement"
	// ReasonNonNormal — the verdict was something other than "normal".
	ReasonNonNormal = "non_normal_verdict"
)

// NotableFlow is one selected conversation, with everything an outside reader
// needs to judge it: the tuple, the timing, the volume, the ensemble verdict,
// every model's own output, and the named raw feature values this build's
// classifier actually reads.
type NotableFlow struct {
	FlowID uint64 `json:"flow_id"`
	// Reasons is why this flow was selected, sorted for determinism.
	Reasons []string  `json:"reasons"`
	TS      time.Time `json:"ts"`
	Sensor  string    `json:"sensor,omitempty"`

	Proto         string `json:"proto"`
	InitiatorIP   string `json:"initiator_ip"`
	InitiatorPort uint16 `json:"initiator_port"`
	ResponderIP   string `json:"responder_ip"`
	ResponderPort uint16 `json:"responder_port"`

	Class        string                  `json:"class"`
	ClassID      int                     `json:"class_id"`
	Score        float64                 `json:"score"`
	Disagreement bool                    `json:"disagreement"`
	Models       []inference.ModelOutput `json:"models"`

	// FirstSeen..CloseReason come from the stored flow record. They are only
	// populated when RecordAvailable is true.
	FirstSeen   time.Time `json:"first_seen,omitzero"`
	LastSeen    time.Time `json:"last_seen,omitzero"`
	DurationSec float64   `json:"duration_sec"`
	FwdPackets  uint64    `json:"fwd_packets"`
	BwdPackets  uint64    `json:"bwd_packets"`
	FwdBytes    uint64    `json:"fwd_bytes"`
	BwdBytes    uint64    `json:"bwd_bytes"`
	CloseReason string    `json:"close_reason,omitempty"`

	// RecordAvailable is false when the flow record behind this verdict has
	// already been evicted from the bounded store: the verdict survives in the
	// classification ring but its features and byte counters are gone. The
	// report says so per flow rather than printing zeroes.
	RecordAvailable bool `json:"record_available"`
	// Features is the decision-relevant named subset (see DecisionFeatures).
	// Empty when RecordAvailable is false.
	Features []FeatureValue `json:"features,omitempty"`
}

// Coverage is the machine-readable half of the honesty contract: every limit
// that applied to this report and every discard the daemon had already made.
// Notes is the human-readable half.
type Coverage struct {
	// Partial is true when anything below means the report is not a complete
	// view of the requested scope. It is the single flag a reader (or a ticket
	// system) can branch on.
	Partial bool `json:"partial"`

	// --- storage.Store (bounded rings that evict) ---
	StoreDriver             string `json:"store_driver"`
	FlowsRetained           int    `json:"flows_retained"`
	FlowsEvicted            uint64 `json:"flows_evicted"`
	ClassificationsRetained int    `json:"classifications_retained"`
	ClassificationsEvicted  uint64 `json:"classifications_evicted"`
	// ScanLimit is how many of the newest verdicts were walked; ScanExhausted
	// is true when the scan filled that budget, meaning older in-scope verdicts
	// exist but were not considered.
	ScanLimit     int  `json:"scan_limit"`
	ScanScanned   int  `json:"scan_scanned"`
	ScanExhausted bool `json:"scan_exhausted"`
	// OldestRetained is the timestamp of the oldest verdict the scan saw.
	// RangeStartsBeforeRetention is true when the requested From is older than
	// that: the window extends past what the daemon still holds.
	OldestRetained             time.Time `json:"oldest_retained,omitzero"`
	RangeStartsBeforeRetention bool      `json:"range_starts_before_retention"`

	// --- internal/insight (capped maps and top-N lists) ---
	HostsTracked        int    `json:"hosts_tracked"`
	HostCap             int    `json:"host_cap"`
	HostsEvicted        uint64 `json:"hosts_evicted"`
	KeyCap              int    `json:"key_cap"`
	KeysPruned          uint64 `json:"keys_pruned"`
	ObservationsDropped uint64 `json:"observations_dropped"`
	TimelineLate        uint64 `json:"timeline_late"`

	// --- notable flows ---
	NotableFlowCap        int  `json:"notable_flow_cap"`
	NotableCandidates     int  `json:"notable_candidates"`
	NotableFlowsTruncated bool `json:"notable_flows_truncated"`
	FlowRecordsMissing    int  `json:"flow_records_missing"`

	// --- Phase 7 ---
	// BaselineAvailable and AnomalyAvailable mirror insight's fields and are
	// false in this build. They exist so a reader can tell "not computed" from
	// "computed and clean".
	BaselineAvailable bool `json:"baseline_available"`
	AnomalyAvailable  bool `json:"anomaly_available"`
}

// Note severities.
const (
	// LevelInfo — context the reader should have.
	LevelInfo = "info"
	// LevelWarning — the report is less complete than it looks.
	LevelWarning = "warning"
)

// Note codes. A consumer keys on Code; a human reads Text.
const (
	NoteBaselineUnavailable = "baseline_unavailable"
	NoteAnomalyUnavailable  = "anomaly_unavailable"
	NotePartialStoreEvicted = "partial_store_evicted"
	NotePartialScanWindow   = "partial_scan_window"
	NotePartialRetention    = "partial_before_retention"
	NotePartialHostsEvicted = "partial_hosts_evicted"
	NotePartialTopNPruned   = "partial_topn_pruned"
	NotePartialObsDropped   = "partial_observations_dropped"
	NotePartialTimelineLate = "partial_timeline_late"
	NoteFlowsTruncated      = "flows_truncated"
	NoteFlowRecordsMissing  = "flow_records_missing"
	NoteNoModels            = "no_models"
	NoteNoStore             = "no_store"
	NoteNoInsight           = "no_insight"
	NoteFeatureAttribution  = "feature_attribution_unavailable"
	NoteUnboundedWindow     = "unbounded_window"
)

// Note is one explicit statement about what this report does and does not know.
type Note struct {
	Code  string `json:"code"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Timeline sources.
const (
	// TimelineFromRing — the incrementally maintained insight ring: exact
	// within its own window.
	TimelineFromRing = "insight-ring"
	// TimelineFromRetained — bucketed on demand from the scanned window of
	// retained verdicts, which is what a host- or filter-scoped series needs.
	TimelineFromRetained = "retained-classifications"
)

// Timeline wraps an insight.Series with a note about where it came from.
type Timeline struct {
	Source string `json:"source"`
	insight.Series
}

// Report is one self-contained investigation artefact. Everything an outside
// reader needs is in this struct; nothing in it requires a call back to the
// daemon.
type Report struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Generator   Generator `json:"generator"`
	Scope       Scope     `json:"scope"`

	// Coverage and Notes come before the findings on purpose: the caveats are
	// part of the finding, not a footnote.
	Coverage Coverage `json:"coverage"`
	Notes    []Note   `json:"notes"`

	// Summary is the in-scope headline count set.
	Summary Summary `json:"summary"`
	// Host is the insight profile, for ScopeHost only.
	Host *insight.Profile `json:"host,omitempty"`

	Classes   []ClassCount         `json:"classes"`
	Timeline  Timeline             `json:"timeline"`
	TopPeers  []insight.PeerCount  `json:"top_peers"`
	TopPorts  []insight.PortCount  `json:"top_ports"`
	Protocols []insight.ProtoCount `json:"protocols"`
	Models    []ModelRef           `json:"models"`

	NotableFlows []NotableFlow `json:"notable_flows"`
	// FeatureLegend documents the named feature values carried per flow.
	FeatureLegend []FeatureMeta `json:"feature_legend"`
}

// Summary is the in-scope headline. Every number here is derived from the
// verdicts the scan actually saw, so it is consistent with the rest of the
// document even when Coverage says the view is partial.
type Summary struct {
	Classifications uint64 `json:"classifications"`
	Disagreements   uint64 `json:"disagreements"`
	NonNormal       uint64 `json:"non_normal"`
	DistinctFlows   int    `json:"distinct_flows"`
	DistinctHosts   int    `json:"distinct_hosts"`
	// FirstVerdict and LastVerdict bound the data actually included, which may
	// be narrower than Scope.From..Scope.To.
	FirstVerdict time.Time `json:"first_verdict,omitzero"`
	LastVerdict  time.Time `json:"last_verdict,omitzero"`
}

// ---------------------------------------------------------- decision features

// DecisionFeatures is the fixed, documented subset of flow-features-v1 carried
// with every notable flow. These are exactly the named values this build's
// classifier reads (internal/inference/heuristic.go), so they are the values
// that actually drove the verdict rather than an arbitrary selection.
//
// This is deliberately *not* a per-flow attribution or a ranked contribution
// list: real feature attribution and the baseline column §19.3 sketches need
// the Phase 7 explanation work. The report carries the
// "feature_attribution_unavailable" note so a reader does not read this table
// as "the top contributing features".
//
// Order is the frozen schema order, not the order they appear in the heuristic,
// so two reports list the same features in the same places.
var DecisionFeatures = orderedBySchema([]string{
	"flow_duration",
	"packets_forward",
	"packets_backward",
	"bytes_forward",
	"bytes_backward",
	"packet_size_mean",
	"packets_per_second",
	"interarrival_mean",
	"interarrival_stddev",
	"destination_port",
	"protocol_tcp",
	"protocol_udp",
	"tcp_syn_count",
	"tcp_ack_count",
	"tcp_fin_count",
	"tcp_rst_count",
	"packet_direction_ratio",
	"small_packet_ratio",
})

// orderedBySchema sorts names into frozen flow-features-v1 index order and
// panics on a name the schema does not define. A typo here would silently emit
// a column of zeroes into an artefact someone acts on, so it fails at init
// instead (§28.5).
func orderedBySchema(names []string) []string {
	idx := make(map[string]int, features.Size)
	for i := 0; i < features.Size; i++ {
		idx[schema.FeatureName(i)] = i
	}
	for _, n := range names {
		if _, ok := idx[n]; !ok {
			panic(fmt.Sprintf("report: %q is not a %s feature", n, schema.FlowFeaturesV1().Schema))
		}
	}
	out := append([]string(nil), names...)
	sort.Slice(out, func(i, j int) bool { return idx[out[i]] < idx[out[j]] })
	return out
}

// featureLegend builds the legend for DecisionFeatures once per report.
func featureLegend() []FeatureMeta {
	meta := make(map[string]schema.Feature, features.Size)
	for _, f := range schema.FlowFeaturesV1().Features {
		meta[f.Name] = f
	}
	out := make([]FeatureMeta, 0, len(DecisionFeatures))
	for _, n := range DecisionFeatures {
		f := meta[n]
		out = append(out, FeatureMeta{Name: f.Name, Unit: f.Unit, Calc: f.Calc})
	}
	return out
}

// decisionValues projects a stored vector onto DecisionFeatures.
func decisionValues(v features.Vector, legend []FeatureMeta) []FeatureValue {
	out := make([]FeatureValue, 0, len(legend))
	for _, f := range legend {
		out = append(out, FeatureValue{Name: f.Name, Value: v.Get(f.Name), Unit: f.Unit})
	}
	return out
}

// ----------------------------------------------------------------- build

// Build assembles a report from live state. It is deterministic: given the same
// Sources content and Options — including Options.GeneratedAt — it produces the
// same document, so a test can assert on the bytes.
//
// It never blocks the packet path: every read goes through storage.Store's own
// lock or insight's read lock, exactly like the equivalent API handler.
func Build(src Sources, opt Options) (*Report, error) {
	opt = opt.withDefaults()

	legend := featureLegend()
	r := &Report{
		Schema:      SchemaID,
		GeneratedAt: opt.GeneratedAt,
		Generator:   generator(),
		Scope: Scope{
			Kind:      opt.Scope,
			Host:      opt.Host,
			From:      opt.From.UTC(),
			To:        opt.To.UTC(),
			Unbounded: opt.From.IsZero() && opt.To.IsZero(),
			Filter:    opt.FilterDesc,
		},
		Classes:       []ClassCount{},
		TopPeers:      []insight.PeerCount{},
		TopPorts:      []insight.PortCount{},
		Protocols:     []insight.ProtoCount{},
		Models:        []ModelRef{},
		NotableFlows:  []NotableFlow{},
		FeatureLegend: legend,
		Notes:         []Note{},
	}
	if opt.From.IsZero() {
		r.Scope.From = time.Time{}
	}
	if opt.To.IsZero() {
		r.Scope.To = time.Time{}
	}

	switch opt.Scope {
	case ScopeHost:
		p, ok := src.Insight.Host(opt.Host)
		if !ok {
			return nil, ErrUnknownHost
		}
		r.Host = &p
		r.TopPeers = nonNilPeers(p.TopPeers)
		r.TopPorts = nonNilPorts(p.TopPorts)
		r.Protocols = nonNilProtos(p.Protocols)
	case ScopeRange:
		// Nothing host-specific; the aggregates below are computed from the
		// in-scope verdicts and their flow records.
	default:
		return nil, fmt.Errorf("report: unknown scope %q", opt.Scope)
	}

	// One bounded scan of the newest verdicts serves the class breakdown, the
	// summary, the timeline and the notable-flow selection.
	var rows []storage.Classification
	if src.Store != nil {
		rows = src.Store.RecentClassifications(opt.ScanLimit)
	}
	keep := scopeFilter(opt)
	inScope := make([]storage.Classification, 0, min(len(rows), 512))
	for _, c := range rows {
		if keep(c) {
			inScope = append(inScope, c)
		}
	}

	r.Summary = summarise(inScope)
	r.Classes = classBreakdown(inScope)
	r.Timeline = buildTimeline(src, opt, inScope)
	if opt.Scope == ScopeRange {
		r.TopPeers, r.TopPorts, r.Protocols = rangeAggregates(inScope)
	}
	r.Models = modelSet(src.Runtime)

	var candidates, missing int
	r.NotableFlows, candidates, missing = notableFlows(src.Store, inScope, opt.MaxFlows, legend)

	r.Coverage = coverage(src, opt, rows, candidates, len(r.NotableFlows), missing)
	r.Notes = notes(r.Coverage, r.Scope, len(r.Models))
	return r, nil
}

// scopeFilter composes the scope's own predicate with the caller's optional
// classification filter. It is applied to the newest-first scan.
func scopeFilter(opt Options) func(storage.Classification) bool {
	return func(c storage.Classification) bool {
		if opt.Scope == ScopeHost && c.InitiatorIP != opt.Host && c.ResponderIP != opt.Host {
			return false
		}
		if !opt.From.IsZero() && c.TS.Before(opt.From) {
			return false
		}
		if !opt.To.IsZero() && c.TS.After(opt.To) {
			return false
		}
		if opt.Keep != nil && !opt.Keep(c) {
			return false
		}
		return true
	}
}

func summarise(rows []storage.Classification) Summary {
	s := Summary{}
	flows := make(map[uint64]struct{}, len(rows))
	hosts := make(map[string]struct{}, len(rows))
	for _, c := range rows {
		s.Classifications++
		if c.Result.Disagreement {
			s.Disagreements++
		}
		if c.Result.Class != "" && c.Result.Class != normalClass {
			s.NonNormal++
		}
		flows[c.FlowID] = struct{}{}
		if c.InitiatorIP != "" {
			hosts[c.InitiatorIP] = struct{}{}
		}
		if c.ResponderIP != "" {
			hosts[c.ResponderIP] = struct{}{}
		}
		if c.TS.IsZero() {
			continue
		}
		if s.FirstVerdict.IsZero() || c.TS.Before(s.FirstVerdict) {
			s.FirstVerdict = c.TS
		}
		if c.TS.After(s.LastVerdict) {
			s.LastVerdict = c.TS
		}
	}
	s.DistinctFlows = len(flows)
	s.DistinctHosts = len(hosts)
	s.FirstVerdict = s.FirstVerdict.UTC()
	s.LastVerdict = s.LastVerdict.UTC()
	return s
}

// normalClass is the traffic-classes-v1 baseline class name. A verdict that is
// not this is what makes a flow notable.
const normalClass = "normal"

// classBreakdown counts in-scope verdicts per class, in frozen schema order so
// two reports put the same class in the same row.
func classBreakdown(rows []storage.Classification) []ClassCount {
	var counts [inference.OutputSize]uint64
	var total uint64
	for _, c := range rows {
		if id := c.Result.ClassID; id >= 0 && id < len(counts) {
			counts[id]++
			total++
		}
	}
	out := make([]ClassCount, 0, len(counts))
	for i, n := range counts {
		if n == 0 {
			continue
		}
		cc := ClassCount{Class: insight.ClassName(i), ClassID: i, Count: n}
		if total > 0 {
			cc.Share = float64(n) / float64(total)
		}
		out = append(out, cc)
	}
	return out
}

// buildTimeline picks the series source. An unfiltered range report is answered
// from insight's incrementally maintained ring, which is exact within its own
// (wider) window. A host scope or any classification filter cannot come from
// that ring — a ring per host would be unbounded — so those are bucketed on
// demand from the scanned verdicts, mirroring GET /api/v1/timeline exactly.
func buildTimeline(src Sources, opt Options, inScope []storage.Classification) Timeline {
	if opt.Scope == ScopeRange && opt.Keep == nil {
		return Timeline{
			Source: TimelineFromRing,
			Series: src.Insight.Timeline(opt.BucketSec, opt.From, opt.To),
		}
	}
	// inScope is already scope-filtered, so BucketSamples needs no predicate.
	return Timeline{
		Source: TimelineFromRetained,
		Series: insight.BucketSamples(inScope, opt.BucketSec, opt.From, opt.To, nil),
	}
}

// rangeAggregates derives top peers, ports and protocols for a range report
// from the in-scope verdicts. A host report uses insight's own profile lists
// instead; a range has no single subject, so these are the busiest addresses,
// service ports and protocols in the window.
func rangeAggregates(rows []storage.Classification) ([]insight.PeerCount, []insight.PortCount, []insight.ProtoCount) {
	peers := map[string]uint64{}
	ports := map[uint16]uint64{}
	protos := map[string]uint64{}
	for _, c := range rows {
		if c.InitiatorIP != "" {
			peers[c.InitiatorIP]++
		}
		if c.ResponderIP != "" && c.ResponderIP != c.InitiatorIP {
			peers[c.ResponderIP]++
		}
		ports[c.ResponderPort]++
		if c.Proto != "" {
			protos[c.Proto]++
		}
	}
	const topN = 16
	pk := make([]insight.PeerCount, 0, len(peers))
	for ip, n := range peers {
		pk = append(pk, insight.PeerCount{IP: ip, Flows: n})
	}
	sort.Slice(pk, func(i, j int) bool {
		if pk[i].Flows != pk[j].Flows {
			return pk[i].Flows > pk[j].Flows
		}
		return pk[i].IP < pk[j].IP
	})
	if len(pk) > topN {
		pk = pk[:topN]
	}

	po := make([]insight.PortCount, 0, len(ports))
	for p, n := range ports {
		po = append(po, insight.PortCount{Port: p, Flows: n})
	}
	sort.Slice(po, func(i, j int) bool {
		if po[i].Flows != po[j].Flows {
			return po[i].Flows > po[j].Flows
		}
		return po[i].Port < po[j].Port
	})
	if len(po) > topN {
		po = po[:topN]
	}

	pr := make([]insight.ProtoCount, 0, len(protos))
	for p, n := range protos {
		pr = append(pr, insight.ProtoCount{Proto: p, Flows: n})
	}
	sort.Slice(pr, func(i, j int) bool {
		if pr[i].Flows != pr[j].Flows {
			return pr[i].Flows > pr[j].Flows
		}
		return pr[i].Proto < pr[j].Proto
	})
	return pk, po, pr
}

func modelSet(rt *inference.Runtime) []ModelRef {
	if rt == nil {
		return []ModelRef{}
	}
	live := rt.Models()
	out := make([]ModelRef, 0, len(live))
	for _, m := range live {
		out = append(out, ModelRef{ID: m.ID(), Family: m.Family(), Role: string(m.Role())})
	}
	return out
}

// notableFlows selects and materialises the flows worth reading. It returns the
// bounded table, how many candidates qualified before the cap, and how many of
// the listed verdicts had already lost their stored flow record.
//
// Selection: every in-scope verdict that either disagreed across models (§12) or
// landed on something other than "normal". Ranking puts disagreements first —
// they are the rarest and the most actionable — then descending confidence, then
// newest, then flow ID, so the order is total and the output deterministic.
func notableFlows(store storage.Store, rows []storage.Classification, limit int, legend []FeatureMeta) (out []NotableFlow, candidates, missing int) {
	type cand struct {
		c            storage.Classification
		disagreement bool
	}
	sel := make([]cand, 0, min(len(rows), limit))
	for _, c := range rows {
		nonNormal := c.Result.Class != "" && c.Result.Class != normalClass
		if !c.Result.Disagreement && !nonNormal {
			continue
		}
		sel = append(sel, cand{c: c, disagreement: c.Result.Disagreement})
	}
	sort.SliceStable(sel, func(i, j int) bool {
		a, b := sel[i], sel[j]
		if a.disagreement != b.disagreement {
			return a.disagreement // disagreements first
		}
		if a.c.Result.Score != b.c.Result.Score {
			return a.c.Result.Score > b.c.Result.Score
		}
		if !a.c.TS.Equal(b.c.TS) {
			return a.c.TS.After(b.c.TS)
		}
		return a.c.FlowID < b.c.FlowID
	})

	candidates = len(sel)
	if len(sel) > limit {
		sel = sel[:limit]
	}

	out = make([]NotableFlow, 0, len(sel))
	for _, s := range sel {
		c := s.c
		nf := NotableFlow{
			FlowID:        c.FlowID,
			TS:            c.TS.UTC(),
			Sensor:        c.Sensor,
			Proto:         c.Proto,
			InitiatorIP:   c.InitiatorIP,
			InitiatorPort: c.InitiatorPort,
			ResponderIP:   c.ResponderIP,
			ResponderPort: c.ResponderPort,
			Class:         c.Result.Class,
			ClassID:       c.Result.ClassID,
			Score:         c.Result.Score,
			Disagreement:  c.Result.Disagreement,
			Models:        c.Result.Models,
		}
		if nf.Models == nil {
			nf.Models = []inference.ModelOutput{}
		}
		nf.Reasons = reasonsFor(c)

		if store != nil {
			if fr, ok := store.Flow(c.FlowID); ok {
				nf.RecordAvailable = true
				nf.FirstSeen = fr.FirstSeen.UTC()
				nf.LastSeen = fr.LastSeen.UTC()
				nf.DurationSec = fr.DurationSec
				nf.FwdPackets = fr.FwdPackets
				nf.BwdPackets = fr.BwdPackets
				nf.FwdBytes = fr.FwdBytes
				nf.BwdBytes = fr.BwdBytes
				nf.CloseReason = fr.CloseReason
				nf.Features = decisionValues(fr.Features, legend)
			}
		}
		if !nf.RecordAvailable {
			missing++
		}
		out = append(out, nf)
	}
	return out, candidates, missing
}

// reasonsFor returns the selection reasons in a fixed order.
func reasonsFor(c storage.Classification) []string {
	out := make([]string, 0, 2)
	if c.Result.Disagreement {
		out = append(out, ReasonDisagreement)
	}
	if c.Result.Class != "" && c.Result.Class != normalClass {
		out = append(out, ReasonNonNormal)
	}
	return out
}

// ------------------------------------------------------------------- coverage

func coverage(src Sources, opt Options, scanned []storage.Classification, candidates, listed, missing int) Coverage {
	c := Coverage{
		ScanLimit:             opt.ScanLimit,
		ScanScanned:           len(scanned),
		ScanExhausted:         len(scanned) >= opt.ScanLimit,
		NotableFlowCap:        opt.MaxFlows,
		NotableCandidates:     candidates,
		NotableFlowsTruncated: candidates > listed,
		FlowRecordsMissing:    missing,
		// Behavioural baselines are still Phase 7 and this package will not
		// invent one (§13, §19.4-6). AnomalyAvailable is set below from the
		// scanned verdicts: true when a flow-anomaly-v1 model scored any of them.
		BaselineAvailable: false,
		AnomalyAvailable:  anomalyScored(scanned),
	}
	if src.Store != nil {
		st := src.Store.Stats()
		c.StoreDriver = st.Driver
		c.FlowsRetained = st.Flows
		c.FlowsEvicted = st.FlowsEvicted
		c.ClassificationsRetained = st.Classifications
		c.ClassificationsEvicted = st.ClassEvicted
	}
	if src.Insight != nil {
		is := src.Insight.Stats()
		c.HostsTracked = is.Hosts
		c.HostCap = is.HostCap
		c.HostsEvicted = is.HostsEvicted
		c.KeyCap = is.KeyCap
		c.KeysPruned = is.KeysPruned
		c.ObservationsDropped = is.Dropped
		c.TimelineLate = is.TimelineLate
	}

	// The oldest verdict the scan saw. RecentClassifications is newest-first,
	// so it is the last element.
	for i := len(scanned) - 1; i >= 0; i-- {
		if !scanned[i].TS.IsZero() {
			c.OldestRetained = scanned[i].TS.UTC()
			break
		}
	}
	if !opt.From.IsZero() && !c.OldestRetained.IsZero() && opt.From.Before(c.OldestRetained) {
		c.RangeStartsBeforeRetention = true
	}

	c.Partial = c.FlowsEvicted > 0 ||
		c.ClassificationsEvicted > 0 ||
		c.ScanExhausted ||
		c.RangeStartsBeforeRetention ||
		c.HostsEvicted > 0 ||
		c.KeysPruned > 0 ||
		c.ObservationsDropped > 0 ||
		c.TimelineLate > 0 ||
		c.NotableFlowsTruncated ||
		c.FlowRecordsMissing > 0
	return c
}

// anomalyScored reports whether a flow-anomaly-v1 model scored any of the
// scanned verdicts.
func anomalyScored(scanned []storage.Classification) bool {
	for i := range scanned {
		if a := scanned[i].Result.Anomaly; a != nil && a.Available {
			return true
		}
	}
	return false
}

// notes turns Coverage into the prose a reader actually sees. The baseline note
// is unconditional (baselines are always Phase 7); the anomaly note fires only
// when nothing scored the traffic for novelty, so a report never looks like a
// clean anomaly result when none was computed.
func notes(c Coverage, sc Scope, models int) []Note {
	out := make([]Note, 0, 12)
	add := func(code, level, format string, args ...any) {
		out = append(out, Note{Code: code, Level: level, Text: fmt.Sprintf(format, args...)})
	}

	if !c.BaselineAvailable {
		add(NoteBaselineUnavailable, LevelWarning,
			"Behavioural baseline comparison is not available in this build (Phase 7, "+
				"PROJECT.md §19.4). This report contains no per-host baseline column.")
	}
	if !c.AnomalyAvailable {
		add(NoteAnomalyUnavailable, LevelWarning,
			"No anomaly model scored this traffic. This report carries no reconstruction "+
				"score, and the absence of an anomaly finding here does NOT mean the traffic "+
				"was checked for novelty and found normal (PROJECT.md §13, ADR 0037).")
	}
	add(NoteFeatureAttribution, LevelInfo,
		"The per-flow feature table is a fixed, documented subset of %s — the named raw "+
			"values this build's classifier reads — not a ranked per-flow attribution. "+
			"Model explanation and the baseline column are Phase 7 work.",
		schema.FlowFeaturesV1().Schema)

	if sc.Unbounded {
		add(NoteUnboundedWindow, LevelInfo,
			"No from/to was supplied, so the window is whatever the daemon still retains, "+
				"which is not the same as all recorded history.")
	}
	if c.FlowsEvicted > 0 || c.ClassificationsEvicted > 0 {
		add(NotePartialStoreEvicted, LevelWarning,
			"PARTIAL VIEW: the record store is a bounded ring that evicts. It has discarded "+
				"%d flow records and %d classifications over this daemon's lifetime "+
				"(retaining %d and %d, driver %q), so conversations from earlier in the "+
				"window may be absent entirely.",
			c.FlowsEvicted, c.ClassificationsEvicted, c.FlowsRetained, c.ClassificationsRetained, c.StoreDriver)
	}
	if c.ScanExhausted {
		add(NotePartialScanWindow, LevelWarning,
			"PARTIAL VIEW: report generation walks the newest %d stored verdicts and that "+
				"budget was filled, so in-scope verdicts older than %s were not considered.",
			c.ScanLimit, fmtTime(c.OldestRetained))
	}
	if c.RangeStartsBeforeRetention {
		add(NotePartialRetention, LevelWarning,
			"PARTIAL VIEW: the requested window starts at %s, before the oldest retained "+
				"verdict (%s). Everything earlier is gone from the store.",
			fmtTime(sc.From), fmtTime(c.OldestRetained))
	}
	if c.HostsEvicted > 0 {
		add(NotePartialHostsEvicted, LevelWarning,
			"PARTIAL VIEW: the host profile map is capped at %d addresses and has evicted "+
				"%d least-recently-active profiles. Aggregates for an evicted host restart "+
				"from zero if it is seen again.",
			c.HostCap, c.HostsEvicted)
	}
	if c.KeysPruned > 0 {
		add(NotePartialTopNPruned, LevelWarning,
			"PARTIAL VIEW: per-host top-N lists are capped at %d distinct ports and peers "+
				"and %d low-count keys have been pruned. Top ports and top peers are exact "+
				"for heavy hitters and incomplete for long tails (a port scan is exactly "+
				"such a tail). Per-host totals are unaffected and remain exact.",
			c.KeyCap, c.KeysPruned)
	}
	if c.ObservationsDropped > 0 {
		add(NotePartialObsDropped, LevelWarning,
			"PARTIAL VIEW: the aggregation queue is bounded and dropped %d observations "+
				"under load, so profile and timeline counters undercount by up to that much.",
			c.ObservationsDropped)
	}
	if c.TimelineLate > 0 {
		add(NotePartialTimelineLate, LevelWarning,
			"PARTIAL VIEW: %d verdicts arrived too late for their timeline bucket and are "+
				"missing from the series (they are still counted everywhere else).",
			c.TimelineLate)
	}
	if c.NotableFlowsTruncated {
		add(NoteFlowsTruncated, LevelWarning,
			"TRUNCATED: %d in-scope flows qualified as notable; this report lists the "+
				"highest-ranked %d (disagreements first, then descending confidence). "+
				"Narrow the window or add a class filter to see the rest.",
			c.NotableCandidates, c.NotableFlowCap)
	}
	if c.FlowRecordsMissing > 0 {
		add(NoteFlowRecordsMissing, LevelWarning,
			"PARTIAL VIEW: %d listed verdicts outlived their flow record in the bounded "+
				"store. Those rows carry the verdict but no timing, volume or feature "+
				"values; they are marked rather than shown as zeroes.",
			c.FlowRecordsMissing)
	}
	if models == 0 {
		add(NoteNoModels, LevelWarning,
			"No classifier was loaded when this report was generated, so no active model "+
				"set is recorded.")
	}
	if c.StoreDriver == "" {
		add(NoteNoStore, LevelWarning,
			"No record store was available, so flow records, verdicts and the notable-flow "+
				"table are empty for reasons unrelated to the traffic.")
	}
	if c.HostCap == 0 {
		add(NoteNoInsight, LevelWarning,
			"No aggregation index was available, so host profiles and the timeline are "+
				"empty for reasons unrelated to the traffic.")
	}
	return out
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "(none retained)"
	}
	return t.UTC().Format(time.RFC3339)
}

// ------------------------------------------------------------------ filenames

// Filename returns the download name for a report: stable, sortable, and safe
// to put in a Content-Disposition header. The scope segment is derived from
// packet-derived input, so it is reduced to [a-z0-9.-] rather than trusted
// (§28.11) — a crafted address can neither escape the quoted header value nor
// walk a path when the browser saves it.
func (r *Report) Filename(ext string) string {
	scope := "range"
	if r.Scope.Kind == ScopeHost {
		scope = "host-" + sanitize(r.Scope.Host)
	}
	ts := r.GeneratedAt.Format("20060102T150405Z")
	return fmt.Sprintf("synapseids-%s-%s.%s", scope, ts, sanitize(ext))
}

// sanitize reduces one segment to [a-z0-9._-]: lowercase alphanumerics pass
// through, everything else (including ':' in an IPv6 literal, and every quote,
// separator and control byte) collapses to '-'. Runs of '-' are collapsed and
// leading/trailing punctuation is trimmed, so no output can begin with a dot
// run — a saved file is then neither a traversal nor a dotfile, and the value
// cannot break out of the quoted Content-Disposition parameter.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for _, ch := range strings.ToLower(s) {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '.', ch == '_':
			b.WriteRune(ch)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if out == "" {
		return "unknown"
	}
	return out
}

// nonNil* keep the JSON arrays as [] rather than null when a profile's optional
// list is absent, so a consumer never has to special-case a missing key.
func nonNilPeers(v []insight.PeerCount) []insight.PeerCount {
	if v == nil {
		return []insight.PeerCount{}
	}
	return v
}

func nonNilPorts(v []insight.PortCount) []insight.PortCount {
	if v == nil {
		return []insight.PortCount{}
	}
	return v
}

func nonNilProtos(v []insight.ProtoCount) []insight.ProtoCount {
	if v == nil {
		return []insight.ProtoCount{}
	}
	return v
}
