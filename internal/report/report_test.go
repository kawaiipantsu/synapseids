package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// base is a fixed instant so every test is deterministic.
var base = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// fixture builds a synthetic store + insight index from a list of verdicts and
// returns Sources ready for Build. The index is Sync'd, so the aggregates are
// fully applied before any read.
type fixture struct {
	src Sources
}

type spec struct {
	flowID       uint64
	initiator    string
	responder    string
	rport        uint16
	proto        string
	class        string
	classID      int
	score        float64
	disagreement bool
	offsetSec    int
	// anomalyScore > 0 attaches an anomaly verdict to the classification.
	anomalyScore   float64
	anomalyExceeds bool
	// skipFlow omits the flow record, simulating a verdict whose record has
	// already been evicted from the bounded ring.
	skipFlow bool
}

func newFixture(t *testing.T, opt insight.Options, specs ...spec) fixture {
	t.Helper()
	store := storage.NewMem(4096, 4096)
	ix := insight.New(opt)
	t.Cleanup(func() { _ = ix.Close() })

	for _, s := range specs {
		ts := base.Add(time.Duration(s.offsetSec) * time.Second)
		fr := storage.FlowRecord{
			ID:            s.flowID,
			Proto:         s.proto,
			InitiatorIP:   s.initiator,
			InitiatorPort: 40000 + uint16(s.flowID%1000),
			ResponderIP:   s.responder,
			ResponderPort: s.rport,
			FirstSeen:     ts.Add(-time.Second),
			LastSeen:      ts,
			DurationSec:   1.0,
			FwdPackets:    3,
			BwdPackets:    1,
			FwdBytes:      180,
			BwdBytes:      60,
			CloseReason:   "fin",
			Features: features.Vector{
				FlowID: s.flowID,
				Schema: features.SchemaID,
			},
		}
		// Give the vector a couple of recognisable non-zero values so the
		// feature projection is observably real rather than all zeroes.
		for i := range fr.Features.Values {
			fr.Features.Values[i] = float64(i) + 0.5
		}
		cl := storage.Classification{
			FlowID:        s.flowID,
			TS:            ts,
			Sensor:        "test-sensor",
			Proto:         s.proto,
			InitiatorIP:   s.initiator,
			InitiatorPort: fr.InitiatorPort,
			ResponderIP:   s.responder,
			ResponderPort: s.rport,
			Result: inference.Result{
				FlowID:       s.flowID,
				Class:        s.class,
				ClassID:      s.classID,
				Score:        s.score,
				Disagreement: s.disagreement,
				Models: []inference.ModelOutput{{
					ModelID: "heuristic-v1", Role: inference.RolePrimary,
					Class: s.class, ClassID: s.classID, Score: s.score,
				}},
			},
		}
		if s.anomalyScore > 0 {
			cl.Result.Anomaly = &inference.AnomalyResult{
				Available: true, ModelID: "flow-anomaly-v1-test", Score: s.anomalyScore,
				ReconError: s.anomalyScore, Exceeds: s.anomalyExceeds,
			}
		}
		if !s.skipFlow {
			store.PutFlow(fr)
		}
		store.PutClassification(cl)
		ix.Observe(&fr, &cl)
	}
	ix.Sync()

	return fixture{src: Sources{
		Store:   store,
		Insight: ix,
		Runtime: inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary)),
	}}
}

func hostOpts(host string) Options {
	return Options{Scope: ScopeHost, Host: host, GeneratedAt: base, BucketSec: 1}
}

func rangeOpts() Options {
	return Options{Scope: ScopeRange, GeneratedAt: base, BucketSec: 1}
}

func mustBuild(t *testing.T, src Sources, opt Options) *Report {
	t.Helper()
	r, err := Build(src, opt)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return r
}

func noteCodes(r *Report) map[string]Note {
	out := make(map[string]Note, len(r.Notes))
	for _, n := range r.Notes {
		out[n.Code] = n
	}
	return out
}

// ------------------------------------------------------------------ scope

func TestHostScopeCountsAndProfile(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 3306, proto: "tcp", class: "brute_force", classID: 3, score: 0.91, offsetSec: 0},
		spec{flowID: 2, initiator: "10.10.10.22", responder: "10.10.10.21", rport: 22, proto: "tcp", class: "scan", classID: 1, score: 0.84, offsetSec: 1},
		spec{flowID: 3, initiator: "10.10.10.22", responder: "10.10.10.9", rport: 443, proto: "tcp", class: "normal", classID: 0, score: 0.97, offsetSec: 2},
		// A conversation that does not involve the subject at all.
		spec{flowID: 4, initiator: "10.10.10.5", responder: "10.10.10.6", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.7, offsetSec: 3},
	)

	r := mustBuild(t, f.src, hostOpts("10.10.10.22"))

	if r.Schema != SchemaID {
		t.Fatalf("schema = %q", r.Schema)
	}
	if r.Scope.Kind != ScopeHost || r.Scope.Host != "10.10.10.22" {
		t.Fatalf("scope = %+v", r.Scope)
	}
	if r.Host == nil || r.Host.IP != "10.10.10.22" {
		t.Fatalf("host profile missing: %+v", r.Host)
	}
	// Three of the four verdicts involve the subject; the fourth must not leak in.
	if r.Summary.Classifications != 3 {
		t.Fatalf("in-scope verdicts = %d, want 3", r.Summary.Classifications)
	}
	if r.Summary.NonNormal != 2 {
		t.Fatalf("non-normal = %d, want 2", r.Summary.NonNormal)
	}
	if r.Summary.DistinctFlows != 3 {
		t.Fatalf("distinct flows = %d, want 3", r.Summary.DistinctFlows)
	}

	// Class breakdown is in frozen schema order and shares sum to 1.
	var total float64
	last := -1
	for _, c := range r.Classes {
		if c.ClassID <= last {
			t.Fatalf("classes not in schema order: %+v", r.Classes)
		}
		last = c.ClassID
		total += c.Share
	}
	if total < 0.999 || total > 1.001 {
		t.Fatalf("class shares sum to %v", total)
	}

	// Notable flows: the two non-normal verdicts, highest confidence first.
	if len(r.NotableFlows) != 2 {
		t.Fatalf("notable flows = %d, want 2", len(r.NotableFlows))
	}
	if r.NotableFlows[0].FlowID != 1 || r.NotableFlows[1].FlowID != 2 {
		t.Fatalf("notable order = %d,%d, want 1,2", r.NotableFlows[0].FlowID, r.NotableFlows[1].FlowID)
	}
	nf := r.NotableFlows[0]
	if !nf.RecordAvailable {
		t.Fatal("flow record should have been resolved")
	}
	if len(nf.Features) != len(DecisionFeatures) {
		t.Fatalf("features = %d, want %d", len(nf.Features), len(DecisionFeatures))
	}
	if len(nf.Models) != 1 || nf.Models[0].ModelID != "heuristic-v1" {
		t.Fatalf("per-model outputs missing: %+v", nf.Models)
	}
	if len(nf.Reasons) != 1 || nf.Reasons[0] != ReasonNonNormal {
		t.Fatalf("reasons = %v", nf.Reasons)
	}

	// The active model set is stamped in.
	if len(r.Models) != 1 || r.Models[0].ID != "heuristic-v1" {
		t.Fatalf("models = %+v", r.Models)
	}
	// The build stamp carries a version and a commit.
	if r.Generator.Version == "" || r.Generator.Commit == "" {
		t.Fatalf("generator not stamped: %+v", r.Generator)
	}
	if !r.GeneratedAt.Equal(base) {
		t.Fatalf("generated_at = %v", r.GeneratedAt)
	}
}

func TestUnknownHostIsAnError(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.2", rport: 80, proto: "tcp", class: "normal", classID: 0, score: 0.9},
	)
	if _, err := Build(f.src, hostOpts("192.0.2.99")); err == nil {
		t.Fatal("want ErrUnknownHost")
	} else if err != ErrUnknownHost {
		t.Fatalf("err = %v, want ErrUnknownHost", err)
	}
}

func TestRangeScopeWindowAndAggregates(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8, offsetSec: 0},
		spec{flowID: 2, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.7, offsetSec: 10},
		spec{flowID: 3, initiator: "10.0.0.2", responder: "10.0.0.9", rport: 53, proto: "udp", class: "normal", classID: 0, score: 0.9, offsetSec: 100},
	)

	opt := rangeOpts()
	opt.From = base
	opt.To = base.Add(20 * time.Second)
	r := mustBuild(t, f.src, opt)

	if r.Scope.Kind != ScopeRange || r.Scope.Unbounded {
		t.Fatalf("scope = %+v", r.Scope)
	}
	if r.Summary.Classifications != 2 {
		t.Fatalf("in-window verdicts = %d, want 2 (the 100s one is outside)", r.Summary.Classifications)
	}
	if r.Host != nil {
		t.Fatal("a range report must not carry a host profile")
	}
	// Range aggregates come from the in-scope verdicts. Both 10.0.0.1 and
	// 10.0.0.9 appear in the two in-window conversations; the tie is broken by
	// address so the ordering is total.
	if len(r.TopPeers) != 2 {
		t.Fatalf("top peers = %+v", r.TopPeers)
	}
	if r.TopPeers[0].IP != "10.0.0.1" || r.TopPeers[0].Flows != 2 ||
		r.TopPeers[1].IP != "10.0.0.9" || r.TopPeers[1].Flows != 2 {
		t.Fatalf("top peers not tie-broken by address: %+v", r.TopPeers)
	}
	if len(r.TopPorts) == 0 || r.TopPorts[0].Port != 80 {
		t.Fatalf("top ports = %+v", r.TopPorts)
	}
	if len(r.Protocols) == 0 || r.Protocols[0].Proto != "tcp" {
		t.Fatalf("protocols = %+v", r.Protocols)
	}
	if r.Timeline.Source != TimelineFromRing {
		t.Fatalf("unfiltered range timeline should come from the ring, got %q", r.Timeline.Source)
	}
}

func TestRangeScopeAppliesTheCallerFilter(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8},
		spec{flowID: 2, initiator: "10.0.0.2", responder: "10.0.0.9", rport: 443, proto: "tcp", class: "normal", classID: 0, score: 0.95},
	)
	opt := rangeOpts()
	opt.FilterDesc = "class=scan"
	opt.Keep = func(c storage.Classification) bool { return c.Result.Class == "scan" }

	r := mustBuild(t, f.src, opt)
	if r.Summary.Classifications != 1 {
		t.Fatalf("filtered verdicts = %d, want 1", r.Summary.Classifications)
	}
	if r.Scope.Filter != "class=scan" {
		t.Fatalf("filter echo = %q", r.Scope.Filter)
	}
	// A filtered series cannot come from the global ring.
	if r.Timeline.Source != TimelineFromRetained {
		t.Fatalf("timeline source = %q", r.Timeline.Source)
	}
}

// ------------------------------------------------- notable-flow selection

func TestDisagreementsRankAboveConfidence(t *testing.T) {
	f := newFixture(t, insight.Options{},
		// Highest confidence, but no disagreement.
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.99, offsetSec: 0},
		// Low confidence, but the models disagreed — this must come first.
		spec{flowID: 2, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "suspicious", classID: 6, score: 0.31, disagreement: true, offsetSec: 1},
		// A disagreeing verdict that is nevertheless "normal": still notable.
		spec{flowID: 3, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "normal", classID: 0, score: 0.55, disagreement: true, offsetSec: 2},
		// Plain normal, no disagreement: not notable at all.
		spec{flowID: 4, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "normal", classID: 0, score: 0.98, offsetSec: 3},
	)
	r := mustBuild(t, f.src, rangeOpts())

	if len(r.NotableFlows) != 3 {
		t.Fatalf("notable flows = %d, want 3", len(r.NotableFlows))
	}
	got := []uint64{r.NotableFlows[0].FlowID, r.NotableFlows[1].FlowID, r.NotableFlows[2].FlowID}
	// Both disagreements first (higher score wins between them: 0.55 > 0.31),
	// then the non-normal verdict.
	want := []uint64{3, 2, 1}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("notable order = %v, want %v", got, want)
		}
	}
	if len(r.NotableFlows[1].Reasons) != 2 {
		t.Fatalf("a disagreeing non-normal verdict should carry both reasons: %v", r.NotableFlows[1].Reasons)
	}
}

func TestTruncationNoteAppearsWhenTheCapIsHit(t *testing.T) {
	specs := make([]spec, 0, 12)
	for i := 0; i < 12; i++ {
		specs = append(specs, spec{
			flowID: uint64(i + 1), initiator: "10.0.0.1", responder: "10.0.0.9",
			rport: 80, proto: "tcp", class: "scan", classID: 1,
			score: 0.5 + float64(i)/100, offsetSec: i,
		})
	}
	f := newFixture(t, insight.Options{}, specs...)

	opt := rangeOpts()
	opt.MaxFlows = 5
	r := mustBuild(t, f.src, opt)

	if len(r.NotableFlows) != 5 {
		t.Fatalf("listed flows = %d, want 5", len(r.NotableFlows))
	}
	if !r.Coverage.NotableFlowsTruncated {
		t.Fatal("coverage should report the notable-flow list as truncated")
	}
	if r.Coverage.NotableCandidates != 12 {
		t.Fatalf("candidates = %d, want 12", r.Coverage.NotableCandidates)
	}
	if !r.Coverage.Partial {
		t.Fatal("a truncated report is a partial view")
	}
	n, ok := noteCodes(r)[NoteFlowsTruncated]
	if !ok {
		t.Fatalf("missing %q note; got %v", NoteFlowsTruncated, r.Notes)
	}
	if !strings.Contains(n.Text, "12") || !strings.Contains(n.Text, "5") {
		t.Fatalf("truncation note should name both counts: %q", n.Text)
	}
	if n.Level != LevelWarning {
		t.Fatalf("truncation note level = %q", n.Level)
	}

	// Untruncated by default.
	r2 := mustBuild(t, f.src, rangeOpts())
	if r2.Coverage.NotableFlowsTruncated {
		t.Fatal("12 flows must not truncate under the 500 default")
	}
	if _, present := noteCodes(r2)[NoteFlowsTruncated]; present {
		t.Fatal("no truncation note when nothing was truncated")
	}
}

func TestDefaultFlowCapIs500AndIsClamped(t *testing.T) {
	if DefaultMaxFlows != 500 {
		t.Fatalf("documented flow cap changed: %d", DefaultMaxFlows)
	}
	o := Options{MaxFlows: 99999}.withDefaults()
	if o.MaxFlows != MaxFlowsCap {
		t.Fatalf("MaxFlows not clamped: %d", o.MaxFlows)
	}
	o = Options{}.withDefaults()
	if o.MaxFlows != DefaultMaxFlows || o.ScanLimit != DefaultScanLimit || o.BucketSec != DefaultBucketSec {
		t.Fatalf("defaults not applied: %+v", o)
	}
}

// ------------------------------------------------------------- honesty rules

func TestPhase7UnavailabilityNoteIsAlwaysPresent(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "normal", classID: 0, score: 0.9},
	)
	for _, opt := range []Options{hostOpts("10.0.0.1"), rangeOpts()} {
		r := mustBuild(t, f.src, opt)

		// The profile's own flags must still be false — if they ever become true
		// this test is the reminder to revisit the note.
		if r.Host != nil && (r.Host.BaselineAvailable || r.Host.AnomalyAvailable) {
			t.Fatal("insight now reports a baseline; the Phase 7 note needs revisiting")
		}
		if r.Coverage.BaselineAvailable || r.Coverage.AnomalyAvailable {
			t.Fatalf("coverage claims a baseline: %+v", r.Coverage)
		}
		base, ok := noteCodes(r)[NoteBaselineUnavailable]
		if !ok {
			t.Fatalf("%s scope: missing the baseline-unavailable note", opt.Scope)
		}
		if base.Level != LevelWarning || !strings.Contains(base.Text, "not available in this build") {
			t.Fatalf("baseline note wrong: %+v", base)
		}
		anom, ok := noteCodes(r)[NoteAnomalyUnavailable]
		if !ok {
			t.Fatalf("%s scope: missing the anomaly-unavailable note", opt.Scope)
		}
		if anom.Level != LevelWarning || !strings.Contains(anom.Text, "does NOT mean") {
			t.Fatalf("anomaly note should say %q: %+v", "does NOT mean", anom)
		}
		// The timeline carries the same statement rather than an empty series
		// that reads as "clean".
		if r.Timeline.AnomalyAvailable {
			t.Fatal("timeline claims an anomaly series")
		}
		// And the feature table is labelled as a fixed subset, not an attribution.
		if _, ok := noteCodes(r)[NoteFeatureAttribution]; !ok {
			t.Fatal("missing the feature-attribution caveat")
		}
	}
}

// When a flow-anomaly-v1 model scored the traffic, the report says so:
// Coverage.AnomalyAvailable is true, the timeline carries the anomaly series,
// and the "no anomaly model" warning is gone.
func TestReportReflectsActiveAnomalyModel(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp",
			class: "normal", classID: 0, score: 0.9, anomalyScore: 0.2},
		spec{flowID: 2, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp",
			class: "normal", classID: 0, score: 0.9, anomalyScore: 0.85, anomalyExceeds: true, offsetSec: 1},
	)
	r := mustBuild(t, f.src, rangeOpts())

	if !r.Coverage.AnomalyAvailable {
		t.Fatal("Coverage.AnomalyAvailable = false with anomaly-scored verdicts in scope")
	}
	if !r.Timeline.AnomalyAvailable {
		t.Fatal("timeline does not carry the anomaly series")
	}
	if _, ok := noteCodes(r)[NoteAnomalyUnavailable]; ok {
		t.Fatal("anomaly-unavailable note present while an anomaly model scored the traffic")
	}
	// The baseline is still Phase 7, so that note stays.
	if _, ok := noteCodes(r)[NoteBaselineUnavailable]; !ok {
		t.Fatal("baseline-unavailable note should still be present")
	}
}

func TestPartialViewNoteWhenStorageHasEvicted(t *testing.T) {
	// A ring of 2 classifications: putting 5 forces evictions.
	store := storage.NewMem(2, 2)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })
	for i := 0; i < 5; i++ {
		fr := storage.FlowRecord{ID: uint64(i + 1), Proto: "tcp", InitiatorIP: "10.0.0.1", ResponderIP: "10.0.0.9", LastSeen: base}
		cl := storage.Classification{
			FlowID: fr.ID, TS: base, Proto: "tcp", InitiatorIP: "10.0.0.1", ResponderIP: "10.0.0.9",
			Result: inference.Result{Class: "scan", ClassID: 1, Score: 0.8},
		}
		store.PutFlow(fr)
		store.PutClassification(cl)
		ix.Observe(&fr, &cl)
	}
	ix.Sync()
	src := Sources{Store: store, Insight: ix, Runtime: inference.NewRuntime()}

	r := mustBuild(t, src, rangeOpts())
	if r.Coverage.ClassificationsEvicted == 0 && r.Coverage.FlowsEvicted == 0 {
		t.Fatalf("expected eviction counters to be non-zero: %+v", r.Coverage)
	}
	if !r.Coverage.Partial {
		t.Fatal("eviction must make the report a partial view")
	}
	n, ok := noteCodes(r)[NotePartialStoreEvicted]
	if !ok {
		t.Fatalf("missing %q; notes = %v", NotePartialStoreEvicted, r.Notes)
	}
	if !strings.Contains(n.Text, "PARTIAL VIEW") {
		t.Fatalf("note should be explicit: %q", n.Text)
	}
	if !strings.Contains(n.Text, "bounded ring") {
		t.Fatalf("note should name the limit: %q", n.Text)
	}
}

func TestPartialViewNoteWhenInsightPrunedTopN(t *testing.T) {
	// A tiny key cap forces the per-host top-N prune that a port scan triggers.
	specs := make([]spec, 0, 40)
	for i := 0; i < 40; i++ {
		specs = append(specs, spec{
			flowID: uint64(i + 1), initiator: "10.10.10.22", responder: "10.10.10.21",
			rport: uint16(1000 + i), proto: "tcp", class: "scan", classID: 1,
			score: 0.8, offsetSec: i,
		})
	}
	f := newFixture(t, insight.Options{MaxKeys: 4}, specs...)

	r := mustBuild(t, f.src, hostOpts("10.10.10.22"))
	if r.Coverage.KeysPruned == 0 {
		t.Fatalf("expected keys_pruned > 0: %+v", r.Coverage)
	}
	if !r.Coverage.Partial {
		t.Fatal("a pruned top-N is a partial view")
	}
	n, ok := noteCodes(r)[NotePartialTopNPruned]
	if !ok {
		t.Fatalf("missing %q; notes = %v", NotePartialTopNPruned, r.Notes)
	}
	if !strings.Contains(n.Text, "PARTIAL VIEW") || !strings.Contains(n.Text, "4") {
		t.Fatalf("prune note should be explicit and name the cap: %q", n.Text)
	}
	// Per-host totals stay exact even when the top-N list was pruned; the note
	// says exactly that, so assert the claim holds.
	if r.Host.Flows != 40 {
		t.Fatalf("host flow total = %d, want 40 (totals must not be pruned)", r.Host.Flows)
	}
}

func TestPartialViewNoteWhenHostsWereEvicted(t *testing.T) {
	specs := make([]spec, 0, 24)
	for i := 0; i < 24; i++ {
		specs = append(specs, spec{
			flowID: uint64(i + 1), initiator: "10.0.0." + itoa(i+1), responder: "10.10.10.22",
			rport: 80, proto: "tcp", class: "normal", classID: 0, score: 0.9, offsetSec: i,
		})
	}
	f := newFixture(t, insight.Options{MaxHosts: 4}, specs...)

	r := mustBuild(t, f.src, rangeOpts())
	if r.Coverage.HostsEvicted == 0 {
		t.Fatalf("expected hosts_evicted > 0: %+v", r.Coverage)
	}
	n, ok := noteCodes(r)[NotePartialHostsEvicted]
	if !ok {
		t.Fatalf("missing %q; notes = %v", NotePartialHostsEvicted, r.Notes)
	}
	if !strings.Contains(n.Text, "PARTIAL VIEW") || !strings.Contains(n.Text, "4") {
		t.Fatalf("host-eviction note should name the cap: %q", n.Text)
	}
}

func TestScanBudgetExhaustionIsReported(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8, offsetSec: 0},
		spec{flowID: 2, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8, offsetSec: 1},
		spec{flowID: 3, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8, offsetSec: 2},
	)
	opt := rangeOpts()
	opt.ScanLimit = 2
	r := mustBuild(t, f.src, opt)

	if !r.Coverage.ScanExhausted || r.Coverage.ScanScanned != 2 {
		t.Fatalf("coverage = %+v", r.Coverage)
	}
	n, ok := noteCodes(r)[NotePartialScanWindow]
	if !ok {
		t.Fatalf("missing %q; notes = %v", NotePartialScanWindow, r.Notes)
	}
	if !strings.Contains(n.Text, "PARTIAL VIEW") {
		t.Fatalf("scan note should be explicit: %q", n.Text)
	}
}

func TestWindowBeforeRetentionIsReported(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8},
	)
	opt := rangeOpts()
	opt.From = base.Add(-24 * time.Hour)
	opt.To = base.Add(time.Hour)
	r := mustBuild(t, f.src, opt)

	if !r.Coverage.RangeStartsBeforeRetention {
		t.Fatalf("coverage = %+v", r.Coverage)
	}
	if _, ok := noteCodes(r)[NotePartialRetention]; !ok {
		t.Fatalf("missing %q; notes = %v", NotePartialRetention, r.Notes)
	}
}

func TestEvictedFlowRecordIsMarkedNotZeroed(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 7, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp",
			class: "scan", classID: 1, score: 0.8, skipFlow: true},
	)
	r := mustBuild(t, f.src, rangeOpts())
	if len(r.NotableFlows) != 1 {
		t.Fatalf("notable flows = %d", len(r.NotableFlows))
	}
	nf := r.NotableFlows[0]
	if nf.RecordAvailable {
		t.Fatal("record_available should be false when the flow record is gone")
	}
	if len(nf.Features) != 0 {
		t.Fatal("features must be empty, not a row of zeroes")
	}
	if r.Coverage.FlowRecordsMissing != 1 {
		t.Fatalf("flow_records_missing = %d", r.Coverage.FlowRecordsMissing)
	}
	if _, ok := noteCodes(r)[NoteFlowRecordsMissing]; !ok {
		t.Fatalf("missing %q; notes = %v", NoteFlowRecordsMissing, r.Notes)
	}
}

func TestCleanReportIsNotPartial(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 80, proto: "tcp", class: "scan", classID: 1, score: 0.8},
	)
	r := mustBuild(t, f.src, rangeOpts())
	if r.Coverage.Partial {
		t.Fatalf("nothing was evicted or truncated, yet partial=true: %+v", r.Coverage)
	}
	// The Phase 7 note is still there — that is a statement about the build, not
	// about coverage.
	if _, ok := noteCodes(r)[NoteBaselineUnavailable]; !ok {
		t.Fatal("Phase 7 note must be unconditional")
	}
}

func TestNilSourcesDegradeWithNotes(t *testing.T) {
	r, err := Build(Sources{}, rangeOpts())
	if err != nil {
		t.Fatalf("Build with empty sources: %v", err)
	}
	codes := noteCodes(r)
	for _, want := range []string{NoteNoStore, NoteNoInsight, NoteNoModels} {
		if _, ok := codes[want]; !ok {
			t.Fatalf("missing %q; notes = %v", want, r.Notes)
		}
	}
	if len(r.NotableFlows) != 0 || len(r.Classes) != 0 {
		t.Fatal("empty sources should produce empty sections")
	}
}

func TestUnknownScopeIsAnError(t *testing.T) {
	if _, err := Build(Sources{}, Options{Scope: "galaxy", GeneratedAt: base}); err == nil {
		t.Fatal("want an error for an unknown scope")
	}
}

// ------------------------------------------------------------- determinism

func TestDeterministicGivenTheSameState(t *testing.T) {
	specs := make([]spec, 0, 30)
	classes := []struct {
		name string
		id   int
	}{{"normal", 0}, {"scan", 1}, {"brute_force", 3}, {"suspicious", 6}}
	for i := 0; i < 30; i++ {
		c := classes[i%len(classes)]
		specs = append(specs, spec{
			flowID: uint64(i + 1), initiator: "10.10.10.22", responder: "10.10.10." + itoa(20+i%5),
			rport: uint16(1000 + i%7), proto: "tcp", class: c.name, classID: c.id,
			// Deliberately repeat scores so the tie-breakers are exercised.
			score: 0.5 + float64(i%3)/10, disagreement: i%7 == 0, offsetSec: i,
		})
	}
	f := newFixture(t, insight.Options{}, specs...)

	for _, opt := range []Options{hostOpts("10.10.10.22"), rangeOpts()} {
		var first []byte
		for i := 0; i < 5; i++ {
			r := mustBuild(t, f.src, opt)
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if i == 0 {
				first = b
				continue
			}
			if string(b) != string(first) {
				t.Fatalf("%s scope: build %d differs from build 0", opt.Scope, i)
			}
		}
		// And the HTML too.
		var firstHTML []byte
		for i := 0; i < 3; i++ {
			r := mustBuild(t, f.src, opt)
			h, err := r.HTML()
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			if i == 0 {
				firstHTML = h
				continue
			}
			if string(h) != string(firstHTML) {
				t.Fatalf("%s scope: HTML build %d differs", opt.Scope, i)
			}
		}
	}
}

func TestJSONRoundTrips(t *testing.T) {
	f := newFixture(t, insight.Options{},
		spec{flowID: 1, initiator: "10.0.0.1", responder: "10.0.0.9", rport: 3306, proto: "tcp", class: "brute_force", classID: 3, score: 0.88},
	)
	r := mustBuild(t, f.src, hostOpts("10.0.0.1"))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Schema != SchemaID || back.Scope.Host != "10.0.0.1" {
		t.Fatalf("round trip lost data: %+v", back.Scope)
	}
	// Empty collections must serialise as [] not null, so a consumer never has
	// to special-case a missing key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, k := range []string{"classes", "top_peers", "top_ports", "protocols", "models", "notable_flows", "notes", "feature_legend"} {
		v, ok := raw[k]
		if !ok {
			t.Fatalf("key %q missing", k)
		}
		if string(v) == "null" {
			t.Fatalf("key %q serialised as null", k)
		}
	}
}

// ------------------------------------------------------------------ filenames

func TestFilenameIsSanitised(t *testing.T) {
	cases := []struct {
		host string
		ext  string
		want string
	}{
		{"10.10.10.22", "json", "synapseids-host-10.10.10.22-20260831T120000Z.json"},
		{"fe80::1", "html", "synapseids-host-fe80-1-20260831T120000Z.html"},
		// A hostile "address" cannot escape the quoted header value or walk a
		// path when the browser writes the file: separators and quotes collapse
		// to '-', runs of '-' collapse, and the leading dot run is trimmed.
		{`../../etc/pa"sswd`, "html", "synapseids-host-etc-pa-sswd-20260831T120000Z.html"},
		{`..\..\windows`, "json", "synapseids-host-windows-20260831T120000Z.json"},
		{"a\r\nSet-Cookie: x", "html", "synapseids-host-a-set-cookie-x-20260831T120000Z.html"},
	}
	for _, c := range cases {
		r := &Report{GeneratedAt: base, Scope: Scope{Kind: ScopeHost, Host: c.host}}
		got := r.Filename(c.ext)
		if got != c.want {
			t.Fatalf("Filename(%q) = %q, want %q", c.host, got, c.want)
		}
		for _, bad := range []string{`"`, "/", "\\", ";", "\n", "\r"} {
			if strings.Contains(got, bad) {
				t.Fatalf("filename %q contains %q", got, bad)
			}
		}
	}
	r := &Report{GeneratedAt: base, Scope: Scope{Kind: ScopeRange}}
	if got := r.Filename("json"); got != "synapseids-range-20260831T120000Z.json" {
		t.Fatalf("range filename = %q", got)
	}
}

// ------------------------------------------------------------- feature subset

func TestDecisionFeaturesAreRealSchemaNamesInSchemaOrder(t *testing.T) {
	if len(DecisionFeatures) == 0 {
		t.Fatal("no decision features")
	}
	// orderedBySchema panics on an unknown name at init, so reaching here proves
	// every name exists. Assert the ordering contract as well.
	last := -1
	for _, n := range DecisionFeatures {
		idx := -1
		for i := 0; i < features.Size; i++ {
			if schema.FeatureName(i) == n {
				idx = i
				break
			}
		}
		if idx <= last {
			t.Fatalf("DecisionFeatures not in frozen schema order at %q", n)
		}
		last = idx
	}
	if len(featureLegend()) != len(DecisionFeatures) {
		t.Fatal("legend and feature list disagree")
	}
}

// itoa avoids pulling strconv into the fixtures for a one-liner.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
