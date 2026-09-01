package alert_test

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// base is a fixed instant so every window assertion is about the record clock,
// never about how long the test took to run.
var base = time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)

// verdict builds a classification the way the pipeline does: the tuple on the
// row, the ensemble result inside it.
func verdict(flowID uint64, ts time.Time, src, dst string, dport uint16, class string, score float64, disagree bool) storage.Classification {
	return storage.Classification{
		FlowID:        flowID,
		TS:            ts,
		Sensor:        "test",
		Proto:         "tcp",
		InitiatorIP:   src,
		InitiatorPort: 51234,
		ResponderIP:   dst,
		ResponderPort: dport,
		Result: inference.Result{
			FlowID:       flowID,
			Class:        class,
			Score:        score,
			Disagreement: disagree,
			Models: []inference.ModelOutput{{
				ModelID: "heuristic-v1", Role: inference.RolePrimary,
				Class: class, Score: score,
			}},
		},
	}
}

// feed pushes verdicts through Observe and waits for the aggregator.
func feed(s *alert.Store, cls ...storage.Classification) {
	for i := range cls {
		s.Observe(nil, &cls[i])
	}
	s.Sync()
}

// newStore starts a Store with the default policy and returns it plus a bus
// subscription, so a test can count AlertCreated events.
func newStore(t *testing.T, opt alert.Options) (*alert.Store, *events.Subscription) {
	t.Helper()
	bus := events.New()
	sub := bus.Subscribe(4096)
	opt.Bus = bus
	s := alert.New(alert.DefaultPolicy(), opt)
	t.Cleanup(func() {
		_ = s.Close()
		sub.Close()
	})
	return s, sub
}

// countAlerts drains sub and returns how many AlertCreated events it saw.
func countAlerts(sub *events.Subscription) int {
	n := 0
	for {
		select {
		case ev := <-sub.C:
			if ev.Type == events.AlertCreated {
				n++
			}
		default:
			return n
		}
	}
}

// TestNmapSweepCollapsesToOneDetection is the issue's headline requirement: a
// 1000-port sweep from one host against one host must not produce 1000
// detections, and must not produce 1000 bus events either (PROJECT.md §22).
func TestNmapSweepCollapsesToOneDetection(t *testing.T) {
	s, sub := newStore(t, alert.Options{})

	cls := make([]storage.Classification, 0, 1000)
	for i := 0; i < 1000; i++ {
		// One second apart in *record* time would exceed the 60s window, so the
		// sweep is paced the way nmap actually paces one: milliseconds apart.
		ts := base.Add(time.Duration(i) * 20 * time.Millisecond)
		cls = append(cls, verdict(uint64(i+1), ts, "10.0.0.66", "10.0.0.1", uint16(1+i), "scan", 0.9, false))
	}
	feed(s, cls...)

	page := s.Detections(alert.Query{Limit: 100})
	if page.Total != 1 {
		t.Fatalf("a 1000-port sweep produced %d detections, want 1: %+v", page.Total, page.Detections)
	}
	d := page.Detections[0]
	if d.Count != 1000 {
		t.Errorf("count = %d, want 1000 — every occurrence must still be counted", d.Count)
	}
	if d.Class != "scan" || d.Severity != alert.SeverityMedium {
		t.Errorf("class/severity = %q/%q, want scan/medium", d.Class, d.Severity)
	}
	if got := countAlerts(sub); got != 1 {
		t.Errorf("AlertCreated published %d times, want 1 — a dedup increment must publish nothing", got)
	}
	if st := s.Stats(); st.Created != 1 || st.Deduped != 999 {
		t.Errorf("stats created/deduped = %d/%d, want 1/999", st.Created, st.Deduped)
	}
}

// TestSweepFlowIDsCapped checks that the flow-id list stays a bounded summary
// while flow_id keeps pointing at the first occurrence.
func TestSweepFlowIDsCapped(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	for i := 0; i < 50; i++ {
		cl := verdict(uint64(100+i), base.Add(time.Duration(i)*time.Millisecond), "10.0.0.66", "10.0.0.1", uint16(1+i), "scan", 0.9, false)
		s.Observe(nil, &cl)
	}
	s.Sync()

	d := s.Detections(alert.Query{Limit: 10}).Detections[0]
	if len(d.FlowIDs) != alert.MaxFlowIDs {
		t.Fatalf("len(flow_ids) = %d, want %d", len(d.FlowIDs), alert.MaxFlowIDs)
	}
	if d.FlowID != 100 {
		t.Errorf("flow_id = %d, want the first occurrence 100", d.FlowID)
	}
	if d.FlowIDs[len(d.FlowIDs)-1] != 149 {
		t.Errorf("flow_ids ends at %d, want the most recent 149", d.FlowIDs[len(d.FlowIDs)-1])
	}
	if d.FlowIDs[0] != 130 {
		t.Errorf("flow_ids starts at %d, want 130 (the 20 most recent)", d.FlowIDs[0])
	}
}

// TestAlertCreatedOncePerNewDetection asserts the event contract across several
// distinct keys: one event per new detection, none for a repeat.
func TestAlertCreatedOncePerNewDetection(t *testing.T) {
	s, sub := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.98, false),
		verdict(2, base.Add(time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.99, false),   // dedup
		verdict(3, base.Add(2*time.Second), "10.0.0.6", "10.10.10.21", 3306, "brute_force", 0.98, false), // new src
		verdict(4, base.Add(3*time.Second), "10.0.0.5", "10.10.10.22", 3306, "brute_force", 0.98, false), // new dst
		verdict(5, base.Add(4*time.Second), "10.0.0.5", "10.10.10.21", 80, "web_attack", 0.98, false),    // new class
		verdict(6, base.Add(5*time.Second), "10.0.0.5", "10.10.10.21", 443, "normal", 0.99, false),       // never alerts
	)

	if got := countAlerts(sub); got != 4 {
		t.Errorf("AlertCreated published %d times, want 4", got)
	}
	page := s.Detections(alert.Query{Limit: 100})
	if page.Total != 4 {
		t.Fatalf("total = %d, want 4: %+v", page.Total, page.Detections)
	}
	if st := s.Stats(); st.Created != 4 || st.Deduped != 1 {
		t.Errorf("created/deduped = %d/%d, want 4/1", st.Created, st.Deduped)
	}
}

// TestAlertCreatedPayloadIsTheDetection checks the bus carries the detection
// itself, so a WebSocket client needs no second request to render it.
func TestAlertCreatedPayloadIsTheDetection(t *testing.T) {
	s, sub := newStore(t, alert.Options{})
	feed(s, verdict(4231, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.983, false))

	select {
	case ev := <-sub.C:
		if ev.Type != events.AlertCreated {
			t.Fatalf("first event is %q, want AlertCreated", ev.Type)
		}
		d, ok := ev.Data.(alert.Detection)
		if !ok {
			t.Fatalf("event data is %T, want alert.Detection", ev.Data)
		}
		if d.FlowID != 4231 || d.Class != "brute_force" || d.Severity != alert.SeverityHigh {
			t.Errorf("payload = %+v, want flow 4231 brute_force/high", d)
		}
		if d.Reason != "brute_force at 98.3% >= 70% threshold" {
			t.Errorf("reason = %q", d.Reason)
		}
		if len(d.Models) != 1 || d.Models[0].ModelID != "heuristic-v1" || d.Models[0].Confidence != 0.983 {
			t.Errorf("models = %+v, want one heuristic-v1 verdict at 0.983", d.Models)
		}
		if d.Models[0].Role != "primary" {
			t.Errorf("model role = %q, want primary", d.Models[0].Role)
		}
	default:
		t.Fatal("no AlertCreated event was published")
	}
}

// TestThresholdSuppression proves a below-threshold verdict raises nothing, and
// that the suppression is counted rather than silently discarded.
func TestThresholdSuppression(t *testing.T) {
	s, sub := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.69, false),
		verdict(2, base, "10.0.0.5", "10.10.10.21", 22, "scan", 0.6999, false),
		verdict(3, base, "10.0.0.9", "10.10.10.21", 443, "normal", 0.99, false),
	)
	if page := s.Detections(alert.Query{Limit: 10}); page.Total != 0 {
		t.Errorf("total = %d, want 0: %+v", page.Total, page.Detections)
	}
	if got := countAlerts(sub); got != 0 {
		t.Errorf("AlertCreated published %d times, want 0", got)
	}
	st := s.Stats()
	if st.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2 — `normal` is not a suppression, it is not alertable", st.Suppressed)
	}
	if st.Observed != 3 {
		t.Errorf("observed = %d, want 3", st.Observed)
	}

	// Exactly at the threshold alerts: the comparison is >=, as the reason string
	// it prints claims.
	feed(s, verdict(4, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.70, false))
	if page := s.Detections(alert.Query{Limit: 10}); page.Total != 1 {
		t.Errorf("a verdict exactly at min_confidence did not alert (total = %d)", page.Total)
	}
}

// TestPerClassThresholdOverride pins the documented default: `suspicious`, the
// supervised catch-all, needs 0.85 where everything else needs 0.70.
func TestPerClassThresholdOverride(t *testing.T) {
	p := alert.DefaultPolicy()
	if got := p.Threshold("suspicious"); got != 0.85 {
		t.Errorf("Threshold(suspicious) = %v, want 0.85", got)
	}
	if got := p.Threshold("scan"); got != alert.DefaultMinConfidence {
		t.Errorf("Threshold(scan) = %v, want the global %v", got, alert.DefaultMinConfidence)
	}

	s, _ := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "suspicious", 0.80, false), // below 0.85
		verdict(2, base, "10.0.0.5", "10.10.10.21", 3306, "scan", 0.80, false),       // above 0.70
	)
	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1 (only the scan): %+v", page.Total, page.Detections)
	}
	if page.Detections[0].Class != "scan" {
		t.Errorf("class = %q, want scan — the per-class override let `suspicious` at 0.80 through", page.Detections[0].Class)
	}
}

// TestAlertOnDisagreementBelowThreshold checks the §12 escape hatch: a
// disagreement is a finding even when confidence is low, and turning the knob
// off removes it.
func TestAlertOnDisagreementBelowThreshold(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s, verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.42, true))

	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1 — alert_on_disagreement should have raised it", page.Total)
	}
	d := page.Detections[0]
	if !d.Disagreement {
		t.Error("disagreement = false, want true")
	}
	if d.Reason != "model disagreement on brute_force at 42.0%, below the 70% threshold" {
		t.Errorf("reason = %q", d.Reason)
	}

	p := alert.DefaultPolicy()
	p.AlertOnDisagreement = false
	off := alert.New(p, alert.Options{})
	defer off.Close() //nolint:errcheck // always nil
	cl := verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.42, true)
	off.Observe(nil, &cl)
	off.Sync()
	if page := off.Detections(alert.Query{Limit: 10}); page.Total != 0 {
		t.Errorf("total = %d with alert_on_disagreement=false, want 0", page.Total)
	}
}

// TestDedupWindowExpiryOpensNewDetection: the window is anchored at the first
// occurrence, so sustained activity re-alerts once per window instead of going
// permanently quiet.
func TestDedupWindowExpiryOpensNewDetection(t *testing.T) {
	s, sub := newStore(t, alert.Options{DedupWindow: 60 * time.Second})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(2, base.Add(59*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(3, base.Add(61*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(4, base.Add(70*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
	)
	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 2 {
		t.Fatalf("total = %d, want 2 (one per 60s window): %+v", page.Total, page.Detections)
	}
	if got := countAlerts(sub); got != 2 {
		t.Errorf("AlertCreated published %d times, want 2", got)
	}
	// Most recently active first.
	if page.Detections[0].FlowID != 3 || page.Detections[1].FlowID != 1 {
		t.Errorf("order = flow %d then %d, want 3 then 1 (last_ts descending)",
			page.Detections[0].FlowID, page.Detections[1].FlowID)
	}
	if c := page.Detections[1].Count; c != 2 {
		t.Errorf("first window count = %d, want 2", c)
	}
}

// TestConfidenceIsMaxSeen: a detection reports the worst case it has seen, and
// the reason it prints comes from that same occurrence.
func TestConfidenceIsMaxSeen(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.75, false),
		verdict(2, base.Add(time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.983, false),
		verdict(3, base.Add(2*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.80, false),
	)
	d := s.Detections(alert.Query{Limit: 10}).Detections[0]
	if d.Confidence != 0.983 {
		t.Errorf("confidence = %v, want the max seen 0.983", d.Confidence)
	}
	if d.Reason != "brute_force at 98.3% >= 70% threshold" {
		t.Errorf("reason = %q, want the one belonging to the max-confidence occurrence", d.Reason)
	}
	if !d.TS.Equal(base) {
		t.Errorf("ts = %v, want the first occurrence %v", d.TS, base)
	}
	if !d.LastTS.Equal(base.Add(2 * time.Second)) {
		t.Errorf("last_ts = %v, want the most recent", d.LastTS)
	}
}

// TestFlowIDsAreDistinct: a long-lived flow contributes a snapshot verdict and a
// terminal one. Both count, but the flow is listed once.
func TestFlowIDsAreDistinct(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s,
		verdict(15, base, "10.10.10.22", "160.79.104.10", 443, "web_attack", 0.83, false),
		verdict(15, base.Add(time.Second), "10.10.10.22", "160.79.104.10", 443, "web_attack", 0.83, false),
		verdict(16, base.Add(2*time.Second), "10.10.10.22", "160.79.104.10", 443, "web_attack", 0.83, false),
	)
	d := s.Detections(alert.Query{Limit: 10}).Detections[0]
	if d.Count != 3 {
		t.Errorf("count = %d, want 3 — every verdict counts", d.Count)
	}
	if len(d.FlowIDs) != 2 || d.FlowIDs[0] != 15 || d.FlowIDs[1] != 16 {
		t.Errorf("flow_ids = %v, want [15 16] — a flow is listed once", d.FlowIDs)
	}
}

// TestDisagreementIsSticky: once any occurrence disagreed, the detection says so.
func TestDisagreementIsSticky(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(2, base.Add(time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, true),
		verdict(3, base.Add(2*time.Second), "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false),
	)
	if d := s.Detections(alert.Query{Limit: 10}).Detections[0]; !d.Disagreement {
		t.Error("disagreement = false, want true — a disagreement anywhere in the group must survive")
	}
}

// TestEvictionCounterAndOldestFirst mirrors storage.Mem's contract: the ring
// drops the oldest detection and counts it, and the count is reported on the
// page so a client knows it is looking at a window.
func TestEvictionCounterAndOldestFirst(t *testing.T) {
	s, _ := newStore(t, alert.Options{MaxRecent: 4})

	// Five distinct keys → five detections, one eviction.
	for i := 0; i < 5; i++ {
		cl := verdict(uint64(i+1), base.Add(time.Duration(i)*time.Second),
			"10.0.0.5", "10.10.10.2"+string(rune('0'+i)), 3306, "brute_force", 0.9, false)
		s.Observe(nil, &cl)
	}
	s.Sync()

	page := s.Detections(alert.Query{Limit: 100})
	if page.Total != 4 {
		t.Fatalf("total = %d, want 4 (max_recent): %+v", page.Total, page.Detections)
	}
	if page.Evicted != 1 {
		t.Errorf("page.evicted = %d, want 1", page.Evicted)
	}
	if st := s.Stats(); st.Evicted != 1 || st.Created != 5 || st.Retained != 4 {
		t.Errorf("stats evicted/created/retained = %d/%d/%d, want 1/5/4", st.Evicted, st.Created, st.Retained)
	}
	// Detection 1 was the oldest and is the one that went.
	if _, ok := s.Detection(1); ok {
		t.Error("detection 1 is still addressable after eviction")
	}
	for id := uint64(2); id <= 5; id++ {
		if _, ok := s.Detection(id); !ok {
			t.Errorf("detection %d is missing", id)
		}
	}
}

// TestEvictedKeyCanAlertAgain: dropping a detection must also drop its dedup
// entry, otherwise an evicted key could never alert again.
func TestEvictedKeyCanAlertAgain(t *testing.T) {
	s, _ := newStore(t, alert.Options{MaxRecent: 2})
	feed(s,
		verdict(1, base, "10.0.0.1", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(2, base, "10.0.0.2", "10.10.10.21", 3306, "brute_force", 0.9, false),
		verdict(3, base, "10.0.0.3", "10.10.10.21", 3306, "brute_force", 0.9, false), // evicts #1
		verdict(4, base.Add(time.Second), "10.0.0.1", "10.10.10.21", 3306, "brute_force", 0.9, false),
	)
	st := s.Stats()
	if st.Created != 4 {
		t.Errorf("created = %d, want 4 — the evicted key must be able to alert again", st.Created)
	}
	if st.Deduped != 0 {
		t.Errorf("deduped = %d, want 0", st.Deduped)
	}
}

// TestFilters exercises every query predicate the REST route exposes.
func TestFilters(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s,
		verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.98, false),             // high
		verdict(2, base.Add(time.Minute), "10.0.0.6", "10.10.10.1", 80, "scan", 0.75, false),      // medium
		verdict(3, base.Add(2*time.Minute), "10.0.0.7", "10.10.10.2", 53, "dos_ddos", 0.9, false), // critical
	)

	cases := []struct {
		name string
		q    alert.Query
		want []string // classes, most recently active first
	}{
		{"unfiltered", alert.Query{Limit: 100}, []string{"dos_ddos", "scan", "brute_force"}},
		{"class", alert.Query{Limit: 100, Class: "scan"}, []string{"scan"}},
		{"severity", alert.Query{Limit: 100, Severity: alert.SeverityCritical}, []string{"dos_ddos"}},
		{"severity none match", alert.Query{Limit: 100, Severity: alert.SeverityLow}, nil},
		{"min_confidence", alert.Query{Limit: 100, MinConfidence: 0.9, HasMinConfidence: true}, []string{"dos_ddos", "brute_force"}},
		{"since", alert.Query{Limit: 100, Since: base.Add(90 * time.Second)}, []string{"dos_ddos"}},
		{"limit", alert.Query{Limit: 1}, []string{"dos_ddos"}},
		{"class+severity conflict", alert.Query{Limit: 100, Class: "scan", Severity: alert.SeverityHigh}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := s.Detections(tc.q)
			got := make([]string, 0, len(page.Detections))
			for _, d := range page.Detections {
				got = append(got, d.Class)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("classes = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("classes = %v, want %v", got, tc.want)
				}
			}
			if page.Returned != len(page.Detections) {
				t.Errorf("returned = %d, len = %d", page.Returned, len(page.Detections))
			}
		})
	}

	// limit=1 must not lie about how many matched.
	if page := s.Detections(alert.Query{Limit: 1}); page.Total != 3 || page.Returned != 1 {
		t.Errorf("total/returned = %d/%d, want 3/1", page.Total, page.Returned)
	}
}

// TestDetectionByIDReturnsACopy: a handler must not be able to see the
// aggregator mutate a detection underneath it, and must not be able to mutate
// the store's copy.
func TestDetectionByIDReturnsACopy(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	feed(s, verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false))

	d, ok := s.Detection(1)
	if !ok {
		t.Fatal("detection 1 not found")
	}
	d.FlowIDs[0] = 999
	d.Models[0].ModelID = "tampered"

	again, _ := s.Detection(1)
	if again.FlowIDs[0] != 1 || again.Models[0].ModelID != "heuristic-v1" {
		t.Errorf("the store handed out its own slices: %+v", again)
	}
	if _, ok := s.Detection(9999); ok {
		t.Error("an unknown id was found")
	}
}

// TestDisabledPolicyStillReportsCounters: alerting off must be visible as "off",
// not as "quiet".
func TestDisabledPolicyStillReportsCounters(t *testing.T) {
	s := alert.New(alert.Policy{}, alert.Options{})
	defer s.Close() //nolint:errcheck // always nil
	cl := verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.99, false)
	s.Observe(nil, &cl)
	s.Sync()

	st := s.Stats()
	if st.Enabled {
		t.Error("stats.enabled = true for a zero policy")
	}
	if st.Created != 0 || st.Suppressed != 0 {
		t.Errorf("created/suppressed = %d/%d, want 0/0 — a disabled policy suppresses nothing, it evaluates nothing", st.Created, st.Suppressed)
	}
	if st.Observed != 1 {
		t.Errorf("observed = %d, want 1", st.Observed)
	}
	if page := s.Detections(alert.Query{Limit: 10}); page.Total != 0 {
		t.Errorf("total = %d, want 0", page.Total)
	}
}

// TestNilStoreIsSafe: every read is nil-receiver safe so the API and the daemon
// can run without an alert store (the #116 typed-nil lesson).
func TestNilStoreIsSafe(t *testing.T) {
	var s *alert.Store
	cl := verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.99, false)
	s.Observe(nil, &cl)
	s.Sync()
	if err := s.Close(); err != nil {
		t.Errorf("Close on a nil store: %v", err)
	}
	page := s.Detections(alert.Query{Limit: 10})
	if page.Detections == nil {
		t.Error("a nil store returned a nil slice — the JSON must be [] not null")
	}
	if page.Total != 0 || page.Returned != 0 {
		t.Errorf("page = %+v, want zeroes", page)
	}
	if _, ok := s.Detection(1); ok {
		t.Error("a nil store found a detection")
	}
	if st := s.Stats(); (st.Observed|st.Created|st.Deduped|st.Suppressed|
		st.SuppressedByRule|st.Evicted|st.Dropped) != 0 ||
		st.Enabled || st.Retained != 0 || st.SuppressRules != nil {
		t.Errorf("Stats = %+v, want the zero value", st)
	}
}

// TestDetectionsIsNeverNil pins the JSON contract: an empty feed serialises as
// [], never null.
func TestDetectionsIsNeverNil(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	if page := s.Detections(alert.Query{Limit: 10}); page.Detections == nil {
		t.Error("Detections = nil on an empty store")
	}
}

// TestObserveDoesNotAllocate pins the packet-path cost: Observe must project and
// enqueue without allocating, exactly like insight.Observe (PROJECT.md §22).
func TestObserveDoesNotAllocate(t *testing.T) {
	// A queue nothing drains, so the measurement is Observe's own cost and not
	// the aggregator's.
	s := alert.New(alert.DefaultPolicy(), alert.Options{QueueSize: 1 << 20})
	defer s.Close() //nolint:errcheck // always nil
	cl := verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false)

	if n := testing.AllocsPerRun(200, func() { s.Observe(nil, &cl) }); n != 0 {
		t.Errorf("Observe allocated %.1f times per call, want 0", n)
	}
}

// TestQueueFullDropsAndCounts: a store whose aggregator is stopped must drop and
// count rather than block the packet path.
func TestQueueFullDropsAndCounts(t *testing.T) {
	s := alert.New(alert.DefaultPolicy(), alert.Options{QueueSize: 1})
	_ = s.Close() // stop the aggregator so nothing drains

	cl := verdict(1, base, "10.0.0.5", "10.10.10.21", 3306, "brute_force", 0.9, false)
	for i := 0; i < 10; i++ {
		s.Observe(nil, &cl) // must not block
	}
	if st := s.Stats(); st.Dropped == 0 {
		t.Error("dropped = 0, want > 0 — a full queue must count the loss (PROJECT.md §24)")
	}
}

// TestObserveFallsBackToTheFlowRecord covers the defensive path for a verdict
// that arrives without its tuple.
func TestObserveFallsBackToTheFlowRecord(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	cl := storage.Classification{
		FlowID: 7,
		Result: inference.Result{Class: "brute_force", Score: 0.9},
	}
	fr := storage.FlowRecord{
		ID: 7, Proto: "tcp",
		InitiatorIP: "10.0.0.5", InitiatorPort: 4444,
		ResponderIP: "10.10.10.21", ResponderPort: 3306,
		LastSeen: base,
	}
	s.Observe(&fr, &cl)
	s.Sync()

	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1", page.Total)
	}
	d := page.Detections[0]
	if d.SrcIP != "10.0.0.5" || d.DstIP != "10.10.10.21" || d.DstPort != 3306 || d.Protocol != "tcp" {
		t.Errorf("tuple = %+v, want it filled from the flow record", d)
	}
	if !d.TS.Equal(base) {
		t.Errorf("ts = %v, want the record's last_seen %v", d.TS, base)
	}
}
