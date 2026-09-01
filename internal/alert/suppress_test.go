package alert_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// suppressStore starts a Store whose policy is the default thresholds plus the
// given compiled suppression rules, and returns it with a bus subscription.
func suppressStore(t *testing.T, specs ...alert.SuppressSpec) (*alert.Store, *events.Subscription) {
	t.Helper()
	rules, err := alert.CompileSuppress(specs)
	if err != nil {
		t.Fatalf("CompileSuppress: %v", err)
	}
	pol := alert.DefaultPolicy()
	pol.Suppress = rules

	bus := events.New()
	sub := bus.Subscribe(4096)
	s := alert.New(pol, alert.Options{Bus: bus})
	t.Cleanup(func() {
		_ = s.Close()
		sub.Close()
	})
	return s, sub
}

// TestSuppressionKeepsClassificationDropsDetection is the issue's core
// requirement: a verdict that clears its threshold but matches an
// expected-behaviour rule raises no detection and no event, but the suppression
// is counted — per rule — so it is auditable and a dead rule is visible.
func TestSuppressionKeepsClassificationDropsDetection(t *testing.T) {
	// The gateway's own edge address does authorised scanning all day.
	s, sub := suppressStore(t, alert.SuppressSpec{
		Src: "203.0.113.7", Class: "scan", Note: "edge box runs authorised recon",
	})

	feed(s,
		verdict(1, base, "203.0.113.7", "198.51.100.9", 25, "scan", 0.95, false),   // suppressed
		verdict(2, base, "203.0.113.7", "198.51.100.9", 1200, "scan", 0.99, false), // suppressed, same rule
		verdict(3, base, "10.0.0.66", "10.0.0.1", 22, "scan", 0.95, false),         // NOT from the edge box: alerts
	)

	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1 (only the un-suppressed scan): %+v", page.Total, page.Detections)
	}
	if page.Detections[0].SrcIP != "10.0.0.66" {
		t.Errorf("the surviving detection is from %s, want 10.0.0.66", page.Detections[0].SrcIP)
	}
	if got := countAlerts(sub); got != 1 {
		t.Errorf("AlertCreated published %d times, want 1", got)
	}

	st := s.Stats()
	if st.SuppressedByRule != 2 {
		t.Errorf("suppressed_by_rule = %d, want 2", st.SuppressedByRule)
	}
	if st.Suppressed != 0 {
		t.Errorf("suppressed (threshold) = %d, want 0 — these cleared their threshold", st.Suppressed)
	}
	if len(st.SuppressRules) != 1 || st.SuppressRules[0].Matched != 2 {
		t.Errorf("per-rule stats = %+v, want one rule with matched=2", st.SuppressRules)
	}
	if st.SuppressRules[0].Note != "edge box runs authorised recon" {
		t.Errorf("per-rule note = %q", st.SuppressRules[0].Note)
	}
	// The classifications themselves are the pipeline's to store; suppression
	// never touched Observe's inputs. Observed counts every verdict it saw.
	if st.Observed != 3 {
		t.Errorf("observed = %d, want 3 — suppression must not hide the verdict from the counters", st.Observed)
	}
}

// TestSuppressionMatchDimensions exercises each matcher and its misses.
func TestSuppressionMatchDimensions(t *testing.T) {
	cases := []struct {
		name       string
		spec       alert.SuppressSpec
		src, dst   string
		dport      uint16
		class      string
		suppressed bool
	}{
		{"src /32 hit", alert.SuppressSpec{Src: "203.0.113.7", Note: "n"}, "203.0.113.7", "8.8.8.8", 53, "scan", true},
		{"src /24 hit", alert.SuppressSpec{Src: "203.0.113.0/24", Note: "n"}, "203.0.113.44", "8.8.8.8", 53, "scan", true},
		{"src prefix miss", alert.SuppressSpec{Src: "203.0.113.0/24", Note: "n"}, "203.0.114.1", "8.8.8.8", 53, "scan", false},
		{"dst CIDR hit", alert.SuppressSpec{Dst: "198.51.100.0/24", Note: "n"}, "10.0.0.1", "198.51.100.30", 443, "botnet_c2", true},
		{"dst_port hit", alert.SuppressSpec{DstPort: 1677, Note: "n"}, "10.0.0.1", "8.8.8.8", 1677, "scan", true},
		{"dst_port miss", alert.SuppressSpec{DstPort: 1677, Note: "n"}, "10.0.0.1", "8.8.8.8", 1678, "scan", false},
		{"class-only hit", alert.SuppressSpec{Class: "botnet_c2", Note: "n"}, "10.0.0.1", "8.8.8.8", 6667, "botnet_c2", true},
		{"class miss", alert.SuppressSpec{Class: "botnet_c2", Note: "n"}, "10.0.0.1", "8.8.8.8", 6667, "scan", false},
		{"combined all hit", alert.SuppressSpec{Src: "203.0.113.0/24", DstPort: 25, Class: "scan", Note: "n"}, "203.0.113.9", "8.8.8.8", 25, "scan", true},
		{"combined one miss", alert.SuppressSpec{Src: "203.0.113.0/24", DstPort: 25, Class: "scan", Note: "n"}, "203.0.113.9", "8.8.8.8", 26, "scan", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, sub := suppressStore(t, tc.spec)
			cl := verdict(1, base, tc.src, tc.dst, tc.dport, tc.class, 0.97, false)
			feed(s, cl)

			total := s.Detections(alert.Query{Limit: 10}).Total
			if tc.suppressed && total != 0 {
				t.Errorf("expected suppression, got %d detection(s)", total)
			}
			if !tc.suppressed && total != 1 {
				t.Errorf("expected an alert, got %d detection(s)", total)
			}
			if got := countAlerts(sub); (got == 0) != tc.suppressed {
				t.Errorf("AlertCreated count = %d with suppressed=%v", got, tc.suppressed)
			}
			if got := s.Stats().SuppressRules[0].Matched; (got == 1) != tc.suppressed {
				t.Errorf("per-rule matched = %d with suppressed=%v", got, tc.suppressed)
			}
		})
	}
}

// TestSuppressionFirstMatchWinsAndDeadRuleIsVisible: rules are evaluated in
// order, the count is attributed to the first match, and a rule that never
// matches reports matched=0 so an operator can find and remove it.
func TestSuppressionFirstMatchWinsAndDeadRuleIsVisible(t *testing.T) {
	s, _ := suppressStore(t,
		alert.SuppressSpec{Class: "scan", Note: "all scans from research VLAN are expected"},
		alert.SuppressSpec{Src: "203.0.113.7", Note: "never actually hit in this test"},
	)
	feed(s, verdict(1, base, "203.0.113.7", "8.8.8.8", 25, "scan", 0.95, false))

	st := s.Stats()
	if st.SuppressedByRule != 1 {
		t.Fatalf("suppressed_by_rule = %d, want 1", st.SuppressedByRule)
	}
	if st.SuppressRules[0].Matched != 1 {
		t.Errorf("rule 0 matched = %d, want 1 (first match wins)", st.SuppressRules[0].Matched)
	}
	if st.SuppressRules[1].Matched != 0 {
		t.Errorf("rule 1 matched = %d, want 0 — a dead rule must be visible as such", st.SuppressRules[1].Matched)
	}
}

// TestSuppressionDoesNotTouchBelowThresholdCounter: a verdict that never cleared
// its threshold is a threshold suppression, not a rule suppression, even if a
// rule would also have matched it.
func TestSuppressionBelowThresholdIsNotRuleSuppression(t *testing.T) {
	s, _ := suppressStore(t, alert.SuppressSpec{Class: "scan", Note: "expected"})
	feed(s, verdict(1, base, "10.0.0.1", "8.8.8.8", 22, "scan", 0.40, false))

	st := s.Stats()
	if st.Suppressed != 1 {
		t.Errorf("suppressed (threshold) = %d, want 1", st.Suppressed)
	}
	if st.SuppressedByRule != 0 {
		t.Errorf("suppressed_by_rule = %d, want 0 — it never cleared the threshold", st.SuppressedByRule)
	}
}

// TestCompileSuppressRejectsBadRules pins the load-time refusals: a rule must be
// well-formed and must actually do something.
func TestCompileSuppressRejectsBadRules(t *testing.T) {
	bad := []struct {
		name string
		spec alert.SuppressSpec
	}{
		{"no matchers", alert.SuppressSpec{Note: "n"}},
		{"no note", alert.SuppressSpec{Class: "scan"}},
		{"blank note", alert.SuppressSpec{Class: "scan", Note: "   "}},
		{"bad src", alert.SuppressSpec{Src: "not-an-ip", Note: "n"}},
		{"bad dst cidr", alert.SuppressSpec{Dst: "10.0.0.0/33", Note: "n"}},
		{"unknown class", alert.SuppressSpec{Class: "nonsense", Note: "n"}},
		{"normal class", alert.SuppressSpec{Class: "normal", Note: "n"}},
		{"port too high", alert.SuppressSpec{DstPort: 70000, Note: "n"}},
		{"port negative", alert.SuppressSpec{DstPort: -1, Note: "n"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := alert.CompileSuppress([]alert.SuppressSpec{tc.spec}); err == nil {
				t.Errorf("CompileSuppress accepted a bad rule (%s)", tc.name)
			}
		})
	}

	good := alert.SuppressSpec{Src: "203.0.113.0/24", DstPort: 443, Class: "botnet_c2", Note: "CDN health checks"}
	if _, err := alert.CompileSuppress([]alert.SuppressSpec{good}); err != nil {
		t.Errorf("CompileSuppress rejected a valid rule: %v", err)
	}
}

// TestSuppressRuleParsingMatchesConfig is the drift guard between config's
// load-time validation and alert's compiler: the same rule must be accepted or
// rejected by both, or a config that loads could still drop a rule (or vice
// versa) — exactly the silent behaviour issue #133 forbids.
func TestSuppressRuleParsingMatchesConfig(t *testing.T) {
	rules := []config.SuppressRule{
		{Src: "203.0.113.7", Class: "scan", Note: "ok"},
		{Dst: "198.51.100.0/24", DstPort: 443, Note: "ok"},
		{DstPort: 1677, Note: "ok"},
		{Note: "no matchers"},
		{Class: "scan"},
		{Src: "garbage", Note: "ok"},
		{Dst: "10/8", Note: "ok"},
		{Class: "normal", Note: "ok"},
		{DstPort: 99999, Note: "ok"},
		{Class: "web_attack", Src: "2001:db8::/32", Note: "ok"},
	}
	for i, r := range rules {
		a := config.Default().Alerts
		a.Suppress = []config.SuppressRule{r}
		cfgErr := config.ValidateAlerts(a) != nil

		_, err := alert.CompileSuppress([]alert.SuppressSpec{{
			Src: r.Src, Dst: r.Dst, DstPort: r.DstPort, Class: r.Class, Note: r.Note,
		}})
		alertErr := err != nil

		if cfgErr != alertErr {
			t.Errorf("rule %d %+v: config rejects=%v, alert rejects=%v — the two parsers have drifted", i, r, cfgErr, alertErr)
		}
	}
}

// TestSuppressionSurvivesStoreClose is a smoke test that the extra slice does
// not upset the nil-store and Close paths.
func TestSuppressionNilAndClose(t *testing.T) {
	s, _ := suppressStore(t, alert.SuppressSpec{Class: "scan", Note: "n"})
	cl := verdict(1, base, "10.0.0.1", "8.8.8.8", 22, "scan", 0.95, false)
	s.Observe(nil, &cl)
	s.Sync()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close and a post-Close Observe are counted drops, not panics.
	_ = s.Close()
	s.Observe(nil, &storage.Classification{})
}
