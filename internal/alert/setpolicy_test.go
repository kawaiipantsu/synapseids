package alert_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/alert"
)

// TestSetPolicySwapsThresholdsLive: raising min_confidence on a running store
// takes effect on the next verdict, with no restart (config hot-reload, #59).
func TestSetPolicySwapsThresholdsLive(t *testing.T) {
	s, sub := newStore(t, alert.Options{})

	// 0.75 clears the default 0.70 floor -> a detection.
	feed(s, verdict(1, base, "10.0.0.5", "10.10.10.9", 22, "scan", 0.75, false))
	if got := s.Detections(alert.Query{Limit: 10}).Total; got != 1 {
		t.Fatalf("pre-reload: total = %d, want 1", got)
	}

	p := alert.DefaultPolicy()
	p.MinConfidence = 0.90
	s.SetPolicy(p)

	// Same shape, still 0.75 -> now below the floor, so no new detection and the
	// suppression counter for the threshold case ticks.
	feed(s, verdict(2, base, "10.0.0.6", "10.10.10.9", 22, "scan", 0.75, false))
	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("post-reload: total = %d, want still 1 (the new verdict is below the raised floor)", page.Total)
	}
	if st := s.Stats(); st.Suppressed == 0 {
		t.Error("a verdict below the raised threshold was not counted as suppressed")
	}
	// The first detection's event is still the only one.
	if got := countAlerts(sub); got != 1 {
		t.Errorf("AlertCreated fired %d times, want 1", got)
	}
}

// TestSetPolicySwapsSuppressionLive: adding an alerts.suppress rule on a running
// store suppresses the matching detection immediately, and the per-rule hit
// slice is resized to the new rule list.
func TestSetPolicySwapsSuppressionLive(t *testing.T) {
	s, _ := newStore(t, alert.Options{})

	feed(s, verdict(1, base, "203.0.113.7", "8.8.8.8", 25, "scan", 0.95, false))
	if s.Detections(alert.Query{Limit: 10}).Total != 1 {
		t.Fatal("pre-reload: expected the scan to alert")
	}

	rules, err := alert.CompileSuppress([]alert.SuppressSpec{
		{Src: "203.0.113.7", Class: "scan", Note: "edge box, authorised"},
	})
	if err != nil {
		t.Fatalf("CompileSuppress: %v", err)
	}
	p := alert.DefaultPolicy()
	p.Suppress = rules
	s.SetPolicy(p)

	feed(s, verdict(2, base, "203.0.113.7", "8.8.8.8", 1200, "scan", 0.99, false))

	st := s.Stats()
	if st.SuppressedByRule != 1 {
		t.Errorf("suppressed_by_rule = %d, want 1 after the rule was added live", st.SuppressedByRule)
	}
	if len(st.SuppressRules) != 1 || st.SuppressRules[0].Matched != 1 {
		t.Errorf("per-rule stats = %+v, want one rule matched once", st.SuppressRules)
	}
	if s.Detections(alert.Query{Limit: 10}).Total != 1 {
		t.Error("the second scan opened a detection despite the new suppress rule")
	}
}

// TestSetPolicyDisableLive: flipping alerts.enabled to false on a running store
// stops new detections.
func TestSetPolicyDisableLive(t *testing.T) {
	s, _ := newStore(t, alert.Options{})
	p := alert.DefaultPolicy()
	p.Enabled = false
	s.SetPolicy(p)

	feed(s, verdict(1, base, "10.0.0.5", "10.10.10.9", 3306, "brute_force", 0.99, false))
	if got := s.Detections(alert.Query{Limit: 10}).Total; got != 0 {
		t.Errorf("total = %d, want 0 with alerting disabled", got)
	}
	if s.Stats().Enabled {
		t.Error("Stats().Enabled still true after SetPolicy(disabled)")
	}
}

// TestSetPolicyOnNilAndClosedStore must not panic.
func TestSetPolicyOnNilAndClosedStore(t *testing.T) {
	var nilStore *alert.Store
	nilStore.SetPolicy(alert.DefaultPolicy())

	s, _ := newStore(t, alert.Options{})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s.SetPolicy(alert.DefaultPolicy()) // after Close: returns, no panic
}
