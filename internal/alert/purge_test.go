package alert_test

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
)

// TestPurgeBeforeDropsOldDetections: the retention sweep (issue #56) drops
// detections whose LastTS is older than the cutoff, counts them, and frees the
// dedup key so a later occurrence opens a fresh detection.
func TestPurgeBeforeDropsOldDetections(t *testing.T) {
	s, _ := newStore(t, alert.Options{})

	old := base                        // 2026-08-31 18:00
	recent := base.Add(48 * time.Hour) // two days later

	feed(s,
		verdict(1, old, "10.0.0.5", "10.10.10.9", 22, "scan", 0.95, false),
		verdict(2, recent, "10.0.0.6", "10.10.10.9", 3306, "brute_force", 0.99, false),
	)
	if s.Detections(alert.Query{Limit: 10}).Total != 2 {
		t.Fatalf("setup: want 2 detections")
	}

	s.PurgeBefore(base.Add(24 * time.Hour)) // keep only the last day

	page := s.Detections(alert.Query{Limit: 10})
	if page.Total != 1 || page.Detections[0].Class != "brute_force" {
		t.Fatalf("after purge: %+v, want just the recent brute_force", page.Detections)
	}
	st := s.Stats()
	if st.Expired != 1 {
		t.Errorf("Stats.Expired = %d, want 1", st.Expired)
	}
	if st.Retained != 1 {
		t.Errorf("Stats.Retained = %d, want 1", st.Retained)
	}

	// The purged detection's key is free: a new scan from the same source opens
	// a fresh detection rather than folding into the dead one.
	feed(s, verdict(3, recent.Add(time.Hour), "10.0.0.5", "10.10.10.9", 22, "scan", 0.95, false))
	if got := s.Detections(alert.Query{Class: "scan", Limit: 10}).Total; got != 1 {
		t.Errorf("scan detections = %d, want 1 fresh one", got)
	}
}

func TestPurgeBeforeNoOpAndSafety(t *testing.T) {
	var nilStore *alert.Store
	nilStore.PurgeBefore(time.Now()) // no panic

	s, _ := newStore(t, alert.Options{})
	feed(s, verdict(1, base, "10.0.0.5", "10.10.10.9", 22, "scan", 0.95, false))

	s.PurgeBefore(time.Time{}) // zero time: no-op
	if s.Stats().Expired != 0 || s.Detections(alert.Query{Limit: 10}).Total != 1 {
		t.Error("a zero-time PurgeBefore changed the store")
	}

	s.PurgeBefore(base.Add(-time.Hour)) // nothing that old
	if s.Stats().Expired != 0 {
		t.Error("purged something that was not old enough")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s.PurgeBefore(time.Now()) // after Close: returns, no panic
}
