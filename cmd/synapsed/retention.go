package main

import (
	"context"
	"log"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// retentionSweeper drops stored records older than their configured window
// (issue #56, PROJECT.md §20). It runs on its own goroutine on a ticker, off
// every hot path: a sweep takes the store's write lock only for the compaction,
// and the alert store does its purge on its own aggregator goroutine.
//
// A window of 0 for a category disables its sweep — that history stays bounded
// only by the ring capacity, which is the pre-#56 behaviour.
type retentionSweeper struct {
	store  storage.Store
	alerts *alert.Store
	cfg    config.Retention
}

// interval is the configured sweep cadence, or the 5m default.
func (rs *retentionSweeper) interval() time.Duration {
	if d := rs.cfg.SweepInterval.D(); d > 0 {
		return d
	}
	return 5 * time.Minute
}

func (rs *retentionSweeper) run(ctx context.Context) {
	if rs.allDisabled() {
		log.Printf("retention: every window is 0 — the sweep is disabled; history is bounded only by the ring sizes")
		return
	}
	log.Printf("retention: sweeping every %s (flows=%s classifications=%s detections=%s)",
		rs.interval(), windowLabel(rs.cfg.Flows.D()), windowLabel(rs.cfg.Classifications.D()), windowLabel(rs.cfg.Detections.D()))
	t := time.NewTicker(rs.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rs.sweep(now)
		}
	}
}

func (rs *retentionSweeper) allDisabled() bool {
	return rs.cfg.Flows.D() <= 0 && rs.cfg.Classifications.D() <= 0 && rs.cfg.Detections.D() <= 0
}

// sweep runs one pass. Separated from run so a test drives it directly.
func (rs *retentionSweeper) sweep(now time.Time) (flows, classifications, detections int) {
	var flowsBefore, classBefore time.Time
	if d := rs.cfg.Flows.D(); d > 0 {
		flowsBefore = now.Add(-d)
	}
	if d := rs.cfg.Classifications.D(); d > 0 {
		classBefore = now.Add(-d)
	}
	if p, ok := rs.store.(storage.Purger); ok && (!flowsBefore.IsZero() || !classBefore.IsZero()) {
		flows, classifications = p.PurgeBefore(flowsBefore, classBefore)
	}

	if d := rs.cfg.Detections.D(); d > 0 && rs.alerts != nil {
		before := rs.alerts.Stats().Expired
		rs.alerts.PurgeBefore(now.Add(-d))
		detections = int(rs.alerts.Stats().Expired - before)
	}

	if flows+classifications+detections > 0 {
		log.Printf("retention: purged %d flow(s), %d classification(s), %d detection(s)",
			flows, classifications, detections)
	}
	return flows, classifications, detections
}

func windowLabel(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	return d.String()
}
