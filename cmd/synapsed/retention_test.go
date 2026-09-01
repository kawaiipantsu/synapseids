package main

import (
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func retCfg(flows, cls, det, sweep time.Duration) config.Retention {
	return config.Retention{
		Flows:           config.Duration(flows),
		Classifications: config.Duration(cls),
		Detections:      config.Duration(det),
		SweepInterval:   config.Duration(sweep),
	}
}

func TestRetentionSweepPurgesEveryCategory(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := storage.NewMem(100, 100)
	al := alert.New(alert.DefaultPolicy(), alert.Options{})
	t.Cleanup(func() { _ = al.Close() })

	// Flows + classifications: half old, half fresh.
	for i := 0; i < 6; i++ {
		age := time.Duration(i) * time.Hour
		store.PutFlow(storage.FlowRecord{ID: uint64(i + 1), LastSeen: now.Add(-age), Features: features.Vector{}})
		store.PutClassification(storage.Classification{FlowID: uint64(i + 1), TS: now.Add(-age)})
	}
	// Detections: one old, one fresh.
	feedDet(al, "10.0.0.1", "8.8.8.8", now.Add(-5*time.Hour))
	feedDet(al, "10.0.0.2", "8.8.8.8", now.Add(-1*time.Hour))

	rs := &retentionSweeper{store: store, alerts: al, cfg: retCfg(3*time.Hour, 3*time.Hour, 3*time.Hour, time.Minute)}
	f, c, d := rs.sweep(now)

	if f != 2 || c != 2 { // ages 4h and 5h are strictly older than the 3h cutoff
		t.Errorf("flows/cls purged = %d/%d, want 2/2", f, c)
	}
	if d != 1 {
		t.Errorf("detections purged = %d, want 1", d)
	}
	if store.Stats().Flows != 4 || store.Stats().Classifications != 4 {
		t.Errorf("store after sweep: %+v", store.Stats())
	}
}

func TestRetentionSweepSkipsDisabledCategories(t *testing.T) {
	now := time.Now()
	store := storage.NewMem(10, 10)
	store.PutFlow(storage.FlowRecord{ID: 1, LastSeen: now.Add(-1000 * time.Hour), Features: features.Vector{}})
	rs := &retentionSweeper{store: store, cfg: retCfg(0, 0, 0, time.Minute)} // all off
	f, c, d := rs.sweep(now)
	if f != 0 || c != 0 || d != 0 {
		t.Errorf("a fully-disabled sweep purged %d/%d/%d", f, c, d)
	}
	if !rs.allDisabled() {
		t.Error("allDisabled() = false for an all-zero retention block")
	}
}

func TestRetentionSweepIntervalDefault(t *testing.T) {
	rs := &retentionSweeper{cfg: retCfg(time.Hour, 0, 0, 0)}
	if rs.interval() != 5*time.Minute {
		t.Errorf("interval() with sweep_interval=0 = %s, want 5m", rs.interval())
	}
	rs.cfg.SweepInterval = config.Duration(90 * time.Second)
	if rs.interval() != 90*time.Second {
		t.Errorf("interval() = %s, want 90s", rs.interval())
	}
}

func feedDet(al *alert.Store, src, dst string, ts time.Time) {
	cl := storage.Classification{
		TS: ts, Sensor: "t", Proto: "tcp",
		InitiatorIP: src, InitiatorPort: 40000, ResponderIP: dst, ResponderPort: 25,
	}
	cl.Result.Class = "scan"
	cl.Result.ClassID = 1
	cl.Result.Score = 0.95
	al.Observe(nil, &cl)
	al.Sync()
}
