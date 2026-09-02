package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionDefaults(t *testing.T) {
	r := Default().Retention
	if r.Flows.D() != 30*24*time.Hour || r.Classifications.D() != 90*24*time.Hour {
		t.Errorf("retention windows = %+v", r)
	}
	if r.Detections.D() != 30*24*time.Hour {
		t.Errorf("detections window = %s, want 720h", r.Detections.D())
	}
	if r.SweepInterval.D() != 5*time.Minute {
		t.Errorf("sweep_interval = %s, want 5m", r.SweepInterval.D())
	}
	if err := ValidateRetention(r); err != nil {
		t.Errorf("default retention does not validate: %v", err)
	}
}

func TestRetentionLoadFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"retention":{
		"flows": "24h", "classifications": "0", "detections": "168h",
		"sweep_interval": "30s"
	}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	r := c.Retention
	if r.Flows.D() != 24*time.Hour || r.Classifications.D() != 0 || r.Detections.D() != 168*time.Hour {
		t.Errorf("retention not parsed: %+v", r)
	}
	if r.SweepInterval.D() != 30*time.Second {
		t.Errorf("sweep_interval = %s", r.SweepInterval.D())
	}
}

func TestRetentionValidationRejectsNonsense(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"negative-flows":  `{"retention":{"flows":"-1h"}}`,
		"negative-sweep":  `{"retention":{"sweep_interval":"-5s"}}`,
		"sweep-too-small": `{"retention":{"sweep_interval":"500ms"}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// A window of 0 is allowed — it means "keep until the ring evicts it".
func TestRetentionZeroWindowIsValid(t *testing.T) {
	if err := ValidateRetention(Retention{Flows: 0, Classifications: 0, Detections: 0, SweepInterval: Duration(time.Minute)}); err != nil {
		t.Errorf("all-zero windows rejected: %v", err)
	}
}
