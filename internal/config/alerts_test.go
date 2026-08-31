package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestAlertsDefaults pins the documented defaults of the alerts block. They are
// quoted in docs/api.md and contrib/config/synapse.json, so a change here is a
// documentation change too.
func TestAlertsDefaults(t *testing.T) {
	a := Default().Alerts
	if !a.Enabled {
		t.Error("alerts.enabled default = false, want true")
	}
	if a.MinConfidence != 0.70 {
		t.Errorf("alerts.min_confidence default = %v, want 0.70", a.MinConfidence)
	}
	if got := a.PerClassMinConfidence["suspicious"]; got != 0.85 {
		t.Errorf("alerts.per_class_min_confidence[suspicious] default = %v, want 0.85", got)
	}
	if len(a.PerClassMinConfidence) != 1 {
		t.Errorf("default per_class_min_confidence = %v, want exactly the suspicious override", a.PerClassMinConfidence)
	}
	if !a.AlertOnDisagreement {
		t.Error("alerts.alert_on_disagreement default = false, want true")
	}
	if a.MaxRecent != 1000 {
		t.Errorf("alerts.max_recent default = %d, want 1000", a.MaxRecent)
	}
	if a.DedupWindowSec != 60 {
		t.Errorf("alerts.dedup_window_sec default = %d, want 60", a.DedupWindowSec)
	}
	if err := ValidateAlerts(a); err != nil {
		t.Errorf("the default alerts block does not validate: %v", err)
	}
}

func TestAlertsLoadFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"alerts":{
		"enabled": false,
		"min_confidence": 0.5,
		"per_class_min_confidence": {"scan": 0.9, "suspicious": 0.95},
		"alert_on_disagreement": false,
		"max_recent": 25,
		"dedup_window_sec": 300
	}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a := c.Alerts
	if a.Enabled {
		t.Error("enabled: an explicit false must survive the overlay onto Default()")
	}
	if a.MinConfidence != 0.5 || a.MaxRecent != 25 || a.DedupWindowSec != 300 || a.AlertOnDisagreement {
		t.Errorf("alerts not parsed: %+v", a)
	}
	if len(a.PerClassMinConfidence) != 2 || a.PerClassMinConfidence["scan"] != 0.9 {
		t.Errorf("per_class_min_confidence = %v, want the file's table to replace the default", a.PerClassMinConfidence)
	}
}

// TestAlertsValidationRejectsNonsense: every one of these is a typo an operator
// would otherwise only notice by wondering why nothing alerts.
func TestAlertsValidationRejectsNonsense(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"min-conf-negative":  `{"alerts":{"min_confidence":-0.1}}`,
		"min-conf-above-one": `{"alerts":{"min_confidence":7}}`,
		"max-recent-zero":    `{"alerts":{"max_recent":0}}`,
		"max-recent-neg":     `{"alerts":{"max_recent":-5}}`,
		"window-zero":        `{"alerts":{"dedup_window_sec":0}}`,
		"window-neg":         `{"alerts":{"dedup_window_sec":-1}}`,
		"unknown-class":      `{"alerts":{"per_class_min_confidence":{"ransomware":0.5}}}`,
		"normal-class":       `{"alerts":{"per_class_min_confidence":{"normal":0.5}}}`,
		"per-class-range":    `{"alerts":{"per_class_min_confidence":{"scan":1.5}}}`,
		"per-class-negative": `{"alerts":{"per_class_min_confidence":{"scan":-1}}}`,
		"unknown-field":      `{"alerts":{"severity_overrides":{"scan":"critical"}}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// TestAlertsErrorNamesTheField: an operator has to be able to find the typo.
func TestAlertsErrorNamesTheField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"alerts":{"per_class_min_confidence":{"ransomware":0.5}}}`))
	_, err := Load(p)
	if err == nil {
		t.Fatal("an unknown class must be rejected")
	}
	for _, want := range []string{"alerts", "per_class_min_confidence", "ransomware", "traffic-classes-v1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q is missing %q", err.Error(), want)
		}
	}
}

// TestAlertsSeverityIsNotConfigurable is a guard, not a feature test: severity is
// derived from the class in internal/alert, and an `alerts.severity` block would
// let a deployment invent a class with no severity. DisallowUnknownFields makes
// that a load error today; this test says so on purpose so the intent survives.
func TestAlertsSeverityIsNotConfigurable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"alerts":{"severity":{"scan":"critical"}}}`))
	if _, err := Load(p); err == nil {
		t.Fatal("alerts.severity must not be a config key — severity is derived from the class (ADR 0027)")
	}
}
