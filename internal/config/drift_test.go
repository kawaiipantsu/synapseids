package config

import (
	"path/filepath"
	"testing"
)

// TestDriftDefaults pins the documented defaults of the drift block (quoted in
// docs/api.md and ADR 0036/0038).
func TestDriftDefaults(t *testing.T) {
	d := Default().Drift
	if d.WarnZ != 2.0 || d.DriftZ != 4.0 {
		t.Errorf("drift bands = %v / %v, want 2.0 / 4.0", d.WarnZ, d.DriftZ)
	}
	if d.RetrainSuggestZ != 6.0 || d.RetrainSuggestFeatures != 3 {
		t.Errorf("retrain trips = %v / %d, want 6.0 / 3", d.RetrainSuggestZ, d.RetrainSuggestFeatures)
	}
	if err := ValidateDrift(d); err != nil {
		t.Errorf("the default drift block does not validate: %v", err)
	}
}

func TestDriftLoadFromFileJSONAndYAML(t *testing.T) {
	for _, tc := range []struct {
		name, ext, body string
	}{
		{"json", ".json", `{"drift":{"warn_z":1.5,"drift_z":3,"retrain_suggest_z":9,"retrain_suggest_features":10}}`},
		{"yaml", ".yaml", "drift:\n  warn_z: 1.5\n  drift_z: 3\n  retrain_suggest_z: 9\n  retrain_suggest_features: 10\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c"+tc.ext)
			mustWrite(t, p, []byte(tc.body))
			c, err := Load(p)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			d := c.Drift
			if d.WarnZ != 1.5 || d.DriftZ != 3 || d.RetrainSuggestZ != 9 || d.RetrainSuggestFeatures != 10 {
				t.Fatalf("drift = %+v", d)
			}
		})
	}
}

func TestDriftValidationRejectsNonsense(t *testing.T) {
	for name, body := range map[string]string{
		"negative-warn":    `{"drift":{"warn_z":-1}}`,
		"zero-drift":       `{"drift":{"drift_z":0}}`,
		"warn-above-drift": `{"drift":{"warn_z":5,"drift_z":4}}`,
		"drift-above-sugg": `{"drift":{"drift_z":8,"retrain_suggest_z":6}}`,
		"zero-features":    `{"drift":{"retrain_suggest_features":0}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.json")
			mustWrite(t, p, []byte(body))
			if _, err := Load(p); err == nil {
				t.Fatalf("%s: expected a validation error", name)
			}
		})
	}
}
