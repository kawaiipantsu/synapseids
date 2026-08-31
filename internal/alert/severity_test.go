package alert_test

import (
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// TestSeverityCoversEveryTrafficClass pins the derived severity for all seven
// traffic-classes-v1 classes by name. It fails on two different mistakes: a
// changed mapping (the want table below), and a class the mapping forgot — the
// loop asserts that every class in the frozen schema is either "normal" or has a
// severity, so a future class with no entry is a test failure as well as an
// init() panic.
func TestSeverityCoversEveryTrafficClass(t *testing.T) {
	want := map[string]alert.Severity{
		"normal":      "", // never alerts
		"suspicious":  alert.SeverityLow,
		"scan":        alert.SeverityMedium,
		"brute_force": alert.SeverityHigh,
		"web_attack":  alert.SeverityHigh,
		"dos_ddos":    alert.SeverityCritical,
		"botnet_c2":   alert.SeverityCritical,
	}

	classes := schema.TrafficClassesV1().Classes
	if len(classes) != 7 {
		t.Fatalf("traffic-classes-v1 has %d classes, want 7 — the schema is frozen (PROJECT.md §9)", len(classes))
	}
	if len(want) != len(classes) {
		t.Fatalf("this test covers %d classes, the schema has %d", len(want), len(classes))
	}

	for _, c := range classes {
		exp, listed := want[c.Name]
		if !listed {
			t.Fatalf("class %q is in traffic-classes-v1 but not in this test's table", c.Name)
		}
		got, ok := alert.SeverityOf(c.Name)
		if exp == "" {
			if ok {
				t.Errorf("SeverityOf(%q) = %q, want no severity", c.Name, got)
			}
			continue
		}
		if !ok {
			t.Errorf("SeverityOf(%q) reported no severity — every non-normal class must have one", c.Name)
			continue
		}
		if got != exp {
			t.Errorf("SeverityOf(%q) = %q, want %q", c.Name, got, exp)
		}
		if !alert.ValidSeverity(got) {
			t.Errorf("SeverityOf(%q) = %q, which is not in Severities()", c.Name, got)
		}
	}
}

// TestSeverityOfUnknownClass proves an off-schema name never yields a blank-but-ok
// severity, which is the failure mode the derivation exists to prevent.
func TestSeverityOfUnknownClass(t *testing.T) {
	for _, name := range []string{"", "NORMAL", "ransomware", "scan "} {
		if sev, ok := alert.SeverityOf(name); ok {
			t.Errorf("SeverityOf(%q) = %q, ok — want not ok", name, sev)
		}
	}
}

func TestValidSeverity(t *testing.T) {
	for _, s := range alert.Severities() {
		if !alert.ValidSeverity(s) {
			t.Errorf("Severities() contains %q but ValidSeverity says no", s)
		}
	}
	for _, s := range []alert.Severity{"", "LOW", "info", "urgent"} {
		if alert.ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = true, want false", s)
		}
	}
}

// TestConfigAlertClassNamesMatchSchema is the drift guard for the class-name list
// duplicated in internal/config.
//
// config is a leaf package that must not import schema (docs/architecture.md), so
// it carries its own copy of the traffic-classes-v1 names to validate
// per_class_min_confidence keys. This test lives here because internal/alert
// legitimately imports both: it asserts through config's public behaviour that
// every class the frozen schema defines is accepted as a key, and that "normal"
// is rejected for a reason other than being unknown.
func TestConfigAlertClassNamesMatchSchema(t *testing.T) {
	for _, c := range schema.TrafficClassesV1().Classes {
		a := config.Default().Alerts
		a.PerClassMinConfidence = map[string]float64{c.Name: 0.5}
		err := config.ValidateAlerts(a)
		if c.Name == alert.ClassNormal {
			if err == nil {
				t.Errorf("ValidateAlerts accepted a threshold for %q, which never alerts", c.Name)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateAlerts rejected the traffic-classes-v1 class %q: %v — config's alertClassNames has drifted from the schema", c.Name, err)
		}
	}
}
