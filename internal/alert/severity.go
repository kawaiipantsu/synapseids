package alert

import (
	"fmt"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Severity is an operator-facing urgency label for a detection.
//
// It is *derived* from the traffic class and is deliberately NOT part of
// traffic-classes-v1. That schema is frozen (PROJECT.md §9, §28.5-6): it
// describes what a model predicts, and a model predicts a class, never an
// urgency. Severity is presentation policy — it can change without a schema
// version, and it must, because "a scan is medium" is an operational judgement
// rather than a measurement. See docs/adr/0027.
type Severity string

// The four severity levels, ordered least to most urgent.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ClassNormal is the traffic-classes-v1 class that never produces a detection.
// It has no severity by construction: benign traffic is the baseline, not a
// finding.
const ClassNormal = "normal"

// Severities lists every valid severity, least urgent first. It backs the
// severity= filter's validation so an unknown value is a 400 rather than a
// silently empty result.
func Severities() []Severity {
	return []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// ValidSeverity reports whether s is one of Severities().
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// classSeverity maps every non-normal traffic-classes-v1 class to its severity.
//
// Every class in the frozen schema must appear here or the package refuses to
// initialise (see init below). That is the point: a class added to a *future*
// classes schema, or a typo here, becomes a startup error rather than a
// detection with an empty severity string that no filter can select and no
// operator can triage.
var classSeverity = map[string]Severity{
	"suspicious":  SeverityLow,
	"scan":        SeverityMedium,
	"brute_force": SeverityHigh,
	"web_attack":  SeverityHigh,
	"dos_ddos":    SeverityCritical,
	"botnet_c2":   SeverityCritical,
}

// init is the startup gate: the severity table must cover the frozen class list
// exactly, in both directions. A drift either way panics at process start rather
// than degrading into detections whose severity is the empty string.
func init() {
	classes := schema.TrafficClassesV1().Classes
	known := make(map[string]bool, len(classes))
	for _, c := range classes {
		known[c.Name] = true
		if c.Name == ClassNormal {
			continue // benign traffic never alerts
		}
		if _, ok := classSeverity[c.Name]; !ok {
			panic(fmt.Sprintf("alert: traffic-classes-v1 class %q has no severity mapping — add it to classSeverity (PROJECT.md §9)", c.Name))
		}
	}
	for name := range classSeverity {
		if !known[name] {
			panic(fmt.Sprintf("alert: classSeverity maps %q, which is not a traffic-classes-v1 class", name))
		}
	}
}

// SeverityOf returns the severity derived from a traffic-classes-v1 class name.
// ok is false for "normal" (never alerts) and for any name that is not in the
// frozen class list.
func SeverityOf(class string) (Severity, bool) {
	if class == ClassNormal {
		return "", false
	}
	sev, ok := classSeverity[class]
	return sev, ok
}
