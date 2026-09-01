package alert

import "fmt"

// Default policy values. They are the documented defaults of the config
// `alerts` block (internal/config); Options.withDefaults applies them to a zero
// value so an embedded Store (tests, future tooling) behaves like the daemon.
const (
	// DefaultMinConfidence is the floor a verdict must clear to become a
	// detection. 0.70 is a deliberate compromise for the Phase 1 heuristic,
	// whose scores are rule-derived rather than calibrated probabilities.
	DefaultMinConfidence = 0.70
	// DefaultMaxRecent bounds the retained detections.
	DefaultMaxRecent = 1000
	// DefaultDedupWindowSec is how long one (src, dst, class) detection keeps
	// absorbing further occurrences before a fresh detection is opened.
	DefaultDedupWindowSec = 60
	// DefaultQueueSize is the depth of the ingest queue between the packet path
	// and the Store's single aggregator goroutine.
	DefaultQueueSize = 4096
)

// DefaultPerClassMinConfidence is the built-in per-class threshold override.
//
// `suspicious` is the supervised catch-all (traffic-classes-v1: "anomalous but
// unattributed"). It is the class a model reaches for when it is least sure, so
// it carries a higher bar than the global floor — otherwise the detection feed
// fills with the one class that tells an operator least.
func DefaultPerClassMinConfidence() map[string]float64 {
	return map[string]float64{"suspicious": 0.85}
}

// Policy decides whether a classification becomes a detection. It is a value:
// copy it, do not share it.
type Policy struct {
	// Enabled false suppresses every detection. The Store still runs and still
	// reports counters, so /api/v1/status can say "alerting is off" rather than
	// "nothing has happened".
	Enabled bool
	// MinConfidence is the global floor in [0,1].
	MinConfidence float64
	// PerClassMinConfidence overrides MinConfidence for a traffic-classes-v1
	// class. A missing entry means "use MinConfidence".
	PerClassMinConfidence map[string]float64
	// AlertOnDisagreement raises a detection for a below-threshold verdict when
	// the models disagreed (PROJECT.md §12: a disagreement is a finding in its
	// own right, and hiding it behind a confidence floor is exactly the
	// information loss the ensemble exists to prevent).
	AlertOnDisagreement bool
	// Suppress is the expected-behaviour layer (issue #133): a verdict that
	// clears its threshold but matches one of these rules is NOT raised as a
	// detection. It is still scored and still stored as a classification —
	// suppression is a reporting decision, not a modelling one. Compile the
	// config rules with CompileSuppress. Empty by default.
	Suppress []SuppressRule
}

// DefaultPolicy returns the built-in policy.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:               true,
		MinConfidence:         DefaultMinConfidence,
		PerClassMinConfidence: DefaultPerClassMinConfidence(),
		AlertOnDisagreement:   true,
	}
}

// Threshold returns the confidence floor that applies to class.
func (p Policy) Threshold(class string) float64 {
	if v, ok := p.PerClassMinConfidence[class]; ok {
		return v
	}
	return p.MinConfidence
}

// Verdict is the policy's answer for one classification.
type Verdict struct {
	Alert    bool
	Severity Severity
	// Reason is the operator-facing explanation, e.g.
	// "brute_force at 98.3% >= 70% threshold". It is built from measured values
	// only — never a fabricated confidence (PROJECT.md §16).
	Reason string
}

// Decide applies the policy to one verdict. class is a traffic-classes-v1 class
// name, score its confidence in [0,1].
//
// A non-alerting outcome is one of three things and the caller distinguishes
// them by looking at Alert alone: disabled, not an alertable class ("normal", or
// a class with no severity), or below the applicable threshold. Only the last is
// counted as "suppressed" — see Store.apply.
func (p Policy) Decide(class string, score float64, disagreement bool) Verdict {
	if !p.Enabled {
		return Verdict{}
	}
	sev, ok := SeverityOf(class)
	if !ok {
		return Verdict{}
	}
	th := p.Threshold(class)
	if score >= th {
		return Verdict{
			Alert:    true,
			Severity: sev,
			Reason:   fmt.Sprintf("%s at %.1f%% >= %.0f%% threshold", class, score*100, th*100),
		}
	}
	if disagreement && p.AlertOnDisagreement {
		return Verdict{
			Alert:    true,
			Severity: sev,
			Reason:   fmt.Sprintf("model disagreement on %s at %.1f%%, below the %.0f%% threshold", class, score*100, th*100),
		}
	}
	return Verdict{}
}

// alertable reports whether class could ever alert under this policy, ignoring
// confidence. It separates "not an alertable class" from "below threshold" so
// the suppressed counter means what it says.
func (p Policy) alertable(class string) bool {
	if !p.Enabled {
		return false
	}
	_, ok := SeverityOf(class)
	return ok
}
