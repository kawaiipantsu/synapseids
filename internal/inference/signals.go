package inference

import (
	"fmt"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

// Signal is bounded heuristic evidence, distinct from a learned probability.
type Signal struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}

// BehaviorSignals reports observable patterns. Encrypted content, exploitation
// and malicious intent cannot be inferred merely from timing or file extensions.
func BehaviorSignals(v features.BehaviorVector) []Signal {
	x := v.Values
	out := []Signal{}
	add := func(k, level, evidence string) { out = append(out, Signal{k, level, evidence}) }
	if x[145] >= 12 && x[148] >= .7 {
		add("port_scan", "warning", fmt.Sprintf("%.0f distinct destination ports across %.0f recent conversations; %.0f%% one-way", x[145], x[144], 100*x[148]))
	}
	if x[146] >= 12 && x[148] >= .7 {
		add("host_sweep", "warning", fmt.Sprintf("%.0f distinct destination addresses in the bounded 60-second source window", x[146]))
	}
	if x[127] > 0 {
		if x[132] >= 3.5 && x[135] >= 12 && x[153] >= 10 && x[154]/x[153] >= .5 {
			add("dga_dns", "warning", "Long high-entropy DNS labels together with repeated NXDOMAIN responses; an advisory DGA-like pattern")
		}
		if x[153] >= 200 && x[155] >= 20 {
			add("dns_exhaustion", "warning", fmt.Sprintf("%.0f DNS queries and %.0f observed unique names across retained source conversations", x[153], x[155]))
		}
		if x[138] > 0 {
			add("suspicious_download", "review", "Plaintext HTTP executable/script extension or response content-type observed; a download hint does not establish malicious content")
		}
		if x[131] >= 3 {
			add("malformed_dns", "warning", fmt.Sprintf("%.0f captured DNS messages failed bounded parsing", x[131]))
		}
	}
	if x[158] >= .9 {
		add("periodic_connections", "review", fmt.Sprintf("Repeated connection starts with mean gap %.1fs and low timing variation; automation may be legitimate", x[149]))
	}
	return out
}
