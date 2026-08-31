package inference

import (
	"math"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// HeuristicNormalPrior is the standing pre-softmax weight the heuristic gives
// "normal", so a flow that trips no rule at all reads as confidently benign
// rather than uncertain. It is reported in an Explanation so an operator can see
// that a `normal` verdict with no fired rules is a *prior*, not a positive
// finding (PROJECT.md §13).
const HeuristicNormalPrior = 3.0

// Heuristic is a transparent rule-based stand-in for a trained neural network.
// It emits a traffic-classes-v1 distribution so the whole pipeline — features,
// runtime, API, UI — is exercised before Phase 2 brings real ONNX models
// (PROJECT.md §26 Phase 1). It is deliberately conservative: when nothing fires
// it returns "normal", and a weak signal lands on "suspicious" rather than being
// forced into an attack class (PROJECT.md §13).
type Heuristic struct {
	id   string
	role Role
}

// NewHeuristic returns a Heuristic model with the given id and role.
func NewHeuristic(id string, role Role) *Heuristic {
	if id == "" {
		id = "heuristic-v1"
	}
	if role == "" {
		role = RolePrimary
	}
	return &Heuristic{id: id, role: role}
}

// ID returns the instance name.
func (h *Heuristic) ID() string { return h.id }

// Family returns the locked contract this model belongs to.
func (h *Heuristic) Family() string { return "flow-classifier-v1" }

// Role returns the model's ensemble role.
func (h *Heuristic) Role() Role { return h.role }

// Classify scores a feature vector.
func (h *Heuristic) Classify(v features.Vector) Scores {
	w, _ := h.evaluate(v, false)
	return softmax(w)
}

// evaluate runs the rule set once and returns the pre-softmax class weights.
//
// Classify and Explain both go through here, so the fired-rule list an operator
// reads is produced by the *same* evaluation that produced the verdict — it can
// never drift from the rules that actually ran (PROJECT.md §19.3).
//
// When explain is false the rule list is not built at all, keeping the packet
// path free of the per-rule schema lookups (PROJECT.md §22, §28.12).
func (h *Heuristic) evaluate(v features.Vector, explain bool) (map[int]float64, []FiredRule) {
	g := v.Get

	var rules []FiredRule
	// fired records one rule that matched, together with the feature values it
	// tested — the values are re-read from the same vector, so what an operator
	// sees is exactly what the condition compared.
	fired := func(id string, class int, detail string, names ...string) {
		if !explain {
			return
		}
		fs := make([]RuleFeature, 0, len(names))
		for _, n := range names {
			fs = append(fs, RuleFeature{Name: n, Value: g(n), Unit: featureUnit(n)})
		}
		rules = append(rules, FiredRule{
			Rule:     id,
			Class:    schema.ClassName(class),
			ClassID:  class,
			Detail:   detail,
			Features: fs,
		})
	}

	synCount := g("tcp_syn_count")
	ackCount := g("tcp_ack_count")
	rstCount := g("tcp_rst_count")
	finCount := g("tcp_fin_count")
	pps := g("packets_per_second")
	fwdPkts := g("packets_forward")
	bwdPkts := g("packets_backward")
	totalPkts := fwdPkts + bwdPkts
	meanSize := g("packet_size_mean")
	smallRatio := g("small_packet_ratio")
	dur := g("flow_duration")
	dport := g("destination_port")
	isTCP := g("protocol_tcp") == 1
	isUDP := g("protocol_udp") == 1
	dirRatio := g("packet_direction_ratio")
	bytesFwd := g("bytes_forward")
	bytesBwd := g("bytes_backward")

	// Raw signal weights, later soft-maxed into a distribution. "normal" holds a
	// firm baseline so a flow that trips no rule reads as confidently benign.
	w := map[int]float64{classNormal: HeuristicNormalPrior}

	// SCAN: a probe SYN with little or no response, a one-directional TCP
	// exchange that ends in RST, or a very short-lived tiny SYN-led flow.
	if isTCP {
		unanswered := synCount >= 1 && bwdPkts == 0 && ackCount <= synCount
		// A lone SYN answered only by a RST is the textbook closed-port probe.
		rstScan := synCount >= 1 && rstCount >= 1 && totalPkts <= 4 && meanSize < 80 && dur < 1
		shortProbe := synCount >= 1 && totalPkts <= 3 && dur < 0.5 && meanSize < 120 && bwdPkts == 0
		if unanswered || rstScan || shortProbe {
			w[classScan] = 5.0 + synCount + rstCount
		}
		// Each matching sub-condition is reported separately; they share the one
		// class weight above rather than each adding their own.
		if unanswered {
			fired("scan.unanswered_syn", classScan,
				"a SYN was sent and nothing came back",
				"tcp_syn_count", "packets_backward", "tcp_ack_count")
		}
		if rstScan {
			fired("scan.syn_rst_probe", classScan,
				"a tiny, short SYN exchange answered by a RST — the textbook closed-port probe",
				"tcp_syn_count", "tcp_rst_count", "packets_forward", "packets_backward",
				"packet_size_mean", "flow_duration")
		}
		if shortProbe {
			fired("scan.short_probe", classScan,
				"a very short-lived, tiny, SYN-led flow with no reply",
				"tcp_syn_count", "packets_forward", "packets_backward",
				"flow_duration", "packet_size_mean")
		}
	}

	// DOS/DDOS: sustained high packet rate of small packets, strongly
	// one-directional.
	if pps >= 200 && smallRatio >= 0.8 && dirRatio >= 0.9 && totalPkts >= 100 {
		w[classDoS] = 4.0 + math.Log1p(pps)
		fired("dos.small_packet_flood", classDoS,
			"a sustained, strongly one-directional flood of small packets",
			"packets_per_second", "small_packet_ratio", "packet_direction_ratio",
			"packets_forward", "packets_backward")
	}
	if isUDP && pps >= 500 && dirRatio >= 0.95 {
		w[classDoS] += 1.5 + math.Log1p(pps)
		fired("dos.udp_flood", classDoS,
			"a very high-rate, almost entirely one-directional UDP flood",
			"protocol_udp", "packets_per_second", "packet_direction_ratio")
	}

	// BRUTE FORCE: many short request/response rounds to an auth-ish port,
	// moderate rate, small packets.
	if isTCP && bwdPkts >= 3 && fwdPkts >= 3 && finCount+rstCount >= 1 &&
		(dport == 22 || dport == 21 || dport == 23 || dport == 3389 || dport == 445 || dport == 3306 || dport == 1433) &&
		dur < 30 && meanSize < 400 {
		w[classBrute] = 4.5
		fired("brute_force.auth_port_rounds", classBrute,
			"repeated short small-packet request/response rounds against an authentication port",
			"destination_port", "packets_forward", "packets_backward",
			"tcp_fin_count", "tcp_rst_count", "flow_duration", "packet_size_mean")
	}

	// WEB ATTACK: HTTP/HTTPS destination with a lopsided large request and a
	// small response.
	if isTCP && (dport == 80 || dport == 8080 || dport == 443 || dport == 8443) {
		if bytesFwd > 4000 && bytesBwd > 0 && bytesFwd > 6*bytesBwd {
			w[classWeb] = 4.0
			fired("web_attack.lopsided_request", classWeb,
				"a large request to an HTTP/HTTPS port answered by a much smaller response",
				"destination_port", "bytes_forward", "bytes_backward")
		}
	}

	// BOTNET C2: long-lived low-rate beacon-like flow to a non-standard port,
	// regular inter-arrival, small symmetric packets.
	iatStd := g("interarrival_stddev")
	iatMean := g("interarrival_mean")
	if isTCP && dur > 60 && pps < 5 && totalPkts >= 6 && meanSize < 300 &&
		dport > 1024 && iatMean > 1 && iatStd < 0.5*iatMean+0.05 {
		w[classC2] = 4.0
		fired("botnet_c2.regular_beacon", classC2,
			"a long-lived, low-rate flow of small packets to a non-standard port, "+
				"arriving at suspiciously regular intervals",
			"flow_duration", "packets_per_second", "packets_forward", "packets_backward",
			"packet_size_mean", "destination_port", "interarrival_mean", "interarrival_stddev")
	}

	// SUSPICIOUS: odd but not conclusive — a fan of SYNs that misses the strict
	// scan test, or an all-small one-way UDP spray below the DoS threshold.
	if _, ok := w[classScan]; !ok {
		if synCount >= 2 && synCount > ackCount+1 {
			w[classSuspicious] = 3.6
			fired("suspicious.syn_fan", classSuspicious,
				"more SYNs than the exchange accounts for, but not enough to call it a scan",
				"tcp_syn_count", "tcp_ack_count")
		}
		if isUDP && dirRatio >= 0.95 && totalPkts >= 20 && smallRatio >= 0.9 {
			w[classSuspicious] = math.Max(w[classSuspicious], 3.5)
			fired("suspicious.udp_spray", classSuspicious,
				"a one-way spray of small UDP packets, below the flood threshold",
				"protocol_udp", "packet_direction_ratio", "packets_forward",
				"packets_backward", "small_packet_ratio")
		}
	}

	return w, rules
}

// traffic-classes-v1 indices.
const (
	classNormal = iota
	classScan
	classDoS
	classBrute
	classC2
	classWeb
	classSuspicious
)

func softmax(w map[int]float64) Scores {
	var s Scores
	// Temperature < 1 sharpens; the heuristic should be fairly decisive.
	const temp = 0.6
	hi := math.Inf(-1)
	for i := 0; i < OutputSize; i++ {
		if v, ok := w[i]; ok && v > hi {
			hi = v
		}
	}
	if math.IsInf(hi, -1) {
		s[classNormal] = 1
		return s
	}
	var sum float64
	for i := 0; i < OutputSize; i++ {
		v := w[i]
		e := math.Exp((v - hi) / temp)
		s[i] = e
		sum += e
	}
	for i := range s {
		s[i] /= sum
	}
	return s
}
