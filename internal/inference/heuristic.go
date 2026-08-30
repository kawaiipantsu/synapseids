package inference

import (
	"math"

	"github.com/kawaiipantsu/synapseids/internal/features"
)

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
	g := v.Get

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
	w := map[int]float64{classNormal: 3.0}

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
	}

	// DOS/DDOS: sustained high packet rate of small packets, strongly
	// one-directional.
	if pps >= 200 && smallRatio >= 0.8 && dirRatio >= 0.9 && totalPkts >= 100 {
		w[classDoS] = 4.0 + math.Log1p(pps)
	}
	if isUDP && pps >= 500 && dirRatio >= 0.95 {
		w[classDoS] += 1.5 + math.Log1p(pps)
	}

	// BRUTE FORCE: many short request/response rounds to an auth-ish port,
	// moderate rate, small packets.
	if isTCP && bwdPkts >= 3 && fwdPkts >= 3 && finCount+rstCount >= 1 &&
		(dport == 22 || dport == 21 || dport == 23 || dport == 3389 || dport == 445 || dport == 3306 || dport == 1433) &&
		dur < 30 && meanSize < 400 {
		w[classBrute] = 4.5
	}

	// WEB ATTACK: HTTP/HTTPS destination with a lopsided large request and a
	// small response.
	if isTCP && (dport == 80 || dport == 8080 || dport == 443 || dport == 8443) {
		if bytesFwd > 4000 && bytesBwd > 0 && bytesFwd > 6*bytesBwd {
			w[classWeb] = 4.0
		}
	}

	// BOTNET C2: long-lived low-rate beacon-like flow to a non-standard port,
	// regular inter-arrival, small symmetric packets.
	iatStd := g("interarrival_stddev")
	iatMean := g("interarrival_mean")
	if isTCP && dur > 60 && pps < 5 && totalPkts >= 6 && meanSize < 300 &&
		dport > 1024 && iatMean > 1 && iatStd < 0.5*iatMean+0.05 {
		w[classC2] = 4.0
	}

	// SUSPICIOUS: odd but not conclusive — a fan of SYNs that misses the strict
	// scan test, or an all-small one-way UDP spray below the DoS threshold.
	if _, ok := w[classScan]; !ok {
		if synCount >= 2 && synCount > ackCount+1 {
			w[classSuspicious] = 3.6
		}
		if isUDP && dirRatio >= 0.95 && totalPkts >= 20 && smallRatio >= 0.9 {
			w[classSuspicious] = math.Max(w[classSuspicious], 3.5)
		}
	}

	return softmax(w)
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
