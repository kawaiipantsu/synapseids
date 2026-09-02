package insight

// Per-host behavioural fingerprints and similarity search (PROJECT.md §30,
// issue #63, ADR 0039).
//
// A fingerprint is a fixed-length vector of scale-free behavioural ratios
// derived from the bounded per-host aggregates this package already keeps — flow
// direction, volume asymmetry, peer/port fan-out and entropy, protocol mix,
// class mix, and the disagreement / anomaly rates. It is a *hand-crafted*
// summary, not a learned embedding: every dimension is a documented ratio a
// human can read, and nothing is trained. A learned embedding (issue #63's
// original framing) can replace (*host).fingerprint() later without changing the
// Fingerprint / Similarity shapes or the API.
//
// Similarity is the cosine between two fingerprints. It answers "which other
// observed hosts behave like this one" — a lateral-movement / botnet-peer lead,
// not a verdict.

import (
	"math"
	"sort"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// classDimNames holds the traffic-classes-v1 names, prefixed, as the class-mix
// fingerprint dimensions. Built once so the frozen class order is the source of
// truth (a new class is a v2, not an edit).
var classDimNames []string

// fingerprintDimNames is the frozen, ordered dimension list. Index i of a
// Fingerprint.Vector is fingerprintDimNames[i]. Appending is a v2.
var fingerprintDimNames []string

func init() {
	base := []string{
		"flow_volume",     // log1p(flows) squashed to 0..1 — evidence weight, not behaviour
		"initiator_bias",  // initiated / (initiated + responded)
		"upload_bias",     // bytes_out / (bytes_in + bytes_out)
		"packet_out_bias", // packets_out / (packets_in + packets_out)
		"avg_pkt_in",      // mean inbound packet size, log-squashed
		"avg_pkt_out",     // mean outbound packet size, log-squashed
		"peer_fanout",     // distinct peers / flows
		"port_fanout",     // distinct service ports / flows
		"port_entropy",    // normalised Shannon entropy of the port distribution
		"peer_entropy",    // normalised Shannon entropy of the peer distribution
		"proto_tcp",       // share of flows
		"proto_udp",
		"proto_icmp",
	}
	// Read the frozen class list straight from the schema package: its init()
	// runs before this one, whereas insight.go's className table may not
	// (init order within a package is by filename, and fingerprint.go < insight.go).
	for _, c := range schema.TrafficClassesV1().Classes {
		classDimNames = append(classDimNames, "class_"+c.Name)
	}
	tail := []string{
		"disagreement_rate", // disagreements / classifications
		"anomaly_rate",      // anomaly_exceeded / anomaly_scored (0 when no anomaly model)
	}
	fingerprintDimNames = append(fingerprintDimNames, base...)
	fingerprintDimNames = append(fingerprintDimNames, classDimNames...)
	fingerprintDimNames = append(fingerprintDimNames, tail...)
}

// FingerprintDims returns a copy of the frozen dimension-name list.
func FingerprintDims() []string {
	out := make([]string, len(fingerprintDimNames))
	copy(out, fingerprintDimNames)
	return out
}

// FingerprintValue is one named dimension of a host fingerprint.
type FingerprintValue struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// Fingerprint is one host's behavioural summary. Vector is the raw ordered
// values (fingerprintDimNames order); Dims is the same values named, for a UI or
// a human. FlowCount is how many terminal flows it was built from — a
// fingerprint from 2 flows is noise, so callers should weight by it.
type Fingerprint struct {
	IP        string             `json:"ip"`
	FlowCount uint64             `json:"flow_count"`
	Dims      []FingerprintValue `json:"dims"`
	Vector    []float64          `json:"vector"`
}

// Similarity is one neighbour of a queried host, cosine-nearest first.
type Similarity struct {
	IP        string  `json:"ip"`
	Cosine    float64 `json:"cosine"`
	FlowCount uint64  `json:"flow_count"`
}

// DefaultSimilarMinFlows is the floor on a candidate host's terminal-flow count
// before it can be a similarity neighbour — below it a fingerprint is mostly
// noise.
const DefaultSimilarMinFlows = 5

// squash maps [0, ∞) to [0, 1) as x/(x+1) — order-preserving, no parameters.
func squash(x float64) float64 {
	if x <= 0 || math.IsNaN(x) {
		return 0
	}
	return x / (x + 1)
}

func safeRatio(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	r := num / den
	if math.IsNaN(r) || math.IsInf(r, 0) {
		return 0
	}
	return r
}

// fingerprint builds the fixed vector for one host. Caller holds ix.mu.RLock.
func (h *host) fingerprint() Fingerprint {
	v := make([]float64, 0, len(fingerprintDimNames))
	flows := float64(h.flows)
	inOut := float64(h.initiated + h.responded)
	bytesTot := float64(h.bytesIn + h.bytesOut)
	pktsTot := float64(h.packetsIn + h.packetsOut)

	v = append(v,
		squash(math.Log1p(flows)/6),                                        // flow_volume (~e^6 ≈ 400 flows → ~0.5)
		safeRatio(float64(h.initiated), inOut),                             // initiator_bias
		safeRatio(float64(h.bytesOut), bytesTot),                           // upload_bias
		safeRatio(float64(h.packetsOut), pktsTot),                          // packet_out_bias
		squash(safeRatio(float64(h.bytesIn), float64(h.packetsIn))/1500),   // avg_pkt_in (÷ MTU)
		squash(safeRatio(float64(h.bytesOut), float64(h.packetsOut))/1500), // avg_pkt_out
		squash(safeRatio(float64(h.peers.distinct()), flows)),              // peer_fanout
		squash(safeRatio(float64(h.ports.distinct()), flows)),              // port_fanout
		h.ports.entropyNorm(),                                              // port_entropy
		h.peers.entropyNorm(),                                              // peer_entropy
		safeRatio(float64(h.protos["TCP"]+h.protos["tcp"]), flows),         // proto_tcp
		safeRatio(float64(h.protos["UDP"]+h.protos["udp"]), flows),         // proto_udp
		safeRatio(float64(h.protos["ICMP"]+h.protos["icmp"]), flows),       // proto_icmp
	)

	cls := float64(h.classifications)
	for i := 0; i < len(className) && i < len(h.classes); i++ {
		if className[i] == "" {
			continue
		}
		v = append(v, safeRatio(float64(h.classes[i]), cls)) // class_<name>
	}

	v = append(v,
		safeRatio(float64(h.disagreements), cls),            // disagreement_rate
		safeRatio(float64(h.anomExceeds), float64(h.anomN)), // anomaly_rate
	)

	dims := make([]FingerprintValue, len(v))
	for i := range v {
		name := ""
		if i < len(fingerprintDimNames) {
			name = fingerprintDimNames[i]
		}
		dims[i] = FingerprintValue{Name: name, Value: v[i]}
	}
	return Fingerprint{IP: h.ip, FlowCount: h.flows, Dims: dims, Vector: v}
}

// HostFingerprint returns the behavioural fingerprint for one tracked host.
func (ix *Index) HostFingerprint(ip string) (Fingerprint, bool) {
	if ix == nil {
		return Fingerprint{}, false
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	h, ok := ix.hosts[ip]
	if !ok {
		return Fingerprint{}, false
	}
	return h.fingerprint(), true
}

func cosine(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na <= 0 || nb <= 0 {
		return 0
	}
	c := dot / (math.Sqrt(na) * math.Sqrt(nb))
	if math.IsNaN(c) {
		return 0
	}
	return math.Max(-1, math.Min(1, c))
}

// SimilarHosts returns up to limit other tracked hosts whose fingerprint is
// cosine-nearest to ip's, most similar first. minFlows floors a candidate's
// terminal-flow count; a value <= 0 selects DefaultSimilarMinFlows. The bool is
// false when ip itself is not tracked.
func (ix *Index) SimilarHosts(ip string, limit, minFlows int) (Fingerprint, []Similarity, bool) {
	if ix == nil {
		return Fingerprint{}, nil, false
	}
	if minFlows <= 0 {
		minFlows = DefaultSimilarMinFlows
	}
	if limit <= 0 {
		limit = 10
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()

	self, ok := ix.hosts[ip]
	if !ok {
		return Fingerprint{}, nil, false
	}
	sfp := self.fingerprint()

	out := make([]Similarity, 0, len(ix.hosts))
	for other, h := range ix.hosts {
		if other == ip || h.flows < uint64(minFlows) {
			continue
		}
		out = append(out, Similarity{
			IP:        other,
			Cosine:    cosine(sfp.Vector, h.fingerprint().Vector),
			FlowCount: h.flows,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cosine != out[j].Cosine {
			return out[i].Cosine > out[j].Cosine
		}
		if out[i].FlowCount != out[j].FlowCount {
			return out[i].FlowCount > out[j].FlowCount
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return sfp, out, true
}
