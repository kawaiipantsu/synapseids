package insight

// Traffic matrix — who talks to whom (issue #68, PROJECT.md §19.4/§19.5).
//
// # Why this is a bounded top-N and not a matrix
//
// The obvious reading of "traffic matrix" is a full hosts × hosts grid. That is
// not something this package can maintain: the host map alone is capped at 2048
// (ADR 0016), and 2048 hosts is up to ~4.2 million ordered pairs. Even at ~150
// bytes of state per pair that is hundreds of megabytes of packet-derived,
// attacker-influenceable state (§21, §28.11) — a single /16 sweep would create it
// on purpose.
//
// So this is deliberately **not** a complete matrix. It is a bounded table of the
// heaviest ordered (initiator, responder) pairs, capped at DefaultMaxPairs, which
// on overflow discards the lighter half by (flows, bytes) and counts the discards
// in Stats.PairsEvicted. Every response says so: Matrix.Partial is true once the
// cap has bitten, so a client renders "top pairs" rather than presenting a
// truncated grid as if it were the whole picture.
//
// The pair direction is the flow's own: flow.Key is direction-normalized, so the
// initiator is the side that opened the conversation. (A, B) and (B, A) are
// different pairs and are never merged.
//
// # Cost
//
// pairTable.observe is one map lookup on a two-string struct key plus scalar
// adds: O(1), no allocation, on the aggregator goroutine — not the packet path.
// Index.Observe is untouched by this file and still copies one ~120-byte
// observation and does one non-blocking send. Benchmarks in matrix_test.go.

import (
	"sort"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// DefaultMaxPairs caps the number of tracked (initiator, responder) pairs. At
// ~200 bytes of state and key per pair this is well under a megabyte, and it is
// two orders of magnitude below the 2048² pairs the host cap permits — which is
// the whole point: see the package comment above.
const DefaultMaxPairs = 4096

// normalClassID is the traffic-classes-v1 index of the benign class, or -1 if the
// schema has no such class. It is resolved from the schema rather than hardcoded
// to 0 so this file states its assumption instead of burying it.
var normalClassID = -1

func init() {
	for _, c := range schema.TrafficClassesV1().Classes {
		if c.Name == "normal" {
			normalClassID = c.Index
			break
		}
	}
}

// pairKey identifies one ordered conversation. Both fields are packet-derived
// address strings, already canonicalised by netip when the flow record was built.
type pairKey struct {
	initiator string
	responder string
}

// pairState is one cell's accumulators. Volume comes from terminal records only
// and classification counts from every record, exactly as host profiles do (ADR
// 0016) — a long flow's periodic snapshots carry cumulative counters, so adding
// them to volume would double-count the same bytes.
type pairState struct {
	flows           uint64
	bytesFwd        uint64
	bytesBwd        uint64
	packetsFwd      uint64
	packetsBwd      uint64
	classifications uint64
	disagreements   uint64
	classes         [inference.OutputSize]uint64
	firstSeen       time.Time
	lastSeen        time.Time
}

func (p *pairState) bytes() uint64   { return p.bytesFwd + p.bytesBwd }
func (p *pairState) packets() uint64 { return p.packetsFwd + p.packetsBwd }

// pairTable is the bounded pair map. It is not safe for concurrent use; the
// Index's copy is written only by the aggregator goroutine under ix.mu, and the
// on-demand MatrixAccumulator owns its own.
type pairTable struct {
	m       map[pairKey]*pairState
	max     int
	evicted uint64
}

func newPairTable(max int) *pairTable {
	if max < 2 {
		max = 2
	}
	return &pairTable{m: make(map[pairKey]*pairState, 64), max: max}
}

// observe folds one observation into its pair cell. O(1) and allocation-free
// except when a new pair is inserted.
func (t *pairTable) observe(ob observation) {
	if ob.initiatorIP == "" || ob.responderIP == "" {
		return
	}
	k := pairKey{initiator: ob.initiatorIP, responder: ob.responderIP}
	p, ok := t.m[k]
	if !ok {
		if len(t.m) >= t.max {
			t.prune()
			// prune always frees at least one slot, so this cannot loop.
		}
		p = &pairState{}
		t.m[k] = p
	}

	if p.firstSeen.IsZero() || (!ob.firstSeen.IsZero() && ob.firstSeen.Before(p.firstSeen)) {
		p.firstSeen = ob.firstSeen
	}
	if ob.lastSeen.After(p.lastSeen) {
		p.lastSeen = ob.lastSeen
	}

	if ob.classID >= 0 {
		p.classifications++
		if ob.classID < len(p.classes) {
			p.classes[ob.classID]++
		}
		if ob.disagreement {
			p.disagreements++
		}
	}

	if !ob.terminal {
		return
	}
	p.flows++
	p.bytesFwd += ob.bytesFwd
	p.bytesBwd += ob.bytesBwd
	p.packetsFwd += ob.packetsFwd
	p.packetsBwd += ob.packetsBwd
}

// prune drops the lighter half of the table, ranked by flows then bytes. Doing it
// in one pass every max/2 inserts keeps the amortised insert cost at O(log n)
// rather than paying a strict-LRU scan on every insert — the same trade-off
// pruneHosts makes.
//
// The consequence is deliberate and documented in the ADR: a pair that is evicted
// and later seen again restarts from zero, so a light pair's counters can
// undercount. Heavy hitters — the ones a matrix exists to show — are never
// evicted while they stay heavy, and the flow log and host profiles remain the
// systems of record for anything this view drops.
func (t *pairTable) prune() {
	keep := t.max / 2
	if keep < 1 {
		keep = 1
	}
	type ent struct {
		k pairKey
		p *pairState
	}
	all := make([]ent, 0, len(t.m))
	for k, p := range t.m {
		all = append(all, ent{k, p})
	}
	sort.Slice(all, func(i, j int) bool {
		return heavier(all[i].k, all[i].p, all[j].k, all[j].p)
	})
	for _, e := range all[min(keep, len(all)):] {
		delete(t.m, e.k)
		t.evicted++
	}
}

// heavier is the total order used for both eviction and the default listing:
// flows, then bytes, then the addresses, so results are deterministic and stable
// across repeated calls with identical state.
func heavier(ak pairKey, a *pairState, bk pairKey, b *pairState) bool {
	if a.flows != b.flows {
		return a.flows > b.flows
	}
	if a.bytes() != b.bytes() {
		return a.bytes() > b.bytes()
	}
	if ak.initiator != bk.initiator {
		return ak.initiator < bk.initiator
	}
	return ak.responder < bk.responder
}

// MatrixSort orders the returned pair list.
type MatrixSort string

// Pair orderings. Flows is the default: a conversation-count matrix is what
// answers "who talks to whom", and it is also the eviction ranking, so the
// default list and the retained set agree.
const (
	MatrixSortFlows    MatrixSort = "flows"
	MatrixSortBytes    MatrixSort = "bytes"
	MatrixSortLastSeen MatrixSort = "last_seen"
)

// ParseMatrixSort validates a sort= parameter. An empty value means
// MatrixSortFlows.
func ParseMatrixSort(s string) (MatrixSort, bool) {
	switch MatrixSort(s) {
	case "":
		return MatrixSortFlows, true
	case MatrixSortFlows, MatrixSortBytes, MatrixSortLastSeen:
		return MatrixSort(s), true
	}
	return "", false
}

// MatrixPair is one cell of the matrix: an ordered conversation and what was seen
// on it.
type MatrixPair struct {
	Initiator string    `json:"initiator"`
	Responder string    `json:"responder"`
	Flows     uint64    `json:"flows"`
	Bytes     uint64    `json:"bytes"`
	BytesFwd  uint64    `json:"bytes_fwd"`
	BytesBwd  uint64    `json:"bytes_bwd"`
	Packets   uint64    `json:"packets"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Classifications uint64       `json:"classifications"`
	Classes         []ClassCount `json:"classes"`
	// DominantClass is the highest-count class on this pair.
	DominantClass string `json:"dominant_class,omitempty"`
	// ThreatClass is the highest-count class that is not "normal", and
	// ThreatCount its verdict count. They are what makes an attack pair visible
	// in a grid: a pair with 400 normal and 3 brute_force verdicts is dominated
	// by "normal" but is the cell an operator wants to see.
	ThreatClass   string `json:"threat_class,omitempty"`
	ThreatCount   uint64 `json:"threat_count,omitempty"`
	Disagreements uint64 `json:"disagreements"`
}

// MatrixAxis is one endpoint of the grid with its totals across the returned
// pairs, in axis order.
type MatrixAxis struct {
	IP    string `json:"ip"`
	Flows uint64 `json:"flows"`
	Bytes uint64 `json:"bytes"`
	Pairs int    `json:"pairs"`
}

// Matrix is the traffic-matrix response (issue #68).
//
// Partial is the honesty flag: true when the pair cap has evicted at least one
// pair (incremental source) or when the scanned window was itself capped (scan
// source). A false Partial means these pairs are everything the daemon saw in
// scope; a true Partial means they are the heaviest ones it kept.
type Matrix struct {
	Pairs      []MatrixPair `json:"pairs"`
	Initiators []MatrixAxis `json:"initiators"`
	Responders []MatrixAxis `json:"responders"`

	Sort MatrixSort `json:"sort"`
	// Source is "incremental" for the always-on bounded table and "scan" for a
	// filtered query bucketed on demand from the stored window.
	Source string `json:"source"`

	TrackedPairs  int    `json:"tracked_pairs"`
	ReturnedPairs int    `json:"returned_pairs"`
	PairCap       int    `json:"pair_cap"`
	PairsEvicted  uint64 `json:"pairs_evicted"`
	Partial       bool   `json:"partial"`
	// Truncated is true when limit= cut the pair list short. It is independent of
	// Partial: a limited view of a complete table is truncated but not partial.
	Truncated bool `json:"truncated"`
	// Scanned is how many stored rows a scan-source query walked. Zero for the
	// incremental source.
	Scanned int `json:"scanned,omitempty"`

	// Totals span every tracked pair, not just the returned ones, so a client can
	// say what share of the traffic the visible cells cover.
	TotalFlows uint64 `json:"total_flows"`
	TotalBytes uint64 `json:"total_bytes"`
	// MaxFlows and MaxBytes are the largest values among the *returned* pairs —
	// the heat scale for the grid.
	MaxFlows uint64 `json:"max_flows"`
	MaxBytes uint64 `json:"max_bytes"`
}

// matrix materialises the table. limit <= 0 means every tracked pair.
func (t *pairTable) matrix(limit int, ord MatrixSort, source string) Matrix {
	out := Matrix{
		Pairs:      []MatrixPair{},
		Initiators: []MatrixAxis{},
		Responders: []MatrixAxis{},
		Sort:       ord,
		Source:     source,
		PairCap:    DefaultMaxPairs,
	}
	if t == nil {
		return out
	}
	out.PairCap = t.max
	out.TrackedPairs = len(t.m)
	out.PairsEvicted = t.evicted
	out.Partial = t.evicted > 0

	type ent struct {
		k pairKey
		p *pairState
	}
	all := make([]ent, 0, len(t.m))
	for k, p := range t.m {
		all = append(all, ent{k, p})
		out.TotalFlows += p.flows
		out.TotalBytes += p.bytes()
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		switch ord {
		case MatrixSortBytes:
			if a.p.bytes() != b.p.bytes() {
				return a.p.bytes() > b.p.bytes()
			}
		case MatrixSortLastSeen:
			if !a.p.lastSeen.Equal(b.p.lastSeen) {
				return a.p.lastSeen.After(b.p.lastSeen)
			}
		}
		// Flows is both the default ordering and the tie-break for the others, so
		// every ordering ends in the same total order and is therefore stable.
		return heavier(a.k, a.p, b.k, b.p)
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
		out.Truncated = true
	}

	// Axes cover exactly the returned pairs, so the grid has no all-zero row or
	// column, and they are ordered by their own totals within that selection.
	inits := make(map[string]*MatrixAxis, len(all))
	resps := make(map[string]*MatrixAxis, len(all))
	axis := func(m map[string]*MatrixAxis, ip string, p *pairState) {
		a, ok := m[ip]
		if !ok {
			a = &MatrixAxis{IP: ip}
			m[ip] = a
		}
		a.Flows += p.flows
		a.Bytes += p.bytes()
		a.Pairs++
	}

	for _, e := range all {
		out.Pairs = append(out.Pairs, e.p.pair(e.k))
		if e.p.flows > out.MaxFlows {
			out.MaxFlows = e.p.flows
		}
		if e.p.bytes() > out.MaxBytes {
			out.MaxBytes = e.p.bytes()
		}
		axis(inits, e.k.initiator, e.p)
		axis(resps, e.k.responder, e.p)
	}
	out.ReturnedPairs = len(out.Pairs)
	out.Initiators = sortedAxis(inits)
	out.Responders = sortedAxis(resps)
	return out
}

func sortedAxis(m map[string]*MatrixAxis) []MatrixAxis {
	out := make([]MatrixAxis, 0, len(m))
	for _, a := range m {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// pair renders one cell.
func (p *pairState) pair(k pairKey) MatrixPair {
	mp := MatrixPair{
		Initiator: k.initiator, Responder: k.responder,
		Flows: p.flows, Bytes: p.bytes(),
		BytesFwd: p.bytesFwd, BytesBwd: p.bytesBwd,
		Packets:         p.packets(),
		FirstSeen:       p.firstSeen,
		LastSeen:        p.lastSeen,
		Classifications: p.classifications,
		Disagreements:   p.disagreements,
		Classes:         make([]ClassCount, 0, 2),
	}
	var domN, threatN uint64
	for i, n := range p.classes {
		if n == 0 {
			continue
		}
		mp.Classes = append(mp.Classes, ClassCount{Class: className[i], ClassID: i, Count: n})
		if n > domN {
			domN, mp.DominantClass = n, className[i]
		}
		if i != normalClassID && n > threatN {
			threatN, mp.ThreatClass = n, className[i]
		}
	}
	mp.ThreatCount = threatN
	sort.Slice(mp.Classes, func(i, j int) bool {
		if mp.Classes[i].Count != mp.Classes[j].Count {
			return mp.Classes[i].Count > mp.Classes[j].Count
		}
		return mp.Classes[i].ClassID < mp.Classes[j].ClassID
	})
	return mp
}

// Matrix returns the incrementally maintained traffic matrix. limit <= 0 means
// every tracked pair. It takes only the read lock, so it never paces the packet
// path.
func (ix *Index) Matrix(limit int, ord MatrixSort) Matrix {
	if ix == nil {
		var none *pairTable
		return none.matrix(limit, ord, "incremental")
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.pairs.matrix(limit, ord, "incremental")
}

// MatrixAccumulator folds an arbitrary, caller-filtered set of stored rows into a
// matrix on demand. It backs the filtered GET /api/v1/matrix query, which cannot
// be answered from the incremental table for the same reason a host-scoped
// timeline cannot come from the incremental ring: keeping a table per filter
// combination would be unbounded.
//
// The caller owns the filter vocabulary — this type deliberately knows nothing
// about class=, model= or min_confidence= — and applies its own bound to how many
// rows it feeds in.
type MatrixAccumulator struct {
	t       *pairTable
	scanned int
}

// NewMatrixAccumulator returns an accumulator capped at maxPairs pairs, with the
// same prune-the-lighter-half policy as the incremental table. maxPairs <= 0
// selects DefaultMaxPairs.
func NewMatrixAccumulator(maxPairs int) *MatrixAccumulator {
	if maxPairs <= 0 {
		maxPairs = DefaultMaxPairs
	}
	return &MatrixAccumulator{t: newPairTable(maxPairs)}
}

// Add folds one stored flow record and its verdict (which may be nil) into the
// matrix. It uses the identical projection and the identical volume-vs-verdict
// counting rules as the live path, so a filtered matrix and the incremental one
// are comparable.
func (a *MatrixAccumulator) Add(fr *storage.FlowRecord, cl *storage.Classification) {
	if a == nil || fr == nil {
		return
	}
	a.scanned++
	a.t.observe(observationOf(fr, cl))
}

// Matrix materialises the result. partial marks the scanned window as itself
// incomplete — the caller sets it when its row scan hit its own cap.
func (a *MatrixAccumulator) Matrix(limit int, ord MatrixSort, partial bool) Matrix {
	if a == nil {
		return NewMatrixAccumulator(0).Matrix(limit, ord, partial)
	}
	m := a.t.matrix(limit, ord, "scan")
	m.Scanned = a.scanned
	m.Partial = m.Partial || partial
	return m
}
