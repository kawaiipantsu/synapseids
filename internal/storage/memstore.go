package storage

import (
	"sync"
	"time"
)

// FlowHistoryCap bounds how many versions of a *single* flow the store keeps —
// the periodic ReasonSnapshot records a long-lived flow emits plus its terminal
// record (PROJECT.md §7, §19.3). Beyond the cap the flow's oldest retained
// version is dropped and counted in Stats.FlowVersionsDropped.
//
// This is the *per-flow* bound only. The global bound is still the flow ring
// itself: every retained version corresponds to exactly one live ring slot, so
// the total number of versions held can never exceed the ring capacity no matter
// how many flows snapshot. At the default snapshot_interval of 60s a flow has to
// stay open for over an hour to reach this cap.
const FlowHistoryCap = 64

// Mem is an in-memory Store backed by fixed-capacity ring buffers. Oldest records
// are overwritten and counted as evicted (PROJECT.md §20, §22).
type Mem struct {
	mu sync.RWMutex

	flows     []flowVersion
	flowHead  int
	flowFull  bool
	flowSeq   uint64
	hist      map[uint64][]flowVersion
	flowEvict uint64
	verDrop   uint64

	flowExpire uint64

	cls         []Classification
	clsHead     int
	clsFull     bool
	clsEvict    uint64
	clsExpire   uint64
	clsDisagree uint64
}

// flowVersion is one stored version of a flow, tagged with a monotonic sequence
// number assigned at PutFlow time.
//
// The sequence number — not SnapshotIndex — is what identifies a version.
// flow.Table increments SnapshotIndex on the *live* entry, so a long flow's
// terminal record inherits the last snapshot's index; two versions of one flow
// can therefore share a SnapshotIndex and it cannot be used as an identity.
type flowVersion struct {
	seq uint64
	rec FlowRecord
}

// NewMem returns a Mem with the given capacities (each floored at 1).
func NewMem(flowCap, classCap int) *Mem {
	if flowCap < 1 {
		flowCap = 1
	}
	if classCap < 1 {
		classCap = 1
	}
	return &Mem{
		flows: make([]flowVersion, flowCap),
		hist:  make(map[uint64][]flowVersion, flowCap),
		cls:   make([]Classification, classCap),
	}
}

// PutFlow stores a flow record, evicting the oldest if the ring is full. Each
// call appends a new *version* of the flow rather than replacing the previous
// one, so a long-lived flow's snapshot history is retained (bounded by
// FlowHistoryCap per flow, and by the ring globally).
func (m *Mem) PutFlow(r FlowRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.flowFull {
		m.dropVersion(m.flows[m.flowHead])
		m.flowEvict++
	}

	m.flowSeq++
	v := flowVersion{seq: m.flowSeq, rec: r}

	h := m.hist[r.ID]
	if len(h) >= FlowHistoryCap {
		// Per-flow cap: drop this flow's oldest retained version. Its ring slot
		// stays put; dropVersion tolerates the miss when that slot is evicted.
		copy(h, h[1:])
		h = h[:len(h)-1]
		m.verDrop++
	}
	m.hist[r.ID] = append(h, v)

	m.flows[m.flowHead] = v
	m.flowHead = (m.flowHead + 1) % len(m.flows)
	if m.flowHead == 0 {
		m.flowFull = true
	}
}

// dropVersion removes v from its flow's history when v is still the oldest
// version retained for that flow.
//
// The ring evicts strictly in PutFlow order and each flow's history is appended
// in that same order, so the version leaving the ring is always the oldest one
// still retained for its flow — unless FlowHistoryCap already dropped it, in
// which case the sequence numbers do not match and there is nothing to do.
// Caller holds m.mu.
func (m *Mem) dropVersion(v flowVersion) {
	h := m.hist[v.rec.ID]
	if len(h) == 0 || h[0].seq != v.seq {
		return
	}
	if len(h) == 1 {
		delete(m.hist, v.rec.ID)
		return
	}
	copy(h, h[1:])
	m.hist[v.rec.ID] = h[:len(h)-1]
}

// PutClassification stores a verdict, evicting the oldest if the ring is full.
func (m *Mem) PutClassification(c Classification) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clsFull {
		m.clsEvict++
	}
	if c.Result.Disagreement {
		m.clsDisagree++
	}
	m.cls[m.clsHead] = c
	m.clsHead = (m.clsHead + 1) % len(m.cls)
	if m.clsHead == 0 {
		m.clsFull = true
	}
}

// Flow returns the most recent stored version of a flow by ID.
func (m *Mem) Flow(id uint64) (FlowRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h := m.hist[id]
	if len(h) == 0 {
		return FlowRecord{}, false
	}
	return h[len(h)-1].rec, true
}

// FlowHistory returns every retained version of a flow, oldest first. The result
// is a fresh slice the caller may keep.
func (m *Mem) FlowHistory(id uint64) []FlowRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h := m.hist[id]
	if len(h) == 0 {
		return nil
	}
	out := make([]FlowRecord, len(h))
	for i, v := range h {
		out[i] = v.rec
	}
	return out
}

// RecentFlows returns up to limit flow records, newest first.
func (m *Mem) RecentFlows(limit int) []FlowRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vs := collect(m.flows, m.flowHead, m.flowFull, limit)
	out := make([]FlowRecord, len(vs))
	for i, v := range vs {
		out[i] = v.rec
	}
	return out
}

// RecentClassifications returns up to limit verdicts, newest first.
func (m *Mem) RecentClassifications(limit int) []Classification {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return collect(m.cls, m.clsHead, m.clsFull, limit)
}

// Stats returns counters.
func (m *Mem) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Stats{
		Flows:               ringLen(m.flowHead, m.flowFull, len(m.flows)),
		Classifications:     ringLen(m.clsHead, m.clsFull, len(m.cls)),
		FlowsEvicted:        m.flowEvict,
		ClassEvicted:        m.clsEvict,
		FlowVersionsDropped: m.verDrop,
		Disagreements:       m.clsDisagree,
		FlowsExpired:        m.flowExpire,
		ClassExpired:        m.clsExpire,
		Driver:              "memory",
	}
}

// PurgeBefore drops stored records older than the given per-category cutoffs and
// returns how many of each it removed (issue #56). A zero-value cutoff skips
// that category. A flow *version* is judged by its record's LastSeen, so a
// long-lived flow keeps its recent snapshots while its stale early ones age out;
// a classification by its TS.
//
// The rings cannot hold gaps, so each affected ring is compacted: the surviving
// records are re-laid newest-first and the head/full state reset. The per-flow
// history map is filtered in step. flowSeq is never rewound, so the
// dropVersion seq-match invariant still holds for records the ring later evicts.
func (m *Mem) PurgeBefore(flowsBefore, classificationsBefore time.Time) (flows, classifications int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !flowsBefore.IsZero() {
		flows = m.purgeFlows(flowsBefore)
		m.flowExpire += uint64(flows)
	}
	if !classificationsBefore.IsZero() {
		classifications = m.purgeClassifications(classificationsBefore)
		m.clsExpire += uint64(classifications)
	}
	return flows, classifications
}

// purgeFlows rebuilds the flow ring and history map without the versions whose
// record LastSeen is before cutoff. Caller holds m.mu.
func (m *Mem) purgeFlows(cutoff time.Time) int {
	kept := collect(m.flows, m.flowHead, m.flowFull, 0) // newest-first
	dropped := 0
	live := kept[:0]
	for _, v := range kept {
		if v.rec.LastSeen.Before(cutoff) {
			dropped++
			continue
		}
		live = append(live, v)
	}
	if dropped == 0 {
		return 0
	}

	// Re-lay the ring oldest-first so a subsequent PutFlow evicts in the right
	// order, and reset the ring bookkeeping.
	for i := range m.flows {
		m.flows[i] = flowVersion{}
	}
	for i := len(live) - 1; i >= 0; i-- {
		m.flows[len(live)-1-i] = live[i]
	}
	m.flowHead = len(live) % len(m.flows)
	m.flowFull = len(live) == len(m.flows)

	// Filter each flow's history to the versions still live in the ring.
	liveSeq := make(map[uint64]struct{}, len(live))
	for _, v := range live {
		liveSeq[v.seq] = struct{}{}
	}
	for id, h := range m.hist {
		out := h[:0]
		for _, v := range h {
			if _, ok := liveSeq[v.seq]; ok {
				out = append(out, v)
			}
		}
		if len(out) == 0 {
			delete(m.hist, id)
		} else {
			m.hist[id] = out
		}
	}
	return dropped
}

// purgeClassifications rebuilds the classification ring without verdicts older
// than cutoff. Caller holds m.mu.
func (m *Mem) purgeClassifications(cutoff time.Time) int {
	kept := collect(m.cls, m.clsHead, m.clsFull, 0) // newest-first
	live := kept[:0]
	dropped := 0
	for _, c := range kept {
		if c.TS.Before(cutoff) {
			dropped++
			continue
		}
		live = append(live, c)
	}
	if dropped == 0 {
		return 0
	}
	for i := range m.cls {
		m.cls[i] = Classification{}
	}
	for i := len(live) - 1; i >= 0; i-- {
		m.cls[len(live)-1-i] = live[i]
	}
	m.clsHead = len(live) % len(m.cls)
	m.clsFull = len(live) == len(m.cls)
	return dropped
}

// Close is a no-op for the memory store.
func (m *Mem) Close() error { return nil }

func ringLen(head int, full bool, size int) int {
	if full {
		return size
	}
	return head
}

func collect[T any](buf []T, head int, full bool, limit int) []T {
	n := ringLen(head, full, len(buf))
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]T, 0, limit)
	// Walk backwards from the most recently written slot.
	for i := 0; i < limit; i++ {
		idx := (head - 1 - i + len(buf)) % len(buf)
		out = append(out, buf[idx])
	}
	return out
}
