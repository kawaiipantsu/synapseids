package storage

import "sync"

// Mem is an in-memory Store backed by fixed-capacity ring buffers. Oldest records
// are overwritten and counted as evicted (PROJECT.md §20, §22).
type Mem struct {
	mu sync.RWMutex

	flows     []FlowRecord
	flowHead  int
	flowFull  bool
	byID      map[uint64]FlowRecord
	flowEvict uint64

	cls         []Classification
	clsHead     int
	clsFull     bool
	clsEvict    uint64
	clsDisagree uint64
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
		flows: make([]FlowRecord, flowCap),
		byID:  make(map[uint64]FlowRecord, flowCap),
		cls:   make([]Classification, classCap),
	}
}

// PutFlow stores a flow record, evicting the oldest if the ring is full.
func (m *Mem) PutFlow(r FlowRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flowFull {
		old := m.flows[m.flowHead]
		if cur, ok := m.byID[old.ID]; ok && cur.SnapshotIndex == old.SnapshotIndex {
			delete(m.byID, old.ID)
		}
		m.flowEvict++
	}
	m.flows[m.flowHead] = r
	m.byID[r.ID] = r
	m.flowHead = (m.flowHead + 1) % len(m.flows)
	if m.flowHead == 0 {
		m.flowFull = true
	}
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
	r, ok := m.byID[id]
	return r, ok
}

// RecentFlows returns up to limit flow records, newest first.
func (m *Mem) RecentFlows(limit int) []FlowRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return collect(m.flows, m.flowHead, m.flowFull, limit)
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
		Flows:           ringLen(m.flowHead, m.flowFull, len(m.flows)),
		Classifications: ringLen(m.clsHead, m.clsFull, len(m.cls)),
		FlowsEvicted:    m.flowEvict,
		ClassEvicted:    m.clsEvict,
		Disagreements:   m.clsDisagree,
		Driver:          "memory",
	}
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
