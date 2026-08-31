// Package alert turns classifications into detections: an alert Policy
// (per-class confidence thresholds plus optional alert-on-disagreement) and a
// bounded, deduplicating Store of the recent ones (issue #117, PROJECT.md §17,
// §22; docs/adr/0027).
//
// # Why a package and not a Store index
//
// A detection is a derived, in-memory, lossy-by-design read model, exactly like
// internal/insight's host and timeline aggregates. Putting it behind
// storage.Store would force every future backend to reimplement dedup, and would
// make the packet path take the same lock a /api/v1/detections request holds
// while it serialises a thousand detections (PROJECT.md §22).
//
// # The packet path does nothing but a channel send
//
// pipeline hands each classified record to Store.Observe, which projects it into
// a small value and does one non-blocking send onto a bounded queue. A single
// aggregator goroutine drains that queue, applies the Policy, folds the
// detection, and publishes events.AlertCreated. A full queue drops the
// observation and counts it, exactly like the event bus (§17, §22, §24).
//
// # AlertCreated fires once per *new* detection
//
// A dedup increment publishes nothing. That is the whole point: a 1000-port nmap
// sweep is one detection with count=1000, one bus event and one WebSocket frame,
// not a thousand of each (§22).
//
// # Bounding
//
// Detections are built from packet-derived, therefore untrusted, data (§21,
// §28.11): a scan from a spoofed source range must not grow the process without
// limit. The retained set is a fixed-capacity ring of MaxRecent; the oldest is
// evicted first and counted, mirroring storage.Mem.
//
// Addresses are stored and returned as the plain strings storage.FlowRecord
// already holds. They are never interpolated into anything executable.
package alert

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// MaxFlowIDs caps the distinct flow ids a single detection carries: the most
// recent MaxFlowIDs of them, oldest dropped. A detection is a summary, not an
// index — the flow log remains the system of record, and Detection.Count always
// reports the true number of occurrences even when the id list has rolled.
const MaxFlowIDs = 20

// ModelVerdict is one model's contribution to a detection. It is a deliberately
// narrow projection of inference.ModelOutput: a detection explains *why it
// fired*, so it carries the per-model class and confidence and not the full
// 7-value probability vector, which the flow's classification already has.
type ModelVerdict struct {
	ModelID    string  `json:"model_id"`
	Role       string  `json:"role"`
	Class      string  `json:"class"`
	Confidence float64 `json:"confidence"`
}

// Detection is one deduplicated finding.
//
// Which occurrence each field comes from is fixed and load-bearing:
//
//   - Identity, from the FIRST occurrence: TS, FlowID, SrcPort, DstPort,
//     Protocol. The dedup key is (SrcIP, DstIP, Class) and does not include the
//     ports, so on a port scan DstPort is the first port hit, not "the" port.
//   - Recency: LastTS and FlowIDs (the newest MaxFlowIDs distinct ids — one flow
//     can contribute several occurrences, because a long-lived flow emits
//     periodic snapshot verdicts as well as a terminal one).
//   - Worst case, from the HIGHEST-CONFIDENCE occurrence: Confidence, Reason,
//     Models. Reason quotes Confidence, so the two must come from the same
//     occurrence or the sentence would be false.
//   - Aggregate: Count (every occurrence) and Disagreement (true if ANY
//     occurrence disagreed).
type Detection struct {
	ID     uint64    `json:"id"`
	TS     time.Time `json:"ts"`
	LastTS time.Time `json:"last_ts"`
	Count  uint64    `json:"count"`

	Class      string   `json:"class"`
	Severity   Severity `json:"severity"`
	Confidence float64  `json:"confidence"`

	FlowID  uint64   `json:"flow_id"`
	FlowIDs []uint64 `json:"flow_ids"`

	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`

	Disagreement bool           `json:"disagreement"`
	Reason       string         `json:"reason"`
	Models       []ModelVerdict `json:"models"`
}

// clone returns a deep copy. Readers get one because the aggregator goroutine
// keeps mutating the retained Detection in place (appending flow ids, raising
// the confidence), and a handler must not serialise a value that is changing
// underneath it.
func (d *Detection) clone() Detection {
	out := *d
	if d.FlowIDs != nil {
		out.FlowIDs = append([]uint64(nil), d.FlowIDs...)
	}
	if d.Models != nil {
		out.Models = append([]ModelVerdict(nil), d.Models...)
	}
	return out
}

// key is the dedup identity: source, destination and class. Ports are
// deliberately absent — including the destination port is what turns one nmap
// sweep into 1000 detections (docs/adr/0027).
type key struct {
	src   string
	dst   string
	class string
}

// occurrence is the compact projection of a classification that the aggregator
// needs. It carries no feature vector, so the packet path copies ~140 bytes.
//
// models is the slice header from the stored inference.Result. rt.Score builds
// that slice once per flow and nothing mutates it afterwards, so retaining the
// header is safe and keeps Observe allocation-free.
type occurrence struct {
	flowID       uint64
	ts           time.Time
	class        string
	score        float64
	disagreement bool
	srcIP        string
	dstIP        string
	srcPort      uint16
	dstPort      uint16
	proto        string
	models       []inference.ModelOutput
}

// item is one queue element: either an occurrence or a sync barrier.
type item struct {
	oc   occurrence
	done chan struct{}
}

// Options configure a Store's bounds and wiring. A zero value selects every
// default. The Policy is a separate argument to New rather than a field here,
// because a zero Policy is a *meaningful* value ("alerting off") and must not be
// silently replaced by the default.
type Options struct {
	// MaxRecent bounds the retained detections (default DefaultMaxRecent).
	MaxRecent int
	// DedupWindow is how long one key's detection keeps absorbing occurrences
	// (default DefaultDedupWindowSec seconds).
	DedupWindow time.Duration
	// QueueSize is the ingest queue depth (default DefaultQueueSize).
	QueueSize int
	// Bus, when non-nil, receives one events.AlertCreated per NEW detection.
	Bus *events.Bus
}

func (o Options) withDefaults() Options {
	if o.MaxRecent <= 0 {
		o.MaxRecent = DefaultMaxRecent
	}
	if o.DedupWindow <= 0 {
		o.DedupWindow = DefaultDedupWindowSec * time.Second
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	return o
}

// Store is the bounded, deduplicating detection store. Create it with New and
// stop it with Close. Every method is nil-receiver safe, so the daemon and the
// API can run without one.
type Store struct {
	pol  Policy
	opt  Options
	ch   chan item
	quit chan struct{}
	stop sync.Once
	wg   sync.WaitGroup

	observed atomic.Uint64
	dropped  atomic.Uint64
	// suppressed is atomic rather than lock-guarded because it is incremented
	// for the *common* case — a `normal`-adjacent verdict below threshold — and
	// taking the write lock there would make every benign flow contend with a
	// /api/v1/detections read for no reason.
	suppressed atomic.Uint64

	// mu guards everything below. Only the aggregator goroutine takes the write
	// lock; readers (the API) take the read lock. The packet path takes neither.
	mu     sync.RWMutex
	ring   []*Detection
	head   int
	full   bool
	byID   map[uint64]*Detection
	active map[key]*Detection
	nextID uint64

	created uint64
	deduped uint64
	evicted uint64
}

// New starts a Store and its aggregator goroutine. p is applied verbatim: pass
// DefaultPolicy() for the built-in thresholds, or a zero Policy to keep the
// store running with alerting switched off.
func New(p Policy, opt Options) *Store {
	opt = opt.withDefaults()
	s := &Store{
		pol:    p,
		opt:    opt,
		ch:     make(chan item, opt.QueueSize),
		quit:   make(chan struct{}),
		ring:   make([]*Detection, opt.MaxRecent),
		byID:   make(map[uint64]*Detection, opt.MaxRecent),
		active: make(map[key]*Detection),
	}
	s.wg.Add(1)
	go s.loop()
	return s
}

// Close stops the aggregator. It is safe to call more than once; Observe after
// Close is a counted drop rather than a panic.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.stop.Do(func() { close(s.quit) })
	s.wg.Wait()
	return nil
}

// Observe evaluates one classified flow against the policy. It never blocks and
// never takes a lock a reader can hold: it does a single non-blocking send onto
// the bounded ingest queue and returns. A full queue drops the observation and
// counts it (PROJECT.md §22). fr and cl are read synchronously and not retained
// beyond cl.Result.Models, which is immutable once scored.
//
// It satisfies pipeline.Observer.
func (s *Store) Observe(fr *storage.FlowRecord, cl *storage.Classification) {
	if s == nil || cl == nil {
		return
	}
	oc := occurrence{
		flowID:       cl.FlowID,
		ts:           cl.TS,
		class:        cl.Result.Class,
		score:        cl.Result.Score,
		disagreement: cl.Result.Disagreement,
		srcIP:        cl.InitiatorIP,
		dstIP:        cl.ResponderIP,
		srcPort:      cl.InitiatorPort,
		dstPort:      cl.ResponderPort,
		proto:        cl.Proto,
		models:       cl.Result.Models,
	}
	// A stored classification always carries the tuple, but a flow record built
	// by a future path might not; prefer the record when the verdict is bare.
	if oc.srcIP == "" && fr != nil {
		oc.srcIP, oc.dstIP = fr.InitiatorIP, fr.ResponderIP
		oc.srcPort, oc.dstPort, oc.proto = fr.InitiatorPort, fr.ResponderPort, fr.Proto
	}
	if oc.ts.IsZero() && fr != nil {
		oc.ts = fr.LastSeen
	}
	select {
	case s.ch <- item{oc: oc}:
	default:
		s.dropped.Add(1)
	}
}

// Sync blocks until every observation queued before the call has been applied.
// It exists for tests and the end-to-end replay check; the API never calls it,
// because a request must not be able to pace the packet path.
func (s *Store) Sync() {
	if s == nil {
		return
	}
	done := make(chan struct{})
	select {
	case s.ch <- item{done: done}:
	case <-s.quit:
		return
	}
	select {
	case <-done:
	case <-s.quit:
	}
}

func (s *Store) loop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.quit:
			return
		case it := <-s.ch:
			if it.done != nil {
				close(it.done)
				continue
			}
			s.apply(it.oc)
		}
	}
}

// apply folds one occurrence into the store. It runs on the aggregator
// goroutine and is the only writer.
//
// The bus publish deliberately happens *outside* the write lock: Bus.Publish is
// non-blocking but it walks every subscriber, and holding the write lock across
// it would let a busy fan-out delay a /api/v1/detections read for no reason.
func (s *Store) apply(oc occurrence) {
	s.observed.Add(1)

	v := s.pol.Decide(oc.class, oc.score, oc.disagreement)
	if !v.Alert {
		if s.pol.alertable(oc.class) {
			// Alertable class, below its threshold: that is a suppression an
			// operator may want to see in the counters. "normal", and a disabled
			// policy, are not.
			s.suppressed.Add(1)
		}
		return
	}

	s.mu.Lock()
	k := key{src: oc.srcIP, dst: oc.dstIP, class: oc.class}
	if d := s.active[k]; d != nil && s.withinWindow(d, oc.ts) {
		s.fold(d, oc, v)
		s.deduped++
		s.mu.Unlock()
		return // no event: a dedup increment must not wake the WebSocket (§22)
	}
	d := s.open(k, oc, v)
	published := d.clone()
	s.mu.Unlock()

	if s.opt.Bus != nil {
		s.opt.Bus.Publish(events.AlertCreated, published)
	}
}

// withinWindow reports whether ts still falls inside d's dedup window.
//
// The window is anchored at the detection's FIRST occurrence, not slid forward
// on every hit. A sliding window would collapse a sustained attack into a single
// detection that never alerts again; anchoring means a long brute force produces
// one detection per window — a handful for a sweep, not a thousand, and not one
// that goes quiet after the first packet (docs/adr/0027).
//
// The clock is the record's own timestamp (packet time), not wall clock, so a
// `--speed max` replay dedups exactly as live capture would (PROJECT.md §26). A
// timestamp before d.TS (clock skew between sensors, an out-of-order record) is
// treated as in-window: re-opening a detection because a record arrived late
// would be worse than absorbing it.
func (s *Store) withinWindow(d *Detection, ts time.Time) bool {
	if ts.IsZero() {
		return true
	}
	return !ts.After(d.TS.Add(s.opt.DedupWindow))
}

// fold absorbs a repeat occurrence into an existing detection. Caller holds the
// write lock.
func (s *Store) fold(d *Detection, oc occurrence, v Verdict) {
	d.Count++
	if oc.ts.After(d.LastTS) {
		d.LastTS = oc.ts
	}
	if oc.disagreement {
		d.Disagreement = true
	}
	if oc.score > d.Confidence {
		// The worst case seen, and the explanation that goes with it.
		d.Confidence = oc.score
		d.Reason = v.Reason
		d.Models = modelVerdicts(oc.models)
	}
	// FlowIDs is a set of flows, Count is a count of verdicts, and the two
	// genuinely differ: a long-lived flow emits periodic snapshot verdicts and
	// then a terminal one, so one flow can occur several times. Counting it twice
	// is correct; listing it twice would just be a confusing "affected flows"
	// list. The scan is over at most MaxFlowIDs entries.
	for _, id := range d.FlowIDs {
		if id == oc.flowID {
			return
		}
	}
	if len(d.FlowIDs) >= MaxFlowIDs {
		copy(d.FlowIDs, d.FlowIDs[1:])
		d.FlowIDs = d.FlowIDs[:MaxFlowIDs-1]
	}
	d.FlowIDs = append(d.FlowIDs, oc.flowID)
}

// open creates a detection for k and installs it in the ring, evicting the
// oldest retained detection if the ring is full. Caller holds the write lock.
func (s *Store) open(k key, oc occurrence, v Verdict) *Detection {
	s.nextID++
	d := &Detection{
		ID:           s.nextID,
		TS:           oc.ts,
		LastTS:       oc.ts,
		Count:        1,
		Class:        oc.class,
		Severity:     v.Severity,
		Confidence:   oc.score,
		FlowID:       oc.flowID,
		FlowIDs:      []uint64{oc.flowID},
		SrcIP:        oc.srcIP,
		DstIP:        oc.dstIP,
		SrcPort:      oc.srcPort,
		DstPort:      oc.dstPort,
		Protocol:     oc.proto,
		Disagreement: oc.disagreement,
		Reason:       v.Reason,
		Models:       modelVerdicts(oc.models),
	}

	if old := s.ring[s.head]; old != nil {
		delete(s.byID, old.ID)
		if cur, ok := s.active[keyOf(old)]; ok && cur == old {
			delete(s.active, keyOf(old))
		}
		s.evicted++
	}
	s.ring[s.head] = d
	s.head = (s.head + 1) % len(s.ring)
	if s.head == 0 {
		s.full = true
	}
	s.byID[d.ID] = d
	s.active[k] = d
	s.created++
	return d
}

func keyOf(d *Detection) key {
	return key{src: d.SrcIP, dst: d.DstIP, class: d.Class}
}

// modelVerdicts projects the per-model outputs. It allocates on the aggregator
// goroutine, never on the packet path.
func modelVerdicts(ms []inference.ModelOutput) []ModelVerdict {
	if len(ms) == 0 {
		return nil
	}
	out := make([]ModelVerdict, 0, len(ms))
	for _, m := range ms {
		out = append(out, ModelVerdict{
			ModelID:    m.ModelID,
			Role:       string(m.Role),
			Class:      m.Class,
			Confidence: m.Score,
		})
	}
	return out
}

// Query is the GET /api/v1/detections filter set. A zero value (with Limit set)
// matches everything.
type Query struct {
	// Limit caps the returned detections. <= 0 means "no cap".
	Limit int
	// Class, when set, must be a traffic-classes-v1 class name.
	Class string
	// Severity, when set, must be one of Severities().
	Severity Severity
	// MinConfidence applies only when HasMinConfidence is true, so an explicit
	// min_confidence=0 is not the same as an absent one.
	MinConfidence    float64
	HasMinConfidence bool
	// Since, when non-zero, keeps detections whose LastTS is at or after it —
	// "active since", not "first seen since", so an ongoing detection that
	// started before the bound is still reported.
	Since time.Time
}

func (q Query) match(d *Detection) bool {
	if q.Class != "" && d.Class != q.Class {
		return false
	}
	if q.Severity != "" && d.Severity != q.Severity {
		return false
	}
	if q.HasMinConfidence && d.Confidence < q.MinConfidence {
		return false
	}
	if !q.Since.IsZero() && d.LastTS.Before(q.Since) {
		return false
	}
	return true
}

// Page is the GET /api/v1/detections response.
type Page struct {
	Detections []Detection `json:"detections"`
	// Total is how many retained detections matched the filter before Limit.
	Total int `json:"total"`
	// Returned is len(Detections).
	Returned int `json:"returned"`
	// Evicted is the lifetime count of detections dropped by the MaxRecent
	// bound. Non-zero means the list is a recent window, not a complete history.
	Evicted uint64 `json:"evicted"`
}

// Detections returns the matching detections, most recently active first
// (LastTS descending, ties broken by descending id so the order is stable).
//
// The result is always a fresh, non-nil slice of deep copies.
func (s *Store) Detections(q Query) Page {
	if s == nil {
		return Page{Detections: []Detection{}}
	}
	s.mu.RLock()
	out := make([]Detection, 0, 64)
	n := len(s.ring)
	if !s.full {
		n = s.head
	}
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + len(s.ring)) % len(s.ring)
		d := s.ring[idx]
		if d == nil || !q.match(d) {
			continue
		}
		out = append(out, d.clone())
	}
	evicted := s.evicted
	s.mu.RUnlock()

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].LastTS.Equal(out[j].LastTS) {
			return out[i].LastTS.After(out[j].LastTS)
		}
		return out[i].ID > out[j].ID
	})

	total := len(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return Page{Detections: out, Total: total, Returned: len(out), Evicted: evicted}
}

// Detection returns one retained detection by id.
func (s *Store) Detection(id uint64) (Detection, bool) {
	if s == nil {
		return Detection{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byID[id]
	if !ok {
		return Detection{}, false
	}
	return d.clone(), true
}

// Stats are the counters surfaced on /api/v1/status under "alerts".
type Stats struct {
	Enabled bool `json:"enabled"`
	// Created counts new detections (== events.AlertCreated published).
	Created uint64 `json:"created"`
	// Deduped counts occurrences absorbed into an existing detection. No event
	// was published for any of them.
	Deduped uint64 `json:"deduped"`
	// Suppressed counts alertable verdicts that did not clear their threshold.
	Suppressed uint64 `json:"suppressed"`
	// Evicted counts detections dropped by the MaxRecent bound.
	Evicted uint64 `json:"evicted"`

	Retained  int    `json:"retained"`
	MaxRecent int    `json:"max_recent"`
	Observed  uint64 `json:"observed"`
	// Dropped counts observations the ingest queue could not accept. Non-zero
	// means the aggregator fell behind the packet path and some verdicts were
	// never evaluated (PROJECT.md §22, §24).
	Dropped        uint64 `json:"dropped"`
	QueueSize      int    `json:"queue_size"`
	DedupWindowSec int    `json:"dedup_window_sec"`
}

// Stats returns a counter snapshot.
func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.ring)
	if !s.full {
		n = s.head
	}
	return Stats{
		Enabled:        s.pol.Enabled,
		Created:        s.created,
		Deduped:        s.deduped,
		Suppressed:     s.suppressed.Load(),
		Evicted:        s.evicted,
		Retained:       n,
		MaxRecent:      len(s.ring),
		Observed:       s.observed.Load(),
		Dropped:        s.dropped.Load(),
		QueueSize:      s.opt.QueueSize,
		DedupWindowSec: int(s.opt.DedupWindow / time.Second),
	}
}
