// Package insight maintains bounded, incrementally-updated aggregates over the
// classified flow stream: observed-host profiles (PROJECT.md §19.5) and the
// classification timeline (§19.6). It is the read model behind Investigation
// mode (§19.4).
//
// # Why this is a package and not a Store index
//
// The aggregates are a derived, in-memory, lossy-by-design view. Putting them
// behind storage.Store would force every future backend (SQLite, ClickHouse) to
// reimplement them, and would make the packet path take the same lock that a
// /api/v1/hosts request holds while it serialises hundreds of profiles
// (PROJECT.md §22). Instead the pipeline hands each classified flow record to
// Index.Observe, which does one non-blocking channel send and returns. A single
// aggregator goroutine drains the queue and owns every map, so the ingest path
// never contends on the read lock. A full queue drops observations and counts
// them, exactly like the event bus (§17, §22, §24).
//
// # Bounding
//
// Every structure here is fed by packet-derived, therefore untrusted, data
// (§21, §28.11): a scan against 65535 ports or a spoofed source range must not
// grow the process without limit. The host map, the per-host top-N key sets, the
// per-host recent-flow ring and the timeline rings are all capped, and each
// eviction is counted and reported through Stats.
//
// Host addresses are stored and returned as plain strings, exactly as
// netip.Addr rendered them. They are never interpolated into anything
// executable; the API emits them as JSON string values.
package insight

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Defaults for Options. They are deliberately modest: the aggregates are an
// operator convenience, not a system of record, and a busy sensor must not be
// able to turn them into an allocation problem.
const (
	// DefaultMaxHosts caps the number of tracked host profiles. When the map
	// exceeds it, the least-recently-active quarter is dropped in one pass
	// (amortised O(1) per insert) and counted in Stats.HostsEvicted.
	DefaultMaxHosts = 2048
	// DefaultMaxKeys caps the distinct ports and distinct peers tracked per
	// host. On overflow the lowest-count half is discarded, so the top-N lists
	// stay correct for heavy hitters and become approximate for long tails
	// (a port scan is exactly such a tail). Discards are counted in
	// Stats.KeysPruned.
	DefaultMaxKeys = 128
	// DefaultRecentFlows caps the per-host recent-flow ring.
	DefaultRecentFlows = 16
	// DefaultQueueSize is the depth of the ingest queue between the packet path
	// and the aggregator goroutine.
	DefaultQueueSize = 8192
)

// Timeline resolutions. Each is a separate fixed-width ring updated on every
// observation; together they cost ~120 KB.
const (
	bucket1s  = 1
	bucket10s = 10
	bucket1m  = 60

	ring1sLen  = 900  // 15 minutes at 1s
	ring10sLen = 720  // 2 hours at 10s
	ring1mLen  = 1440 // 24 hours at 1m
)

// className maps a traffic-classes-v1 index to its name once, at init.
var className [inference.OutputSize]string

func init() {
	for _, c := range schema.TrafficClassesV1().Classes {
		if c.Index >= 0 && c.Index < len(className) {
			className[c.Index] = c.Name
		}
	}
}

// ClassName returns the traffic-classes-v1 name for an index, or "" if the
// index is out of range.
func ClassName(id int) string {
	if id < 0 || id >= len(className) {
		return ""
	}
	return className[id]
}

// Options configure an Index. A zero value selects every default.
type Options struct {
	MaxHosts    int
	MaxKeys     int
	RecentFlows int
	QueueSize   int
	// MaxPairs caps the traffic matrix's tracked (initiator, responder) pairs.
	// See matrix.go for why this is a bounded top-N rather than a full matrix.
	MaxPairs int
}

func (o Options) withDefaults() Options {
	if o.MaxPairs <= 0 {
		o.MaxPairs = DefaultMaxPairs
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = DefaultMaxHosts
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = DefaultMaxKeys
	}
	if o.RecentFlows <= 0 {
		o.RecentFlows = DefaultRecentFlows
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	return o
}

// observation is the compact projection of a classified flow record that the
// aggregator needs. The pipeline builds one per record; it deliberately does not
// carry the 48-value feature vector, so the queue element stays small and the
// packet path copies ~120 bytes rather than ~500.
type observation struct {
	flowID        uint64
	terminal      bool // false for a periodic mid-flow snapshot record
	proto         string
	initiatorIP   string
	initiatorPort uint16
	responderIP   string
	responderPort uint16
	firstSeen     time.Time
	lastSeen      time.Time
	ts            time.Time
	packetsFwd    uint64
	packetsBwd    uint64
	bytesFwd      uint64
	bytesBwd      uint64
	classID       int
	disagreement  bool
}

// item is one queue element: either an observation or a sync barrier.
type item struct {
	ob   observation
	done chan struct{}
}

// Index is the live aggregate. Create it with New and stop it with Close.
type Index struct {
	opt  Options
	ch   chan item
	quit chan struct{}
	stop sync.Once
	wg   sync.WaitGroup

	observed atomic.Uint64
	dropped  atomic.Uint64

	// mu guards everything below. Only the aggregator goroutine takes the write
	// lock; readers (the API) take the read lock. The packet path takes neither.
	mu           sync.RWMutex
	hosts        map[string]*host
	hostsEvicted uint64
	keysPruned   uint64
	rings        []*ring
	// pairs is the bounded traffic matrix (issue #68). See matrix.go.
	pairs *pairTable
}

// New starts an Index and its aggregator goroutine.
func New(opt Options) *Index {
	opt = opt.withDefaults()
	ix := &Index{
		opt:   opt,
		ch:    make(chan item, opt.QueueSize),
		quit:  make(chan struct{}),
		hosts: make(map[string]*host),
		pairs: newPairTable(opt.MaxPairs),
		rings: []*ring{
			newRing(bucket1s, ring1sLen),
			newRing(bucket10s, ring10sLen),
			newRing(bucket1m, ring1mLen),
		},
	}
	ix.wg.Add(1)
	go ix.loop()
	return ix
}

// Close stops the aggregator. It is safe to call more than once; Observe after
// Close is a counted drop rather than a panic.
func (ix *Index) Close() error {
	ix.stop.Do(func() { close(ix.quit) })
	ix.wg.Wait()
	return nil
}

// Observe records one classified flow record. It never blocks and never takes a
// lock a reader can hold: it does a single non-blocking send onto the bounded
// ingest queue. When the queue is full the observation is dropped and counted
// (PROJECT.md §22). fr and cl are read synchronously and not retained.
//
// A nil Index is a no-op, so the pipeline can run without one.
func (ix *Index) Observe(fr *storage.FlowRecord, cl *storage.Classification) {
	if ix == nil || fr == nil {
		return
	}
	ob := observationOf(fr, cl)
	select {
	case ix.ch <- item{ob: ob}:
	default:
		ix.dropped.Add(1)
	}
}

// observationOf projects a stored record and its verdict into the compact form
// the aggregates fold. It is deliberately shared between the live path (Observe)
// and the on-demand traffic-matrix accumulator in matrix.go, so a filtered matrix
// and the incremental one apply identical rules. It allocates nothing: every
// field is a scalar, a string header or a time.Time copied by value.
func observationOf(fr *storage.FlowRecord, cl *storage.Classification) observation {
	ob := observation{
		flowID:        fr.ID,
		terminal:      fr.CloseReason != "snapshot",
		proto:         fr.Proto,
		initiatorIP:   fr.InitiatorIP,
		initiatorPort: fr.InitiatorPort,
		responderIP:   fr.ResponderIP,
		responderPort: fr.ResponderPort,
		firstSeen:     fr.FirstSeen,
		lastSeen:      fr.LastSeen,
		ts:            fr.LastSeen,
		packetsFwd:    fr.FwdPackets,
		packetsBwd:    fr.BwdPackets,
		bytesFwd:      fr.FwdBytes,
		bytesBwd:      fr.BwdBytes,
		classID:       -1,
	}
	if cl != nil {
		ob.ts = cl.TS
		ob.classID = cl.Result.ClassID
		ob.disagreement = cl.Result.Disagreement
	}
	return ob
}

// Sync blocks until every observation queued before the call has been applied.
// It exists for tests and for the end-to-end replay check; the API never calls
// it, because a request must not be able to pace the packet path.
func (ix *Index) Sync() {
	if ix == nil {
		return
	}
	done := make(chan struct{})
	select {
	case ix.ch <- item{done: done}:
	case <-ix.quit:
		return
	}
	select {
	case <-done:
	case <-ix.quit:
	}
}

func (ix *Index) loop() {
	defer ix.wg.Done()
	for {
		select {
		case <-ix.quit:
			return
		case it := <-ix.ch:
			if it.done != nil {
				close(it.done)
				continue
			}
			ix.apply(it.ob)
		}
	}
}

// apply folds one observation into the aggregates. It runs on the aggregator
// goroutine and is the only writer.
func (ix *Index) apply(ob observation) {
	ix.observed.Add(1)
	ix.mu.Lock()
	defer ix.mu.Unlock()

	// Timeline: every verdict counts, including the periodic snapshot verdicts,
	// because that is what /api/v1/classifications contains.
	if ob.classID >= 0 {
		for _, r := range ix.rings {
			r.add(ob.ts, ob.classID, ob.disagreement)
		}
	}

	if ob.initiatorIP != "" {
		ix.hostOf(ob.initiatorIP).observe(ob, true, ix)
	}
	if ob.responderIP != "" && ob.responderIP != ob.initiatorIP {
		ix.hostOf(ob.responderIP).observe(ob, false, ix)
	}

	// The traffic matrix (issue #68). One map lookup plus scalar adds; the pair
	// cap and its eviction counter live in matrix.go.
	ix.pairs.observe(ob)
}

// hostOf returns the host state for ip, creating it and pruning the map if the
// cap is exceeded. Caller holds the write lock.
func (ix *Index) hostOf(ip string) *host {
	if h, ok := ix.hosts[ip]; ok {
		return h
	}
	if len(ix.hosts) >= ix.opt.MaxHosts {
		ix.pruneHosts()
	}
	h := &host{
		ip:     ip,
		protos: make(map[string]uint64, 4),
		ports:  newCounter[uint16](ix.opt.MaxKeys),
		peers:  newCounter[string](ix.opt.MaxKeys),
		recent: make([]flowRef, 0, ix.opt.RecentFlows),
	}
	ix.hosts[ip] = h
	return h
}

// pruneHosts drops the least-recently-active quarter of the host map in a single
// pass. Doing it in batches keeps the amortised cost per new host at O(1) rather
// than O(MaxHosts). Caller holds the write lock.
func (ix *Index) pruneHosts() {
	keep := ix.opt.MaxHosts - ix.opt.MaxHosts/4
	if keep < 1 {
		keep = 1
	}
	type ent struct {
		ip   string
		last int64
	}
	all := make([]ent, 0, len(ix.hosts))
	for ip, h := range ix.hosts {
		all = append(all, ent{ip, h.lastSeen.UnixNano()})
	}
	// Newest-active first; everything past `keep` goes.
	sort.Slice(all, func(i, j int) bool {
		if all[i].last != all[j].last {
			return all[i].last > all[j].last
		}
		return all[i].ip < all[j].ip
	})
	for _, e := range all[min(keep, len(all)):] {
		delete(ix.hosts, e.ip)
		ix.hostsEvicted++
	}
}

// Stats reports the aggregator's counters, including everything it had to throw
// away (PROJECT.md §24).
type Stats struct {
	Hosts        int    `json:"hosts"`
	HostCap      int    `json:"host_cap"`
	HostsEvicted uint64 `json:"hosts_evicted"`
	KeyCap       int    `json:"key_cap"`
	KeysPruned   uint64 `json:"keys_pruned"`
	Observed     uint64 `json:"observed"`
	Dropped      uint64 `json:"dropped"`
	QueueSize    int    `json:"queue_size"`
	TimelineLate uint64 `json:"timeline_late"`

	// Traffic-matrix counters (issue #68). PairsEvicted > 0 means the matrix is a
	// bounded top-N of the heaviest conversations rather than a complete one, and
	// every /api/v1/matrix response says so with partial:true.
	Pairs        int    `json:"pairs"`
	PairCap      int    `json:"pair_cap"`
	PairsEvicted uint64 `json:"pairs_evicted"`
}

// Stats returns a counter snapshot.
func (ix *Index) Stats() Stats {
	if ix == nil {
		return Stats{}
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	var late uint64
	for _, r := range ix.rings {
		late += r.late
	}
	return Stats{
		Hosts:        len(ix.hosts),
		HostCap:      ix.opt.MaxHosts,
		HostsEvicted: ix.hostsEvicted,
		KeyCap:       ix.opt.MaxKeys,
		KeysPruned:   ix.keysPruned,
		Observed:     ix.observed.Load(),
		Dropped:      ix.dropped.Load(),
		QueueSize:    ix.opt.QueueSize,
		TimelineLate: late,
		Pairs:        len(ix.pairs.m),
		PairCap:      ix.pairs.max,
		PairsEvicted: ix.pairs.evicted,
	}
}

// ---------------------------------------------------------------- host state

// flowRef is a compact pointer back into the flow store for the profile's
// recent-flow list. The full record (including its feature vector) is resolved
// on demand via storage.Store.Flow, so the profile never duplicates it.
type flowRef struct {
	id      uint64
	ts      time.Time
	proto   string
	peer    string
	port    uint16
	bytes   uint64
	classID int
}

type host struct {
	ip                   string
	firstSeen, lastSeen  time.Time
	flows                uint64
	initiated, responded uint64
	packetsIn            uint64
	packetsOut           uint64
	bytesIn              uint64
	bytesOut             uint64
	protos               map[string]uint64
	ports                *counter[uint16]
	peers                *counter[string]
	classes              [inference.OutputSize]uint64
	classifications      uint64
	disagreements        uint64

	recent     []flowRef
	recentHead int
}

// observe folds one side of a flow into this host. asInitiator selects which
// direction is "out".
//
// Volume and flow counts come only from terminal records: a long flow emits
// periodic snapshots carrying cumulative counters, so adding those too would
// double-count. Classification counts come from every record, snapshot verdicts
// included, which keeps a host's class mix consistent with
// /api/v1/classifications.
func (h *host) observe(ob observation, asInitiator bool, ix *Index) {
	if h.firstSeen.IsZero() || ob.firstSeen.Before(h.firstSeen) {
		h.firstSeen = ob.firstSeen
	}
	if ob.lastSeen.After(h.lastSeen) {
		h.lastSeen = ob.lastSeen
	}

	if ob.classID >= 0 {
		h.classifications++
		if ob.classID < len(h.classes) {
			h.classes[ob.classID]++
		}
		if ob.disagreement {
			h.disagreements++
		}
	}

	if !ob.terminal {
		return
	}

	h.flows++
	h.protos[ob.proto]++
	if len(h.protos) > ix.opt.MaxKeys {
		// Protocol names come from the decoder's fixed set, so this is a
		// belt-and-braces bound rather than an expected path.
		for k := range h.protos {
			delete(h.protos, k)
			ix.keysPruned++
			break
		}
	}

	peer := ob.responderIP
	if !asInitiator {
		peer = ob.initiatorIP
		h.responded++
		h.bytesIn += ob.bytesFwd
		h.bytesOut += ob.bytesBwd
		h.packetsIn += ob.packetsFwd
		h.packetsOut += ob.packetsBwd
	} else {
		h.initiated++
		h.bytesOut += ob.bytesFwd
		h.bytesIn += ob.bytesBwd
		h.packetsOut += ob.packetsFwd
		h.packetsIn += ob.packetsBwd
	}

	// The tracked port is the conversation's service port (the responder side):
	// for an initiator that is "a port I connected to", for a responder "a port
	// I served".
	ix.keysPruned += h.ports.add(ob.responderPort)
	if peer != "" {
		ix.keysPruned += h.peers.add(peer)
	}

	ref := flowRef{
		id: ob.flowID, ts: ob.lastSeen, proto: ob.proto,
		peer: peer, port: ob.responderPort,
		bytes: ob.bytesFwd + ob.bytesBwd, classID: ob.classID,
	}
	if len(h.recent) < cap(h.recent) {
		h.recent = append(h.recent, ref)
		return
	}
	h.recent[h.recentHead] = ref
	h.recentHead = (h.recentHead + 1) % len(h.recent)
}

// recentNewestFirst returns up to n refs, newest first.
func (h *host) recentNewestFirst(n int) []flowRef {
	if n <= 0 || len(h.recent) == 0 {
		return nil
	}
	if n > len(h.recent) {
		n = len(h.recent)
	}
	head := h.recentHead
	if len(h.recent) < cap(h.recent) {
		head = len(h.recent) // not yet wrapped: newest is the last appended
	}
	out := make([]flowRef, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, h.recent[(head-1-i+len(h.recent))%len(h.recent)])
	}
	return out
}

// ------------------------------------------------------- bounded top-N counter

// counter counts occurrences of a bounded number of distinct keys. When the key
// set overflows its cap, the lowest-count half is discarded: heavy hitters
// survive, long tails (a port scan's 60000 one-hit ports) do not. Discards are
// returned so the Index can report them.
type counter[K comparable] struct {
	m   map[K]uint64
	cap int
}

func newCounter[K comparable](capacity int) *counter[K] {
	if capacity < 2 {
		capacity = 2
	}
	return &counter[K]{m: make(map[K]uint64, 8), cap: capacity}
}

// add increments k and returns the number of keys discarded to make room.
func (c *counter[K]) add(k K) uint64 {
	var pruned uint64
	if _, ok := c.m[k]; !ok && len(c.m) >= c.cap {
		pruned = c.prune()
	}
	c.m[k]++
	return pruned
}

// prune keeps the top half by count and drops the rest.
func (c *counter[K]) prune() uint64 {
	keep := c.cap / 2
	counts := make([]uint64, 0, len(c.m))
	for _, n := range c.m {
		counts = append(counts, n)
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i] > counts[j] })
	cut := counts[min(keep, len(counts)-1)]
	var dropped uint64
	for k, n := range c.m {
		if n <= cut && len(c.m)-int(dropped) > keep {
			delete(c.m, k)
			dropped++
		}
	}
	return dropped
}

type kv[K comparable] struct {
	key K
	n   uint64
}

// top returns the n highest-count keys, count descending. Ties are broken by a
// stable per-key ordering supplied by less so results are deterministic.
func (c *counter[K]) top(n int, less func(a, b K) bool) []kv[K] {
	out := make([]kv[K], 0, len(c.m))
	for k, v := range c.m {
		out = append(out, kv[K]{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return less(out[i].key, out[j].key)
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// -------------------------------------------------------------- timeline ring

type tbucket struct {
	ts       int64 // bucket start, unix seconds; 0 means "never written"
	total    uint32
	byClass  [inference.OutputSize]uint32
	disagree uint32
}

// ring is a fixed-width, fixed-length bucket ring. Slot reuse is the eviction
// policy: writing a newer bucket into a slot discards whatever older bucket
// occupied it, and a read only trusts a slot whose ts matches the bucket it is
// asking for, so stale slots read as zero.
type ring struct {
	width  int64
	buf    []tbucket
	newest int64 // ts of the newest bucket written, 0 if empty
	late   uint64
}

func newRing(width int64, n int) *ring {
	return &ring{width: width, buf: make([]tbucket, n)}
}

func (r *ring) add(ts time.Time, classID int, disagree bool) {
	if ts.IsZero() {
		return
	}
	sec := ts.Unix()
	b := sec - mod(sec, r.width)
	idx := int(mod(sec/r.width, int64(len(r.buf))))
	slot := &r.buf[idx]
	switch {
	case slot.ts == b:
		// accumulate below
	case b > slot.ts:
		*slot = tbucket{ts: b}
	default:
		// The slot already holds a newer bucket: this sample is older than the
		// ring's window for that slot and cannot be represented.
		r.late++
		return
	}
	slot.total++
	if classID >= 0 && classID < len(slot.byClass) {
		slot.byClass[classID]++
	}
	if disagree {
		slot.disagree++
	}
	if b > r.newest {
		r.newest = b
	}
}

// mod is a non-negative modulo (Go's % keeps the sign of the dividend, and
// pre-1970 or negative-clock timestamps must not index out of range).
func mod(a, m int64) int64 {
	v := a % m
	if v < 0 {
		v += m
	}
	return v
}

// series reads a dense bucket range out of the ring. from/to are inclusive
// bucket-start bounds in unix seconds; zero means "unbounded".
//
// An unbounded `from` resolves to the oldest non-empty bucket still in the ring,
// not to the start of the ring's window: a 1m ring covers 24 h, and a caller
// that asks for "everything" wants the data, not 1400 leading zeroes. Between
// that point and the newest bucket the series is dense, so a gap is an explicit
// zero rather than a missing x value.
func (r *ring) series(from, to int64) []Bucket {
	if r.newest == 0 {
		return []Bucket{}
	}
	span := int64(len(r.buf)) * r.width
	windowLo := r.newest - span + r.width
	lo := r.newest
	hi := r.newest
	for _, s := range r.buf {
		if s.ts >= windowLo && s.ts < lo {
			lo = s.ts
		}
	}
	if from != 0 {
		lo = from - mod(from, r.width)
		if lo < windowLo {
			lo = windowLo
		}
	}
	if to != 0 && to < hi {
		hi = to - mod(to, r.width)
	}
	if hi < lo {
		return []Bucket{}
	}
	n := int((hi-lo)/r.width) + 1
	if n > len(r.buf) {
		n = len(r.buf)
		lo = hi - int64(n-1)*r.width
	}
	out := make([]Bucket, 0, n)
	for b := lo; b <= hi; b += r.width {
		slot := r.buf[int(mod(b/r.width, int64(len(r.buf))))]
		out = append(out, bucketOf(b, slot))
	}
	return out
}

func bucketOf(b int64, slot tbucket) Bucket {
	out := Bucket{TS: time.Unix(b, 0).UTC()}
	if slot.ts != b {
		out.ByClass = map[string]uint32{}
		return out
	}
	out.Total = slot.total
	out.Disagreements = slot.disagree
	out.ByClass = make(map[string]uint32, 2)
	for i, n := range slot.byClass {
		if n > 0 {
			out.ByClass[className[i]] = n
		}
	}
	return out
}

// ------------------------------------------------------------------ read side

// ProtoCount is one protocol and the number of flows seen with it.
type ProtoCount struct {
	Proto string `json:"proto"`
	Flows uint64 `json:"flows"`
}

// PortCount is one service port and the number of flows seen on it.
type PortCount struct {
	Port  uint16 `json:"port"`
	Flows uint64 `json:"flows"`
}

// PeerCount is one peer address and the number of flows shared with it.
type PeerCount struct {
	IP    string `json:"ip"`
	Flows uint64 `json:"flows"`
}

// ClassCount is one traffic class and how many of this host's verdicts chose it.
type ClassCount struct {
	Class   string `json:"class"`
	ClassID int    `json:"class_id"`
	Count   uint64 `json:"count"`
}

// FlowRef points at a stored flow record. The caller resolves the full record
// (and its feature vector) through storage.Store.Flow if it needs one.
type FlowRef struct {
	FlowID uint64    `json:"flow_id"`
	TS     time.Time `json:"ts"`
	Proto  string    `json:"proto"`
	Peer   string    `json:"peer"`
	Port   uint16    `json:"port"`
	Bytes  uint64    `json:"bytes"`
	Class  string    `json:"class,omitempty"`
}

// Profile is an observed host (PROJECT.md §19.5). The list endpoint returns
// shallow profiles (short top-N lists, no peers, no recent flows); the detail
// endpoint fills everything in.
//
// BaselineAvailable and AnomalyAvailable are always false in Phase 5: behavioural
// baselines and anomaly trend need the Phase 7 anomaly/drift work, and this
// package will not invent them (PROJECT.md §13, §19.5).
type Profile struct {
	IP              string       `json:"ip"`
	FirstSeen       time.Time    `json:"first_seen"`
	LastSeen        time.Time    `json:"last_seen"`
	Flows           uint64       `json:"flows"`
	FlowsInitiated  uint64       `json:"flows_initiated"`
	FlowsResponded  uint64       `json:"flows_responded"`
	PacketsIn       uint64       `json:"packets_in"`
	PacketsOut      uint64       `json:"packets_out"`
	BytesIn         uint64       `json:"bytes_in"`
	BytesOut        uint64       `json:"bytes_out"`
	Protocols       []ProtoCount `json:"protocols"`
	TopPorts        []PortCount  `json:"top_ports"`
	TopPeers        []PeerCount  `json:"top_peers,omitempty"`
	Classifications uint64       `json:"classifications"`
	Classes         []ClassCount `json:"classes"`
	Disagreements   uint64       `json:"disagreements"`
	RecentFlows     []FlowRef    `json:"recent_flows,omitempty"`

	BaselineAvailable bool `json:"baseline_available"`
	AnomalyAvailable  bool `json:"anomaly_available"`
}

// depth controls how much of a profile is materialised.
type depth struct {
	ports  int
	peers  int
	recent int
}

var (
	shallow = depth{ports: 5, peers: 0, recent: 0}
	full    = depth{ports: 16, peers: 16, recent: DefaultRecentFlows}
)

func (h *host) profile(d depth) Profile {
	p := Profile{
		IP:              h.ip,
		FirstSeen:       h.firstSeen,
		LastSeen:        h.lastSeen,
		Flows:           h.flows,
		FlowsInitiated:  h.initiated,
		FlowsResponded:  h.responded,
		PacketsIn:       h.packetsIn,
		PacketsOut:      h.packetsOut,
		BytesIn:         h.bytesIn,
		BytesOut:        h.bytesOut,
		Classifications: h.classifications,
		Disagreements:   h.disagreements,
		Protocols:       make([]ProtoCount, 0, len(h.protos)),
		TopPorts:        make([]PortCount, 0, d.ports),
		Classes:         make([]ClassCount, 0, len(h.classes)),
	}
	for name, n := range h.protos {
		p.Protocols = append(p.Protocols, ProtoCount{Proto: name, Flows: n})
	}
	sort.Slice(p.Protocols, func(i, j int) bool {
		if p.Protocols[i].Flows != p.Protocols[j].Flows {
			return p.Protocols[i].Flows > p.Protocols[j].Flows
		}
		return p.Protocols[i].Proto < p.Protocols[j].Proto
	})
	for _, e := range h.ports.top(d.ports, func(a, b uint16) bool { return a < b }) {
		p.TopPorts = append(p.TopPorts, PortCount{Port: e.key, Flows: e.n})
	}
	if d.peers > 0 {
		p.TopPeers = make([]PeerCount, 0, d.peers)
		for _, e := range h.peers.top(d.peers, func(a, b string) bool { return a < b }) {
			p.TopPeers = append(p.TopPeers, PeerCount{IP: e.key, Flows: e.n})
		}
	}
	for i, n := range h.classes {
		if n > 0 {
			p.Classes = append(p.Classes, ClassCount{Class: className[i], ClassID: i, Count: n})
		}
	}
	for _, r := range h.recentNewestFirst(d.recent) {
		p.RecentFlows = append(p.RecentFlows, FlowRef{
			FlowID: r.id, TS: r.ts, Proto: r.proto, Peer: r.peer,
			Port: r.port, Bytes: r.bytes, Class: ClassName(r.classID),
		})
	}
	return p
}

// Sort orders the host list.
type Sort string

// Host list orderings.
const (
	SortLastSeen Sort = "last_seen"
	SortFlows    Sort = "flows"
	SortBytes    Sort = "bytes"
)

// ParseSort validates a sort= parameter. An empty value means SortLastSeen.
func ParseSort(s string) (Sort, bool) {
	switch Sort(s) {
	case "":
		return SortLastSeen, true
	case SortLastSeen, SortFlows, SortBytes:
		return Sort(s), true
	}
	return "", false
}

// Hosts returns shallow profiles, ordered by ord, optionally filtered to
// addresses containing the substring q. limit <= 0 means "all tracked hosts".
func (ix *Index) Hosts(q string, ord Sort, limit int) []Profile {
	if ix == nil {
		return []Profile{}
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()

	out := make([]Profile, 0, min(len(ix.hosts), max(limit, 16)))
	for ip, h := range ix.hosts {
		if q != "" && !strings.Contains(ip, q) {
			continue
		}
		out = append(out, h.profile(shallow))
	}
	sortProfiles(out, ord)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortProfiles(p []Profile, ord Sort) {
	sort.Slice(p, func(i, j int) bool {
		a, b := p[i], p[j]
		switch ord {
		case SortFlows:
			if a.Flows != b.Flows {
				return a.Flows > b.Flows
			}
		case SortBytes:
			if a.BytesIn+a.BytesOut != b.BytesIn+b.BytesOut {
				return a.BytesIn+a.BytesOut > b.BytesIn+b.BytesOut
			}
		case SortLastSeen:
			if !a.LastSeen.Equal(b.LastSeen) {
				return a.LastSeen.After(b.LastSeen)
			}
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.IP < b.IP
	})
}

// Host returns the full profile for one address.
func (ix *Index) Host(ip string) (Profile, bool) {
	if ix == nil {
		return Profile{}, false
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	h, ok := ix.hosts[ip]
	if !ok {
		return Profile{}, false
	}
	return h.profile(full), true
}

// Bucket is one time slice of the classification timeline. Anomaly scores are
// Phase 7 and deliberately absent — see Series.AnomalyAvailable.
type Bucket struct {
	TS            time.Time         `json:"ts"`
	Total         uint32            `json:"total"`
	ByClass       map[string]uint32 `json:"by_class"`
	Disagreements uint32            `json:"disagreements"`
}

// Series is a bucketed classification timeline (PROJECT.md §19.6).
type Series struct {
	BucketSec int      `json:"bucket_sec"`
	Buckets   []Bucket `json:"buckets"`
	// AnomalyAvailable is always false until the Phase 7 anomaly model lands.
	// The field exists so a client can label the gap instead of plotting a
	// fabricated zero line.
	AnomalyAvailable bool `json:"anomaly_available"`
}

// ValidBucketSec reports whether n is one of the supported bucket widths.
func ValidBucketSec(n int) bool {
	return n == bucket1s || n == bucket10s || n == bucket1m
}

// ParseBucket maps a bucket= parameter ("1s", "10s", "1m") to its width in
// seconds. An empty value means 1s.
func ParseBucket(s string) (int, bool) {
	switch s {
	case "", "1s":
		return bucket1s, true
	case "10s":
		return bucket10s, true
	case "1m", "60s":
		return bucket1m, true
	}
	return 0, false
}

// Timeline returns the incrementally-maintained global series at the given
// bucket width. from/to are inclusive bounds; a zero time means "the ring's own
// window".
func (ix *Index) Timeline(bucketSec int, from, to time.Time) Series {
	s := Series{BucketSec: bucketSec, Buckets: []Bucket{}}
	if ix == nil {
		return s
	}
	var lo, hi int64
	if !from.IsZero() {
		lo = from.Unix()
	}
	if !to.IsZero() {
		hi = to.Unix()
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	for _, r := range ix.rings {
		if int(r.width) == bucketSec {
			s.Buckets = r.series(lo, hi)
			break
		}
	}
	return s
}

// BucketSamples buckets an arbitrary slice of verdicts on demand. It backs the
// host-scoped and class-filtered timeline, which cannot come from the global
// ring: keeping a ring per host would be unbounded, so a scoped series is
// computed from the newest window of stored classifications instead. The result
// is dense over the observed range and ordered oldest first.
func BucketSamples(rows []storage.Classification, bucketSec int, from, to time.Time, keep func(storage.Classification) bool) Series {
	s := Series{BucketSec: bucketSec, Buckets: []Bucket{}}
	if bucketSec <= 0 {
		return s
	}
	w := int64(bucketSec)
	agg := make(map[int64]*tbucket)
	var lo, hi int64
	for _, c := range rows {
		if keep != nil && !keep(c) {
			continue
		}
		if c.TS.IsZero() {
			continue
		}
		if !from.IsZero() && c.TS.Before(from) {
			continue
		}
		if !to.IsZero() && c.TS.After(to) {
			continue
		}
		sec := c.TS.Unix()
		b := sec - mod(sec, w)
		t, ok := agg[b]
		if !ok {
			t = &tbucket{ts: b}
			agg[b] = t
			if lo == 0 || b < lo {
				lo = b
			}
			if b > hi {
				hi = b
			}
		}
		t.total++
		if id := c.Result.ClassID; id >= 0 && id < len(t.byClass) {
			t.byClass[id]++
		}
		if c.Result.Disagreement {
			t.disagree++
		}
	}
	if len(agg) == 0 {
		return s
	}
	// Cap the dense expansion so a wide from/to cannot allocate without bound.
	const maxBuckets = ring1mLen
	if n := (hi-lo)/w + 1; n > maxBuckets {
		lo = hi - (maxBuckets-1)*w
	}
	for b := lo; b <= hi; b += w {
		if t, ok := agg[b]; ok {
			s.Buckets = append(s.Buckets, bucketOf(b, *t))
		} else {
			s.Buckets = append(s.Buckets, bucketOf(b, tbucket{}))
		}
	}
	return s
}
