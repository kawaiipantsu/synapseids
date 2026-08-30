package flow

import (
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Options configure a Table's lifecycle timers.
type Options struct {
	IdleTimeout      time.Duration
	MaxLifetime      time.Duration
	SnapshotInterval time.Duration // 0 disables periodic snapshots
	MaxFlows         int           // 0 means unbounded (not recommended)

	// IDGen allocates globally-unique flow IDs. When nil the Table uses a
	// per-instance counter starting at 1, which is fine for a single run but
	// collides across runs — the daemon passes a shared allocator.
	IDGen func() uint64
}

// Stats reports Table activity since construction.
type Stats struct {
	Active    int
	Started   uint64
	Closed    uint64
	Snapshots uint64
	Evicted   uint64
}

type entry struct {
	Record
	lastFwdTS, lastBwdTS time.Time
	finFromInit          bool
	finFromResp          bool
	rst                  bool
	nextSnapshotAt       time.Time
}

// graceWindow is how long a key stays in the recently-closed set after a
// FIN/RST teardown so trailing ACKs do not spawn a phantom one-packet flow.
const graceWindow = 3 * time.Second

// Table accumulates packets into flows and emits Records via onFlow. It is not
// safe for concurrent use: feed it from a single goroutine (PROJECT.md §22).
type Table struct {
	opt        Options
	flows      map[Key]*entry
	recentDown map[Key]time.Time
	nextID     uint64
	stats      Stats
	onFlow     func(Record)
}

// NewTable returns a Table that calls onFlow for every snapshot and every closed
// flow.
func NewTable(opt Options, onFlow func(Record)) *Table {
	return &Table{
		flows:      make(map[Key]*entry),
		recentDown: make(map[Key]time.Time),
		opt:        opt,
		onFlow:     onFlow,
	}
}

// Stats returns a counter snapshot.
func (t *Table) Stats() Stats {
	s := t.stats
	s.Active = len(t.flows)
	return s
}

// Observe folds one packet into its flow, creating the flow if needed and
// closing it if this packet completes a TCP teardown.
func (t *Table) Observe(p packet.Packet) {
	k, fwdFromA := KeyOf(p)
	e := t.flows[k]
	if e == nil {
		// Absorb the TIME_WAIT tail: a non-SYN packet arriving just after a
		// FIN/RST teardown belongs to the flow that just closed, not a new one.
		if down, ok := t.recentDown[k]; ok {
			isSYN := p.Proto == packet.ProtoTCP && p.TCPFlags&packet.FlagSYN != 0
			if p.TS.Sub(down) < graceWindow && !isSYN {
				return
			}
			delete(t.recentDown, k)
		}
		e = t.open(k, p, fwdFromA)
	}

	forward := t.isForward(e, p, fwdFromA)
	t.fold(e, p, forward)

	if p.Proto == packet.ProtoTCP {
		if p.TCPFlags&packet.FlagRST != 0 {
			e.rst = true
		}
		if p.TCPFlags&packet.FlagFIN != 0 {
			if forward {
				e.finFromInit = true
			} else {
				e.finFromResp = true
			}
		}
		if e.rst || (e.finFromInit && e.finFromResp) {
			t.emit(k, e, ReasonFINRST)
			delete(t.flows, k)
			t.recentDown[k] = p.TS
			t.stats.Closed++
		}
	}
}

func (t *Table) open(k Key, p packet.Packet, fwdFromA bool) *entry {
	var id uint64
	if t.opt.IDGen != nil {
		id = t.opt.IDGen()
	} else {
		t.nextID++
		id = t.nextID
	}
	t.stats.Started++

	initIP, initPort := p.SrcIP, p.SrcPort
	respIP, respPort := p.DstIP, p.DstPort
	// A bare SYN identifies the initiator regardless of packet order.
	if p.Proto == packet.ProtoTCP && p.TCPFlags&packet.FlagSYN != 0 && p.TCPFlags&packet.FlagACK != 0 {
		initIP, initPort = p.DstIP, p.DstPort
		respIP, respPort = p.SrcIP, p.SrcPort
	}
	_ = fwdFromA

	e := &entry{Record: Record{
		ID:            id,
		Key:           k,
		InitiatorIP:   initIP,
		InitiatorPort: initPort,
		ResponderIP:   respIP,
		ResponderPort: respPort,
		Proto:         p.Proto,
		FirstSeen:     p.TS,
		LastSeen:      p.TS,
		PktSizeMin:    p.TotalLen,
		PktSizeMax:    p.TotalLen,
	}}
	if p.Proto == packet.ProtoTCP {
		e.InitialWindow = uint32(p.TCPWindow)
	}
	if t.opt.SnapshotInterval > 0 {
		e.nextSnapshotAt = p.TS.Add(t.opt.SnapshotInterval)
	}
	t.flows[k] = e

	if t.opt.MaxFlows > 0 && len(t.flows) > t.opt.MaxFlows {
		t.evictOldest()
	}
	return e
}

// isForward reports whether p travels initiator->responder for flow e.
func (t *Table) isForward(e *entry, p packet.Packet, fwdFromA bool) bool {
	if p.SrcIP == e.InitiatorIP && p.SrcPort == e.InitiatorPort {
		return true
	}
	if p.SrcIP == e.ResponderIP && p.SrcPort == e.ResponderPort {
		return false
	}
	// ICMP or a rewritten port: fall back to tuple orientation.
	return fwdFromA
}

func (t *Table) fold(e *entry, p packet.Packet, forward bool) {
	size := float64(p.TotalLen)
	e.pktSizeSum += size
	e.pktSizeSumSq += size * size
	if p.TotalLen < e.PktSizeMin {
		e.PktSizeMin = p.TotalLen
	}
	if p.TotalLen > e.PktSizeMax {
		e.PktSizeMax = p.TotalLen
	}
	if p.TotalLen <= 100 {
		e.SmallPkts++
	}
	if p.TotalLen >= 1000 {
		e.LargePkts++
	}

	// Global inter-arrival.
	if !e.LastSeen.IsZero() && p.TS.After(e.LastSeen) {
		gap := p.TS.Sub(e.LastSeen).Seconds()
		e.iatSum += gap
		e.iatSumSq += gap * gap
		if e.iatCount == 0 || gap < e.iatMin {
			e.iatMin = gap
		}
		if gap > e.iatMax {
			e.iatMax = gap
		}
		e.iatCount++
	}
	if p.TS.After(e.LastSeen) {
		e.LastSeen = p.TS
	}

	if forward {
		e.FwdPackets++
		e.FwdBytes += uint64(p.TotalLen)
		e.FwdPayload += uint64(p.PayloadLen)
		e.fwdSizeSum += size
		if !e.lastFwdTS.IsZero() && p.TS.After(e.lastFwdTS) {
			e.fwdIATSum += p.TS.Sub(e.lastFwdTS).Seconds()
			e.fwdIATCount++
		}
		e.lastFwdTS = p.TS
	} else {
		e.BwdPackets++
		e.BwdBytes += uint64(p.TotalLen)
		e.BwdPayload += uint64(p.PayloadLen)
		e.bwdSizeSum += size
		if !e.lastBwdTS.IsZero() && p.TS.After(e.lastBwdTS) {
			e.bwdIATSum += p.TS.Sub(e.lastBwdTS).Seconds()
			e.bwdIATCount++
		}
		e.lastBwdTS = p.TS
	}

	if p.Proto == packet.ProtoTCP {
		f := p.TCPFlags
		if f&packet.FlagSYN != 0 {
			e.SynCount++
		}
		if f&packet.FlagACK != 0 {
			e.AckCount++
		}
		if f&packet.FlagFIN != 0 {
			e.FinCount++
		}
		if f&packet.FlagRST != 0 {
			e.RstCount++
		}
		if f&packet.FlagPSH != 0 {
			e.PshCount++
		}
		if f&packet.FlagURG != 0 {
			e.UrgCount++
		}
		e.windowSum += float64(p.TCPWindow)
		e.windowCount++
	}
}

// Tick sweeps the table for idle / over-age flows and due snapshots. Call it
// periodically with a monotonically non-decreasing now (e.g. the latest packet
// timestamp).
func (t *Table) Tick(now time.Time) {
	for k, ts := range t.recentDown {
		if now.Sub(ts) >= graceWindow {
			delete(t.recentDown, k)
		}
	}
	for k, e := range t.flows {
		if t.opt.MaxLifetime > 0 && now.Sub(e.FirstSeen) >= t.opt.MaxLifetime {
			t.emit(k, e, ReasonMaxLife)
			delete(t.flows, k)
			t.stats.Closed++
			continue
		}
		if t.opt.IdleTimeout > 0 && now.Sub(e.LastSeen) >= t.opt.IdleTimeout {
			t.emit(k, e, ReasonIdle)
			delete(t.flows, k)
			t.stats.Closed++
			continue
		}
		if t.opt.SnapshotInterval > 0 && !e.nextSnapshotAt.IsZero() && !now.Before(e.nextSnapshotAt) {
			e.SnapshotIndex++
			t.emitSnapshot(e)
			e.nextSnapshotAt = now.Add(t.opt.SnapshotInterval)
		}
	}
}

// Flush closes every remaining flow (capture ended).
func (t *Table) Flush() {
	for k, e := range t.flows {
		t.emit(k, e, ReasonCapEnd)
		delete(t.flows, k)
		t.stats.Closed++
	}
}

func (t *Table) evictOldest() {
	var oldestKey Key
	var oldest *entry
	for k, e := range t.flows {
		if oldest == nil || e.LastSeen.Before(oldest.LastSeen) {
			oldestKey, oldest = k, e
		}
	}
	if oldest == nil {
		return
	}
	t.emit(oldestKey, oldest, ReasonEvicted)
	delete(t.flows, oldestKey)
	t.stats.Evicted++
	t.stats.Closed++
}

func (t *Table) emit(_ Key, e *entry, reason CloseReason) {
	rec := e.Record
	rec.Reason = reason
	if t.onFlow != nil {
		t.onFlow(rec)
	}
}

func (t *Table) emitSnapshot(e *entry) {
	rec := e.Record
	rec.Reason = ReasonSnapshot
	t.stats.Snapshots++
	if t.onFlow != nil {
		t.onFlow(rec)
	}
}
