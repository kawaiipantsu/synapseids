package capture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Source lifecycle states reported in SourceStatus.State.
const (
	StateRunning = "running"
	StateError   = "error"
	StateStopped = "stopped"
)

// SourceMeta is descriptive metadata the Manager keeps beside a Source for the
// capture-sources view. It never influences packet handling.
type SourceMeta struct {
	Kind   string // "nic", "replay", ...
	Filter string // human-readable current filter ("" or "(all)" = everything)
}

// SourceStatus is one row of GET /api/v1/captures (PROJECT.md §19.14).
type SourceStatus struct {
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	State         string    `json:"state"` // running | error | stopped
	Packets       uint64    `json:"packets"`
	Decoded       uint64    `json:"decoded"`
	DecodeErrors  uint64    `json:"decode_errors"`
	Bytes         uint64    `json:"bytes"`
	Drops         uint64    `json:"drops"`
	PPS           float64   `json:"pps"`
	BPS           float64   `json:"bps"`
	LastPacket    time.Time `json:"last_packet"`
	Filter        string    `json:"filter"`
	Error         string    `json:"error"`
	ConnLatencyMS int64     `json:"connection_latency_ms"` // 0 / not-applicable for a local NIC
}

type managedSource struct {
	name string
	src  Source
	meta SourceMeta

	mu       sync.Mutex
	state    string
	errText  string
	pps, bps float64
	cancel   context.CancelFunc
	// rate sampling baseline
	lastSample time.Time
	lastPkts   uint64
	lastBytes  uint64
}

// Manager runs N capture Sources concurrently and merges their packets into one
// channel. The pipeline consumes that single channel, so the single-goroutine
// flow.Table downstream is still fed from exactly one place (PROJECT.md §22,
// CLAUDE.md). A Source that errors is isolated: its status flips to "error",
// it stops contributing packets, and every other source and the pipeline keep
// running.
//
// Manager itself satisfies Source, so pipeline.Run consumes it directly.
type Manager struct {
	sampleEvery time.Duration

	mu      sync.Mutex
	order   []string
	srcs    map[string]*managedSource
	out     chan packet.Packet
	started bool
	ctx     context.Context
	cancel  context.CancelFunc

	fwg sync.WaitGroup // per-source forwarder goroutines
}

// NewManager returns an idle Manager. Add sources, then hand it to pipeline.Run
// (which calls Packets). Rates are sampled once a second.
func NewManager() *Manager { return newManager(1024, time.Second) }

func newManager(buf int, sample time.Duration) *Manager {
	return &Manager{
		sampleEvery: sample,
		srcs:        make(map[string]*managedSource),
		out:         make(chan packet.Packet, buf),
	}
}

// Add registers src under name. It may be called before Packets (the common
// case) or after (the forwarder starts immediately). Runtime removal and a
// REST-driven add are tracked for the capture-sources UI (#32).
func (m *Manager) Add(name string, src Source, meta SourceMeta) error {
	if name == "" {
		return errors.New("capture: source name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.srcs[name]; dup {
		return fmt.Errorf("capture: source %q already registered", name)
	}
	ms := &managedSource{name: name, src: src, meta: meta, state: StateStopped, lastSample: time.Now()}
	m.srcs[name] = ms
	m.order = append(m.order, name)
	if m.started {
		m.launch(ms)
	}
	return nil
}

// Remove stops and deregisters a source. It is present for #32; the daemon does
// not call it yet. Returns false if the name is unknown.
func (m *Manager) Remove(name string) bool {
	m.mu.Lock()
	ms, ok := m.srcs[name]
	if ok {
		delete(m.srcs, name)
		for i, n := range m.order {
			if n == name {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	ms.mu.Lock()
	cancel := ms.cancel
	ms.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = ms.src.Close()
	return true
}

// Packets starts every registered source and returns the merged stream. The
// error channel is the aggregate terminal channel: a single source's failure is
// recorded in its SourceStatus, never forwarded here, so it never terminates the
// pipeline. The channel closes only on full shutdown (ctx cancelled).
func (m *Manager) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	errc := make(chan error, 1)
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return m.out, errc
	}
	m.started = true
	m.ctx, m.cancel = context.WithCancel(ctx)
	for _, name := range m.order {
		m.launch(m.srcs[name])
	}
	m.mu.Unlock()

	go m.sampleLoop(errc)
	return m.out, errc
}

// launch spawns the forwarder for one source. Caller holds m.mu (or the source
// is freshly created and unpublished).
func (m *Manager) launch(ms *managedSource) {
	sctx, scancel := context.WithCancel(m.ctx)

	ms.mu.Lock()
	ms.cancel = scancel
	ms.state = StateRunning
	ms.errText = ""
	ms.lastSample = time.Now()
	ms.lastPkts, ms.lastBytes = 0, 0
	ms.mu.Unlock()

	m.fwg.Add(1)
	go func() {
		defer m.fwg.Done()
		defer scancel()

		pkts, errs := ms.src.Packets(sctx)
		drain := func() {
			for range pkts { //nolint:revive // intentional drain until the source closes its channel
			}
		}

		for {
			select {
			case <-m.ctx.Done():
				m.setState(ms, StateStopped, "")
				scancel()
				drain()
				return

			case err := <-errs:
				if err == nil || isCancel(err) {
					continue
				}
				m.setState(ms, StateError, err.Error())
				scancel()
				drain()
				return

			case p, ok := <-pkts:
				if !ok {
					m.pendingErr(ms, errs)
					return
				}
				select {
				case m.out <- p:
				case <-m.ctx.Done():
					m.setState(ms, StateStopped, "")
					scancel()
					drain()
					return
				}
			}
		}
	}()
}

// pendingErr records a terminal error the source left on errs as it closed its
// packet channel, or marks the source cleanly stopped if there was none.
func (m *Manager) pendingErr(ms *managedSource, errs <-chan error) {
	select {
	case err := <-errs:
		if err != nil && !isCancel(err) {
			m.setState(ms, StateError, err.Error())
			return
		}
	default:
	}
	m.setStateIfRunning(ms, StateStopped, "")
}

func (m *Manager) setState(ms *managedSource, state, errText string) {
	ms.mu.Lock()
	ms.state = state
	if errText != "" {
		ms.errText = errText
	}
	ms.mu.Unlock()
}

func (m *Manager) setStateIfRunning(ms *managedSource, state, errText string) {
	ms.mu.Lock()
	if ms.state == StateRunning {
		ms.state = state
		ms.errText = errText
	}
	ms.mu.Unlock()
}

// sampleLoop refreshes per-source PPS/BPS off the packet path, then closes the
// merged channel once every forwarder has exited (ctx shutdown).
func (m *Manager) sampleLoop(errc chan error) {
	t := time.NewTicker(m.sampleEvery)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			m.fwg.Wait()
			close(m.out)
			close(errc)
			return
		case now := <-t.C:
			m.sample(now)
		}
	}
}

func (m *Manager) sample(now time.Time) {
	for _, ms := range m.snapshotSources() {
		st := ms.src.Stats()
		ms.mu.Lock()
		if dt := now.Sub(ms.lastSample).Seconds(); dt > 0 {
			if st.Packets >= ms.lastPkts {
				ms.pps = float64(st.Packets-ms.lastPkts) / dt
			}
			if st.Bytes >= ms.lastBytes {
				ms.bps = float64(st.Bytes-ms.lastBytes) / dt
			}
		}
		ms.lastSample = now
		ms.lastPkts = st.Packets
		ms.lastBytes = st.Bytes
		ms.mu.Unlock()
	}
}

func (m *Manager) snapshotSources() []*managedSource {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*managedSource, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.srcs[name])
	}
	return out
}

// List returns the status of every source in registration order.
func (m *Manager) List() []SourceStatus {
	srcs := m.snapshotSources()
	out := make([]SourceStatus, 0, len(srcs))
	for _, ms := range srcs {
		out = append(out, ms.status())
	}
	return out
}

// Get returns one source's status.
func (m *Manager) Get(name string) (SourceStatus, bool) {
	m.mu.Lock()
	ms, ok := m.srcs[name]
	m.mu.Unlock()
	if !ok {
		return SourceStatus{}, false
	}
	return ms.status(), true
}

// latencyReporter is implemented by sources whose connection setup has a
// measurable cost (a TLS dial for pcap-over-ip); a local NIC does not implement
// it and connection_latency_ms stays 0.
type latencyReporter interface{ ConnLatencyMS() int64 }

// filterReporter is implemented by sources that only learn their effective
// filter after connecting (the sensor advertises it in the handshake).
type filterReporter interface{ DynamicFilter() (string, bool) }

func (ms *managedSource) status() SourceStatus {
	st := ms.src.Stats()
	ms.mu.Lock()
	ss := SourceStatus{
		Name:         ms.name,
		Kind:         ms.meta.Kind,
		State:        ms.state,
		Packets:      st.Packets,
		Decoded:      st.Decoded,
		DecodeErrors: st.DecodeErr,
		Bytes:        st.Bytes,
		Drops:        st.Drops,
		PPS:          ms.pps,
		BPS:          ms.bps,
		LastPacket:   st.LastTS,
		Filter:       ms.meta.Filter,
		Error:        ms.errText,
	}
	ms.mu.Unlock()

	if lr, ok := ms.src.(latencyReporter); ok {
		ss.ConnLatencyMS = lr.ConnLatencyMS()
	}
	if fr, ok := ms.src.(filterReporter); ok {
		if f, known := fr.DynamicFilter(); known && f != "" {
			ss.Filter = f
		}
	}
	return ss
}

// Stats reports the aggregate counters across every source, so Manager can stand
// in for a single Source (PROJECT.md §24).
func (m *Manager) Stats() Stats {
	var agg Stats
	for _, ms := range m.snapshotSources() {
		st := ms.src.Stats()
		agg.Packets += st.Packets
		agg.Decoded += st.Decoded
		agg.DecodeErr += st.DecodeErr
		agg.Bytes += st.Bytes
		agg.Drops += st.Drops
		if st.LastTS.After(agg.LastTS) {
			agg.LastTS = st.LastTS
		}
	}
	return agg
}

// Close cancels every source and waits for the forwarders to drain. Safe to call
// even if Packets was never called.
func (m *Manager) Close() error {
	m.mu.Lock()
	cancel := m.cancel
	started := m.started
	srcs := make([]*managedSource, 0, len(m.order))
	for _, name := range m.order {
		srcs = append(srcs, m.srcs[name])
	}
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var firstErr error
	for _, ms := range srcs {
		if err := ms.src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if started {
		m.fwg.Wait()
	}
	return firstErr
}

func isCancel(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
