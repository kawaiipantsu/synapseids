package pipeline_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

const modeFixture = "../../testdata/pcap/portscan.pcap"

// modeFlowOptions is the one lifecycle configuration every side of every run in
// this file uses. Sensor and daemon must agree, or flow boundaries — and
// therefore classifications — legitimately differ.
func modeFlowOptions() flow.Options {
	return flow.Options{
		IdleTimeout: 30 * time.Second,
		MaxLifetime: 5 * time.Minute,
		MaxFlows:    10000,
	}
}

// verdict is the mode-independent identity of one classification. Flow ids are
// deliberately absent: they are daemon-local and differ between runs by design.
type verdict struct {
	Proto     string
	Initiator string
	Responder string
	Reason    string
	Class     string
	FwdPkts   uint64
	BwdPkts   uint64
	FwdBytes  uint64
	BwdBytes  uint64
}

func (v verdict) String() string {
	return fmt.Sprintf("%s %s->%s %s %s pkts=%d/%d bytes=%d/%d",
		v.Proto, v.Initiator, v.Responder, v.Reason, v.Class, v.FwdPkts, v.BwdPkts, v.FwdBytes, v.BwdBytes)
}

// runResult is everything a mode run is judged on.
type runResult struct {
	verdicts []verdict
	flows    []storage.FlowRecord
	stats    pipeline.Stats
	// wireBytes is the total SYNPOIP frame payload the daemon received.
	wireBytes uint64
	records   uint64
	packets   uint64
}

func summarize(store *storage.Mem, st pipeline.Stats) runResult {
	flows := store.RecentFlows(5000)
	byID := make(map[uint64]storage.FlowRecord, len(flows))
	for _, f := range flows {
		byID[f.ID] = f
	}
	cls := store.RecentClassifications(5000)
	out := runResult{flows: flows, stats: st, verdicts: make([]verdict, 0, len(cls))}
	for _, c := range cls {
		f := byID[c.FlowID]
		out.verdicts = append(out.verdicts, verdict{
			Proto:     c.Proto,
			Initiator: fmt.Sprintf("%s:%d", c.InitiatorIP, c.InitiatorPort),
			Responder: fmt.Sprintf("%s:%d", c.ResponderIP, c.ResponderPort),
			Reason:    f.CloseReason,
			Class:     c.Result.Class,
			FwdPkts:   f.FwdPackets, BwdPkts: f.BwdPackets,
			FwdBytes: f.FwdBytes, BwdBytes: f.BwdBytes,
		})
	}
	sort.Slice(out.verdicts, func(i, j int) bool {
		return out.verdicts[i].String() < out.verdicts[j].String()
	})
	return out
}

// localBaseline is the canonical answer: the fixture straight through the local
// pipeline, no transport involved. Its source channel closes on its own, so the
// run terminates deterministically with a final flush.
func localBaseline(t *testing.T) runResult {
	t.Helper()
	src, err := capture.OpenPCAPFile(filepath.Clean(modeFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()

	store := storage.NewMem(5000, 5000)
	bus := events.New()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	var id atomic.Uint64

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := pipeline.Run(ctx, src, rt, bus, store, pipeline.Options{
		Flow: modeFlowOptions(), Sensor: "local",
		IDGen: func() uint64 { return id.Add(1) },
	})
	if err != nil {
		t.Fatalf("baseline pipeline: %v", err)
	}
	res := summarize(store, st)
	res.packets = st.Packets
	if len(res.verdicts) == 0 {
		t.Fatal("the baseline produced no classifications — the fixture or the pipeline is broken")
	}
	return res
}

// handoffRegistrar is a SourceRegistrar that hands the registered Source to the
// test instead of a Manager, so the test can drive pipeline.Run over that one
// source directly. The source's packet channel then closes when the SYNPOIP
// session ends, which makes the run terminate on its own — no sleeping, no
// polling, and nothing that can pass before the work happened.
type handoffRegistrar struct {
	mu   sync.Mutex
	got  chan capture.Source
	rows map[string]capture.SourceMeta
	// ever keeps every meta ever registered, so an assertion can still read the
	// row after the peer disconnected and the live row was removed.
	ever map[string]capture.SourceMeta
}

func newHandoffRegistrar() *handoffRegistrar {
	return &handoffRegistrar{
		got:  make(chan capture.Source, 4),
		rows: map[string]capture.SourceMeta{},
		ever: map[string]capture.SourceMeta{},
	}
}

func (h *handoffRegistrar) Add(name string, src capture.Source, meta capture.SourceMeta) error {
	h.mu.Lock()
	h.rows[name] = meta
	h.ever[name] = meta
	h.mu.Unlock()
	h.got <- src
	return nil
}

func (h *handoffRegistrar) Remove(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.rows[name]
	delete(h.rows, name)
	return ok
}

func (h *handoffRegistrar) Get(string) (capture.SourceStatus, bool) {
	return capture.SourceStatus{}, false
}

func (h *handoffRegistrar) meta(name string) (capture.SourceMeta, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ok := h.ever[name]
	return m, ok
}

// runOverCollector streams the fixture from an in-process sensor in the given
// mode, through a real loopback TLS collector, into a real pipeline.
func runOverCollector(t *testing.T, mode pcapoverip.Mode) runResult {
	t.Helper()

	srvCert, certPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	records := make(chan pcapoverip.SensorRecord, 4096)
	col, err := capture.NewCollector(capture.CollectorConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert}},
		Token:     "mode-token",
		Records:   records,
		Logf:      t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	reg := newHandoffRegistrar()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	colDone := make(chan struct{})
	go func() {
		_ = col.Run(ctx, reg)
		close(colDone)
	}()
	addr := waitReady(t, col)

	// The sensor: dial the collector and speak the SYNPOIP server role on the
	// accepted connection (PROTOCOL.md §6), in the mode under test.
	stream, link, err := pcapoverip.PcapFileStream(filepath.Clean(modeFixture), 0)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("collector CA PEM did not parse")
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("sensor dial: %v", err)
	}

	sensorDone := make(chan struct{})
	go func() {
		defer close(sensorDone)
		pcapoverip.ServeConn(ctx, conn, pcapoverip.ServerConfig{
			Token: "mode-token", LinkType: link,
			Mode: mode, Flow: modeFlowOptions(),
			SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{
				SensorID: "edge-" + mode.String(), Location: "wan",
			}),
			Logf: t.Logf,
		}, stream)
	}()

	// Take the registered source and drive the pipeline over it. Run returns
	// when the session ends and the source closes its channel — the completion
	// signal is the thing itself, not a timer.
	var src capture.Source
	select {
	case src = <-reg.got:
	case <-time.After(20 * time.Second):
		t.Fatal("the collector never registered the sensor")
	}

	store := storage.NewMem(5000, 5000)
	bus := events.New()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	var id atomic.Uint64

	st, rerr := pipeline.Run(ctx, src, rt, bus, store, pipeline.Options{
		Flow: modeFlowOptions(), Sensor: "collector",
		IDGen:   func() uint64 { return id.Add(1) },
		Records: records,
	})
	if rerr != nil {
		t.Fatalf("%s-mode pipeline: %v", mode, rerr)
	}

	<-sensorDone
	cancel()
	<-colDone

	// The registered row must advertise the mode, so an operator can see it.
	if m, ok := reg.meta("edge-" + mode.String()); !ok {
		t.Errorf("the sensor was not registered under its sensor id")
	} else if m.Mode != mode.String() {
		t.Errorf("registered SourceMeta.Mode = %q, want %q", m.Mode, mode)
	}

	sst := src.Stats()
	res := summarize(store, st)
	res.records, res.packets = sst.Records, sst.Packets
	// Count what actually went over TLS, framing included: every frame costs a
	// 5-byte header (type + uint32 length), and a 0x01 packet frame also carries
	// an 8-byte timestamp prefix ahead of the captured bytes.
	res.wireBytes = sst.Bytes + sst.Packets*(frameHeaderBytes+packetTSBytes) +
		sst.RecordBytes + sst.Records*frameHeaderBytes
	return res
}

// SYNPOIP framing overhead, per PROTOCOL.md §3.
const (
	frameHeaderBytes = 5
	packetTSBytes    = 8
)

// TestSensorModesAgree is the strong property of issue #45: raw, flow and
// feature are transport optimisations, not behaviour changes. All three, and a
// purely local replay, must classify the same capture identically.
func TestSensorModesAgree(t *testing.T) {
	base := localBaseline(t)
	t.Logf("baseline (local replay): %d packets, %d flows, %d verdicts",
		base.packets, base.stats.Flows, len(base.verdicts))

	results := map[pcapoverip.Mode]runResult{}
	for _, mode := range []pcapoverip.Mode{pcapoverip.ModeRaw, pcapoverip.ModeFlow, pcapoverip.ModeFeature} {
		res := runOverCollector(t, mode)
		results[mode] = res

		if len(res.verdicts) != len(base.verdicts) {
			t.Fatalf("%s mode produced %d verdicts, baseline has %d",
				mode, len(res.verdicts), len(base.verdicts))
		}
		for i := range res.verdicts {
			if res.verdicts[i] != base.verdicts[i] {
				t.Errorf("%s mode verdict %d differs:\n got %s\nwant %s",
					mode, i, res.verdicts[i], base.verdicts[i])
			}
		}

		// Flow ids must be globally unique whatever entered the pipeline.
		seen := map[uint64]bool{}
		for _, f := range res.flows {
			if f.ID == 0 {
				t.Errorf("%s mode: a stored flow has id 0", mode)
			}
			if seen[f.ID] {
				t.Errorf("%s mode: flow id %d was reused", mode, f.ID)
			}
			seen[f.ID] = true
		}

		switch mode {
		case pcapoverip.ModeRaw:
			if res.records != 0 || res.packets == 0 {
				t.Errorf("raw mode: want packets>0 and records==0, got packets=%d records=%d",
					res.packets, res.records)
			}
			if res.stats.FlowRecords != 0 || res.stats.FeatureRecords != 0 {
				t.Errorf("raw mode entered the record path: %+v", res.stats)
			}
			for _, f := range res.flows {
				if f.SensorMode != "" || f.SensorFlowID != 0 {
					t.Errorf("raw mode stored remote provenance: mode=%q sensor_flow_id=%d",
						f.SensorMode, f.SensorFlowID)
				}
			}

		case pcapoverip.ModeFlow, pcapoverip.ModeFeature:
			// No frames crossed the wire at all: that is the modes' whole point.
			if res.packets != 0 {
				t.Errorf("%s mode transferred %d packets — packet content must not cross the wire", mode, res.packets)
			}
			if res.records == 0 {
				t.Fatalf("%s mode received no records", mode)
			}
			if res.stats.Packets != 0 {
				t.Errorf("%s mode fed %d packets into the flow table", mode, res.stats.Packets)
			}
			wantFlowRecs, wantFeatRecs := res.records, uint64(0)
			if mode == pcapoverip.ModeFeature {
				wantFlowRecs, wantFeatRecs = 0, res.records
			}
			if res.stats.FlowRecords != wantFlowRecs || res.stats.FeatureRecords != wantFeatRecs {
				t.Errorf("%s mode: flow_records=%d feature_records=%d, want %d/%d",
					mode, res.stats.FlowRecords, res.stats.FeatureRecords, wantFlowRecs, wantFeatRecs)
			}
			if res.stats.RecordsRejected != 0 {
				t.Errorf("%s mode rejected %d records", mode, res.stats.RecordsRejected)
			}
			// Provenance: the sensor's own id is kept, and ours is different.
			remapped := 0
			for _, f := range res.flows {
				if f.SensorMode != mode.String() {
					t.Errorf("%s mode: stored sensor_mode = %q", mode, f.SensorMode)
				}
				if f.SensorFlowID == 0 {
					t.Errorf("%s mode: flow %d lost the sensor's id", mode, f.ID)
				}
				if f.Features.FlowID != f.ID {
					t.Errorf("%s mode: vector flow_id %d != record id %d", mode, f.Features.FlowID, f.ID)
				}
				if f.SensorFlowID != f.ID {
					remapped++
				}
			}
			if remapped == 0 {
				t.Errorf("%s mode: no flow id was actually remapped — the ids happen to coincide, "+
					"so this assertion proved nothing", mode)
			}
		}
	}

	// The bandwidth story, measured rather than asserted — and reported honestly.
	//
	// A record mode's cost is per *flow*; raw's is per *packet*. Which wins is
	// therefore a property of the traffic, not of the protocol, and this fixture
	// is the worst possible case for the record modes: a SYN scan of 29 tiny
	// frames spread over 24 one-packet flows. So the assertion here is on the
	// per-record cost — the thing the design controls — and the comparison with
	// raw is logged with the break-even point that follows from it.
	raw := results[pcapoverip.ModeRaw]
	if raw.wireBytes == 0 || raw.packets == 0 {
		t.Fatal("raw mode measured nothing on the wire")
	}
	perPacket := float64(raw.wireBytes) / float64(raw.packets)

	for _, mode := range []pcapoverip.Mode{pcapoverip.ModeRaw, pcapoverip.ModeFlow, pcapoverip.ModeFeature} {
		r := results[mode]
		pct := 100 * float64(r.wireBytes) / float64(raw.wireBytes)
		line := fmt.Sprintf("%-8s wire %7d B (%6.1f%% of raw)  packets=%2d records=%2d",
			mode, r.wireBytes, pct, r.packets, r.records)
		if r.records > 0 {
			perRecord := float64(r.wireBytes) / float64(r.records)
			line += fmt.Sprintf("  %.0f B/record, break-even at %.1f packets/flow",
				perRecord, perRecord/perPacket)
		} else {
			line += fmt.Sprintf("  %.0f B/packet", perPacket)
		}
		t.Log(line)
	}

	// What the design does guarantee: a fixed, small, per-flow cost.
	const maxFlowRecordWire = 320
	const maxFeatureRecordWire = 450
	for mode, cap := range map[pcapoverip.Mode]float64{
		pcapoverip.ModeFlow:    maxFlowRecordWire,
		pcapoverip.ModeFeature: maxFeatureRecordWire,
	} {
		r := results[mode]
		if r.records == 0 {
			t.Fatalf("%s mode shipped no records", mode)
		}
		if per := float64(r.wireBytes) / float64(r.records); per > cap {
			t.Errorf("%s mode costs %.0f B/record, want <= %.0f — the fixed layout grew",
				mode, per, cap)
		}
	}
}

// TestSensorModesConcurrent runs one collector with three sensors in three
// different modes at once, into one pipeline. It is the race-detector case: the
// record path and the packet path share a goroutine, and three sessions share
// the collector's peer map and the record channel.
func TestSensorModesConcurrent(t *testing.T) {
	srvCert, certPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	records := make(chan pcapoverip.SensorRecord, 4096)
	col, err := capture.NewCollector(capture.CollectorConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert}},
		Token:     "multi",
		Records:   records,
		Logf:      t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	var connected atomic.Int64
	col.OnConnect = func(si capture.SensorInfo) {
		if si.Mode == "" {
			t.Errorf("sensor %q connected with no mode", si.SensorID)
		}
		connected.Add(1)
	}

	store := storage.NewMem(5000, 5000)
	bus := events.New()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	mgr := capture.NewManager()
	var id atomic.Uint64

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// An Observer counts records *as the pipeline classifies them*, which is the
	// only completion signal that cannot be satisfied before the work happened.
	// Waiting on sensor deregistration instead is not enough: a session is
	// deregistered when its read loop ends, which does not prove the records it
	// pushed have been taken off the channel yet.
	seen := &modeCounter{}
	pipeDone := make(chan pipeline.Stats, 1)
	go func() {
		st, _ := pipeline.Run(ctx, mgr, rt, bus, store, pipeline.Options{
			Flow: modeFlowOptions(), Sensor: "collector",
			IDGen:    func() uint64 { return id.Add(1) },
			Records:  records,
			Observer: seen,
		})
		pipeDone <- st
	}()

	colDone := make(chan struct{})
	go func() {
		_ = col.Run(ctx, mgr)
		close(colDone)
	}()
	addr := waitReady(t, col)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("CA PEM did not parse")
	}

	modes := []pcapoverip.Mode{pcapoverip.ModeRaw, pcapoverip.ModeFlow, pcapoverip.ModeFeature}
	var wg sync.WaitGroup
	for _, mode := range modes {
		wg.Add(1)
		go func(m pcapoverip.Mode) {
			defer wg.Done()
			stream, link, serr := pcapoverip.PcapFileStream(filepath.Clean(modeFixture), 0)
			if serr != nil {
				t.Errorf("%s: %v", m, serr)
				return
			}
			conn, derr := tls.Dial("tcp", addr, &tls.Config{
				ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12,
			})
			if derr != nil {
				t.Errorf("%s dial: %v", m, derr)
				return
			}
			pcapoverip.ServeConn(ctx, conn, pcapoverip.ServerConfig{
				Token: "multi", LinkType: link, Mode: m, Flow: modeFlowOptions(),
				SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{
					SensorID: "edge-" + m.String(), Location: "wan",
				}),
				Logf: t.Logf,
			}, stream)
		}(mode)
	}
	wg.Wait()

	// Every sensor has stopped *sending*. Now wait until the pipeline has
	// actually classified every record both record-mode sensors produced. The
	// fixture yields 24 flows, so the target is exact: this cannot pass before
	// the records have been processed, and a genuinely lost record makes it time
	// out rather than quietly under-count.
	const wantPerMode = 24
	deadline := time.Now().Add(20 * time.Second)
	for {
		gotFlow, gotFeat := seen.counts()
		if gotFlow >= wantPerMode && gotFeat >= wantPerMode {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pipeline classified %d flow-mode and %d feature-mode records, want %d each",
				gotFlow, gotFeat, wantPerMode)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// End the run by closing the Manager rather than cancelling the pipeline
	// context. The Manager closes its merged channel only after every forwarder
	// has drained its source, so pipeline.Run sees a clean end-of-stream, drains
	// the buffered records and runs its final flush — nothing in flight is lost.
	// Cancelling instead would race the drain and silently drop raw packets.
	_ = mgr.Close()
	st := <-pipeDone
	cancel()
	<-colDone

	if connected.Load() != int64(len(modes)) {
		t.Errorf("%d sensors connected, want %d", connected.Load(), len(modes))
	}
	if st.FlowRecords == 0 || st.FeatureRecords == 0 || st.Packets == 0 {
		t.Errorf("not every mode contributed: %+v", st)
	}

	ids := map[uint64]bool{}
	byMode := map[string]int{}
	for _, f := range store.RecentFlows(5000) {
		if ids[f.ID] {
			t.Errorf("flow id %d was reused across concurrent sensors", f.ID)
		}
		ids[f.ID] = true
		byMode[f.SensorMode]++
	}
	t.Logf("three concurrent sensors: %+v; flows by provenance: %v", st, byMode)
	if byMode[""] == 0 || byMode["flow"] == 0 || byMode["feature"] == 0 {
		t.Errorf("expected flows from all three modes, got %v", byMode)
	}
}

// modeCounter is a pipeline.Observer that tallies classified records by
// provenance. Observe runs on the pipeline goroutine, so the counters are
// updated from one place and read from the test with atomics.
type modeCounter struct {
	flow    atomic.Int64
	feature atomic.Int64
}

func (m *modeCounter) Observe(fr *storage.FlowRecord, _ *storage.Classification) {
	switch fr.SensorMode {
	case "flow":
		m.flow.Add(1)
	case "feature":
		m.feature.Add(1)
	}
}

func (m *modeCounter) counts() (flowRecs, featureRecs int64) {
	return m.flow.Load(), m.feature.Load()
}

// TestFeatureModeStoresNoInventedPacketDetail checks the honesty requirement: a
// feature-mode row reports exactly the counts flow-features-v1 encodes and is
// labelled as feature-derived, rather than defaulting fields to zero and
// implying a measurement that never crossed the wire.
func TestFeatureModeStoresNoInventedPacketDetail(t *testing.T) {
	res := runOverCollector(t, pcapoverip.ModeFeature)
	if len(res.flows) == 0 {
		t.Fatal("no flows stored")
	}
	for _, f := range res.flows {
		c := f.Features.Counts()
		if f.FwdPackets != c.FwdPackets || f.BwdPackets != c.BwdPackets ||
			f.FwdBytes != c.FwdBytes || f.BwdBytes != c.BwdBytes ||
			f.DurationSec != c.DurationSec {
			t.Errorf("flow %d's counters disagree with its own vector: row=%d/%d/%d/%d dur=%v vector=%+v",
				f.ID, f.FwdPackets, f.BwdPackets, f.FwdBytes, f.BwdBytes, f.DurationSec, c)
		}
		if f.SensorMode != "feature" {
			t.Errorf("flow %d is not labelled feature-derived", f.ID)
		}
		if f.FirstSeen.IsZero() || f.LastSeen.IsZero() {
			t.Errorf("flow %d has no wall-clock timing", f.ID)
		}
		if f.CloseReason == "" {
			t.Errorf("flow %d has no close reason", f.ID)
		}
	}
}
