package capture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

const portscanPCAP = "../../testdata/pcap/portscan.pcap"

// collectorHarness stands up a Collector on 127.0.0.1:0 backed by a real,
// started capture.Manager whose packets are counted, plus the CA the test
// "sensors" verify the collector against.
type collectorHarness struct {
	col        *Collector
	mgr        *Manager
	addr       string
	caPEM      []byte
	packets    *atomic.Int64
	connects   *atomic.Int64
	disconnAll *atomic.Int64
	cancel     context.CancelFunc
	runDone    chan struct{}
}

func newCollectorHarness(t *testing.T, cfg CollectorConfig) *collectorHarness {
	t.Helper()

	srvCert, certPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert}}
	}
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	// Bind a port ourselves, then close and hand the address to the Collector so
	// Run's tls.Listen picks the same free port on loopback.
	cfg.Listen = "127.0.0.1:0"

	col, err := NewCollector(cfg)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}

	h := &collectorHarness{
		col: col, caPEM: certPEM,
		packets: new(atomic.Int64), connects: new(atomic.Int64), disconnAll: new(atomic.Int64),
		runDone: make(chan struct{}),
	}
	col.OnConnect = func(SensorInfo) { h.connects.Add(1) }
	col.OnDisconnect = func(SensorInfo) { h.disconnAll.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	h.mgr = NewManager()
	pkts, _ := h.mgr.Packets(ctx)
	go func() {
		for range pkts {
			h.packets.Add(1)
		}
	}()

	// Let Run bind an ephemeral port itself and read the address back through
	// the Collector's own Addr(). Binding here, closing, and handing the freed
	// port to Run is a TOCTOU: under a loaded whole-tree run another listener
	// can claim it in the gap.
	go func() {
		_ = col.Run(ctx, h.mgr)
		close(h.runDone)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-h.runDone:
		case <-time.After(3 * time.Second):
			t.Error("collector Run did not return after cancel")
		}
		_ = h.mgr.Close()
	})

	// Wait for Run to publish the bound address. No probe dial: a probe would
	// log a spurious "handshake failed: EOF" and briefly occupy a sensor slot.
	waitFor(t, "collector listener up", func() bool { return col.Addr() != "" })
	h.addr = col.Addr()
	return h
}

func (h *collectorHarness) clientTLS(t *testing.T, clientCert ...tls.Certificate) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.caPEM) {
		t.Fatal("ca PEM did not parse")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", RootCAs: pool}
	if len(clientCert) > 0 {
		cfg.Certificates = clientCert
	}
	return cfg
}

// runSensor dials the collector and serves the SYNPOIP sensor side (ServeConn),
// exactly as `synapse-sensor pcap-over-ip --connect` does. It returns when the
// stream ends or ctx is cancelled.
func runSensor(t *testing.T, ctx context.Context, addr string, tlsCfg *tls.Config, srvCfg pcapoverip.ServerConfig, stream pcapoverip.StreamFunc) error {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	pcapoverip.ServeConn(ctx, conn, srvCfg, stream)
	return nil
}

func portscanStream(t *testing.T) (pcapoverip.StreamFunc, uint32) {
	t.Helper()
	stream, link, err := pcapoverip.PcapFileStream(filepath.Clean(portscanPCAP), 0)
	if err != nil {
		t.Fatalf("PcapFileStream: %v", err)
	}
	return stream, link
}

// blockingStream emits nothing and stays open until ctx is cancelled — a sensor
// that holds its slot without ending the capture.
func blockingStream(ctx context.Context) (<-chan pcapoverip.Record, <-chan error) {
	rec := make(chan pcapoverip.Record)
	errc := make(chan error, 1)
	go func() {
		<-ctx.Done()
		close(rec)
	}()
	return rec, errc
}

// heldStream forwards every record from inner, then — instead of closing and
// triggering an end-of-capture goodbye — holds the session open until ctx is
// cancelled. It lets a test observe a sensor while it is still connected.
func heldStream(inner pcapoverip.StreamFunc) pcapoverip.StreamFunc {
	return func(ctx context.Context) (<-chan pcapoverip.Record, <-chan error) {
		in, _ := inner(ctx)
		out := make(chan pcapoverip.Record)
		errc := make(chan error, 1)
		go func() {
			defer close(out)
			for {
				select {
				case r, ok := <-in:
					if !ok {
						<-ctx.Done()
						return
					}
					select {
					case out <- r:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		return out, errc
	}
}

// TestCollectorRegistersAndStreams: a sensor dials in, the collector registers
// it as a Manager source that carries the parsed hello identity, its packets are
// counted, and cancelling the sensor removes the row and fires the disconnect
// hook.
func TestCollectorRegistersAndStreams(t *testing.T) {
	h := newCollectorHarness(t, CollectorConfig{Token: "shared-secret", MaxSensors: 4})

	stream, link := portscanStream(t)
	if packet.LinkType(link) != packet.LinkEthernet {
		t.Fatalf("fixture link type %d, want Ethernet", link)
	}
	srvCfg := pcapoverip.ServerConfig{
		Token:         "shared-secret",
		LinkType:      link,
		Filter:        "wan ip",
		SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{SensorID: "edge-1", Location: "wan", AgentVersion: "0.1.0-test", OSArch: "linux/amd64"}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sensorDone := make(chan struct{})
	go func() {
		if err := runSensor(t, ctx, h.addr, h.clientTLS(t), srvCfg, heldStream(stream)); err != nil {
			t.Errorf("sensor: %v", err)
		}
		close(sensorDone)
	}()

	// It shows up in /api/v1/sensors and /api/v1/captures while connected.
	waitFor(t, "sensor registered", func() bool { return len(h.col.Sensors()) == 1 })
	ss := h.col.Sensors()[0]
	if ss.SensorID != "edge-1" || ss.Location != "wan" || ss.Filter != "wan ip" {
		t.Fatalf("sensor status projection wrong: %+v", ss)
	}
	if ss.AgentVersion != "0.1.0-test" || ss.OSArch != "linux/amd64" {
		t.Fatalf("diagnostic fields missing: %+v", ss)
	}
	if _, ok := h.mgr.Get("edge-1"); !ok {
		t.Fatal("sensor was not registered as a capture.Manager source")
	}
	if got, ok := h.col.Sensor("edge-1"); !ok || got.RemoteAddr == "" {
		t.Fatalf("Sensor(edge-1) = %+v ok=%v", got, ok)
	}
	waitFor(t, "packets counted", func() bool { return h.packets.Load() > 0 })

	// Cancelling the sensor drops the connection → the collector deregisters it.
	cancel()
	<-sensorDone
	waitFor(t, "sensor deregistered", func() bool { return len(h.col.Sensors()) == 0 })
	if _, ok := h.mgr.Get("edge-1"); ok {
		t.Fatal("sensor row was not removed after the connection dropped")
	}
	if h.connects.Load() != 1 || h.disconnAll.Load() != 1 {
		t.Fatalf("hooks: connects=%d disconnects=%d", h.connects.Load(), h.disconnAll.Load())
	}
	t.Logf("streamed %d packets from one reverse-connected sensor", h.packets.Load())
}

// TestCollectorRemovesOnGoodbye: a sensor that reaches end-of-capture sends a
// SYNPOIP goodbye; the collector must deregister the row and publish the
// disconnect (feeds events.SensorDisconnected).
func TestCollectorRemovesOnGoodbye(t *testing.T) {
	h := newCollectorHarness(t, CollectorConfig{Token: "s"})
	stream, link := portscanStream(t)
	srvCfg := pcapoverip.ServerConfig{
		Token: "s", LinkType: link,
		SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{SensorID: "edge-1", Location: "wan"}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runSensor(t, ctx, h.addr, h.clientTLS(t), srvCfg, stream); err != nil {
		t.Fatalf("sensor: %v", err) // returns at end of capture
	}

	// Everything below runSensor is asynchronous: the sensor's whole lifetime
	// (connect, stream, goodbye) happens inside that call, and the collector
	// forwards, deregisters and fires its hooks on its own goroutines. Checking
	// any of it synchronously is a race — and "len(Sensors()) == 0" checked on
	// its own would pass vacuously, since it is also true before the sensor ever
	// arrives. Wait for the registration to have *happened* (the OnConnect hook,
	// which survives the session ending) before waiting for the teardown.
	waitFor(t, "sensor registered", func() bool { return h.connects.Load() == 1 })
	waitFor(t, "packets reached the manager", func() bool { return h.packets.Load() > 0 })
	waitFor(t, "sensor deregistered after goodbye", func() bool {
		_, lingering := h.mgr.Get("edge-1")
		return len(h.col.Sensors()) == 0 && h.disconnAll.Load() == 1 && !lingering
	})
}

// TestCollectorRejectsBadToken: the sensor rejects the daemon's ClientHello
// token, so the collector counts an auth rejection and registers nothing.
func TestCollectorRejectsBadToken(t *testing.T) {
	h := newCollectorHarness(t, CollectorConfig{Token: "wrong-token"})
	stream, link := portscanStream(t)
	srvCfg := pcapoverip.ServerConfig{Token: "right-token", LinkType: link, SessionPrefix: "edge-1"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runSensor(t, ctx, h.addr, h.clientTLS(t), srvCfg, stream)

	time.Sleep(100 * time.Millisecond)
	if n := len(h.col.Sensors()); n != 0 {
		t.Fatalf("a bad-token sensor was registered (%d sensors)", n)
	}
	if h.col.rejectedAuth.Load() == 0 {
		t.Fatal("rejectedAuth counter did not move")
	}
}

// TestCollectorRequiresClientCert: with mutual TLS on, a sensor that presents no
// client certificate fails the TLS handshake and is not registered; a sensor
// presenting a certificate the collector's client CA trusts connects normally.
func TestCollectorRequiresClientCert(t *testing.T) {
	sensorCert, sensorCAPEM, _, err := pcapoverip.SelfSignedCert("sensor")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(sensorCAPEM)

	srvCert, certPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	h := newCollectorHarness(t, CollectorConfig{TLSConfig: tlsCfg, RequireClientCert: true})
	h.caPEM = certPEM

	// No client certificate → rejected at the TLS layer.
	stream, link := portscanStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = runSensor(t, ctx, h.addr, h.clientTLS(t), pcapoverip.ServerConfig{LinkType: link, SessionPrefix: "no-cert"}, stream)

	time.Sleep(150 * time.Millisecond)
	if n := len(h.col.Sensors()); n != 0 {
		t.Fatalf("a sensor without a client cert was registered (%d)", n)
	}
	if h.col.rejectedTLS.Load() == 0 {
		t.Fatal("rejectedTLS counter did not move")
	}

	// Trusted client certificate → connects normally.
	stream2, link2 := portscanStream(t)
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go func() {
		_ = runSensor(t, sctx, h.addr, h.clientTLS(t, sensorCert),
			pcapoverip.ServerConfig{LinkType: link2, SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{SensorID: "mtls-1"})},
			heldStream(stream2))
	}()
	waitFor(t, "mTLS sensor registered", func() bool { return len(h.col.Sensors()) == 1 })
	scancel()
	waitFor(t, "mTLS sensor gone", func() bool { return len(h.col.Sensors()) == 0 })
}

// TestCollectorEnforcesMaxSensors: past the cap, a new connection is refused.
func TestCollectorEnforcesMaxSensors(t *testing.T) {
	h := newCollectorHarness(t, CollectorConfig{MaxSensors: 1})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Sensor 1 holds its slot open.
	go func() {
		_ = runSensor(t, ctx, h.addr, h.clientTLS(t), pcapoverip.ServerConfig{LinkType: 1, SessionPrefix: "held"}, blockingStream)
	}()
	waitFor(t, "sensor registered", func() bool { return len(h.col.Sensors()) == 1 })

	// Sensor 2 is over the cap.
	stream, link := portscanStream(t)
	sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	_ = runSensor(t, sctx, h.addr, h.clientTLS(t), pcapoverip.ServerConfig{LinkType: link, SessionPrefix: "rejected"}, stream)

	time.Sleep(150 * time.Millisecond)
	if n := len(h.col.Sensors()); n != 1 {
		t.Fatalf("cap not enforced: %d sensors registered", n)
	}
	if h.col.rejectedCap.Load() == 0 {
		t.Fatal("rejectedCap counter did not move")
	}
}

// TestCollectorConcurrentSensors: several sensors stream at once, all register
// (with de-duplicated Manager names since they share a sensor id), all stream,
// and all deregister when dropped. Run under -race in CI.
func TestCollectorConcurrentSensors(t *testing.T) {
	const n = 5
	h := newCollectorHarness(t, CollectorConfig{Token: "s", MaxSensors: n + 2})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream, link := portscanStream(t)
			srvCfg := pcapoverip.ServerConfig{
				Token: "s", LinkType: link,
				SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{SensorID: "edge", Location: "loc"}),
			}
			if err := runSensor(t, ctx, h.addr, h.clientTLS(t), srvCfg, heldStream(stream)); err != nil {
				t.Errorf("sensor %d: %v", i, err)
			}
		}(i)
	}

	waitFor(t, "all sensors registered", func() bool { return len(h.col.Sensors()) == n })
	waitFor(t, "packets from all sensors", func() bool { return h.packets.Load() > 0 })

	// Every peer has a distinct Manager row.
	seen := map[string]bool{}
	for _, s := range h.col.Sensors() {
		if seen[s.SourceName] {
			t.Fatalf("duplicate Manager source name %q", s.SourceName)
		}
		seen[s.SourceName] = true
	}

	cancel()
	wg.Wait()
	waitFor(t, "all sensors gone", func() bool { return len(h.col.Sensors()) == 0 })
}
