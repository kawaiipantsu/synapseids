package pipeline_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
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

// TestCollectorToPipelineEndToEnd wires the whole reverse-connect path in
// process: a sensor dials the daemon-side collector, the collector registers it
// as a capture.Manager source, and the pipeline turns its packets into flows and
// classifications — the same output a local replay of the fixture produces.
func TestCollectorToPipelineEndToEnd(t *testing.T) {
	srvCert, certPEM, _, err := pcapoverip.SelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	col, err := capture.NewCollector(capture.CollectorConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{srvCert}},
		Token:     "e2e-token",
		Logf:      t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	bus := events.New()
	sub := bus.Subscribe(256)
	defer sub.Close()
	var sensorConnected, sensorDisconnected atomic.Int64
	go func() {
		for ev := range sub.C {
			switch ev.Type {
			case events.SensorConnected:
				sensorConnected.Add(1)
			case events.SensorDisconnected:
				sensorDisconnected.Add(1)
			}
		}
	}()
	col.OnConnect = func(si capture.SensorInfo) {
		bus.Publish(events.SensorConnected, map[string]any{"sensor_id": si.SensorID, "location": si.Location})
	}
	col.OnDisconnect = func(si capture.SensorInfo) {
		bus.Publish(events.SensorDisconnected, map[string]any{"sensor_id": si.SensorID})
	}

	store := storage.NewMem(500, 500)
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	mgr := capture.NewManager()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pipeDone := make(chan pipeline.Stats, 1)
	go func() {
		st, _ := pipeline.Run(ctx, mgr, rt, bus, store, pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 2 * time.Second, MaxLifetime: 30 * time.Second},
			Sensor: "local",
		})
		pipeDone <- st
	}()

	colDone := make(chan struct{})
	go func() {
		_ = col.Run(ctx, mgr)
		close(colDone)
	}()

	// Wait for the listener to bind, then run the sensor.
	addr := waitReady(t, col)

	stream, link, err := pcapoverip.PcapFileStream(filepath.Clean("../../testdata/pcap/portscan.pcap"), 0)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("sensor dial: %v", err)
	}
	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()
	pcapoverip.ServeConn(sctx, conn, pcapoverip.ServerConfig{
		Token: "e2e-token", LinkType: link,
		SessionPrefix: pcapoverip.FormatSessionPrefix(pcapoverip.SensorIdentity{SensorID: "edge-1", Location: "wan"}),
	}, stream)

	// The sensor has sent its goodbye; give the pipeline a moment to drain and
	// close the last flow, then stop everything.
	deadline := time.Now().Add(10 * time.Second)
	for len(store.RecentClassifications(500)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no classification produced from the reverse-connected sensor")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	_ = mgr.Close()
	st := <-pipeDone
	<-colDone

	cls := store.RecentClassifications(500)
	if st.Packets == 0 || st.Flows == 0 || len(cls) == 0 {
		t.Fatalf("end-to-end produced no work: stats=%+v classifications=%d", st, len(cls))
	}
	scan := 0
	for _, c := range cls {
		if c.Result.Class == "scan" {
			scan++
		}
	}
	if scan == 0 {
		t.Errorf("portscan.pcap over the collector produced no scan verdicts (%d classifications)", len(cls))
	}
	if sensorConnected.Load() == 0 {
		t.Error("SensorConnected was never published")
	}
	// disconnect fires once the collector notices the session end.
	dd := time.Now().Add(2 * time.Second)
	for sensorDisconnected.Load() == 0 && time.Now().Before(dd) {
		time.Sleep(10 * time.Millisecond)
	}
	if sensorDisconnected.Load() == 0 {
		t.Error("SensorDisconnected was never published")
	}
	t.Logf("end-to-end: %d packets, %d flows, %d classifications", st.Packets, st.Flows, len(cls))
}

func waitReady(t *testing.T, col *capture.Collector) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := col.Addr(); a != "" {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("collector listener never bound")
	return ""
}
