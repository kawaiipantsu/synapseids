// Command synapsed is the SynapseIDS daemon: it manages capture sources, builds
// flows, extracts flow-features-v1 vectors, scores them with the inference
// runtime, persists the results, and exposes a versioned REST API plus one live
// WebSocket channel (PROJECT.md §5.1). Phase 1 wires PCAP replay end to end; live
// capture backends are tracked separately.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/api"
	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/capturewire"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/obs"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/review"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/training"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

// multiFlag collects a repeatable string flag (--capture eth0 --capture lo).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("synapsed", flag.ContinueOnError)
	var (
		cfgPath = fs.String("config", "", "path to a JSON config file (see contrib/config/synapse.json)")
		listen  = fs.String("listen", "", "override server.listen, e.g. 127.0.0.1:8080")
		showVer = fs.Bool("version", false, "print build metadata and exit")
		caps    multiFlag
	)
	fs.Var(&caps, "capture", "capture live traffic from this network interface (repeatable); adds a promiscuous AF_PACKET NIC source. Needs CAP_NET_RAW/CAP_NET_ADMIN")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "synapsed — SynapseIDS daemon\n\nUsage:\n  synapsed [--config FILE] [--listen HOST:PORT] [--capture IFACE ...]\n  synapsed --version\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVer {
		fmt.Println(version.String("synapsed"))
		return 0
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}

	// Structured logging (issue #55). From here on every log line — including the
	// many packages that take an injected log.Printf — goes through the slog
	// handler at the configured level. logger holds a live level knob for
	// config hot-reload (issue #59). A bad format/level was rejected by
	// config.Load, so logSetupErr should always be nil.
	logger, logSetupErr := obs.SetupLogging(os.Stderr, cfg.Logging.Format, cfg.Logging.Level)
	if logSetupErr != nil {
		logger.Warn("logging setup fell back to defaults", "err", logSetupErr)
	}
	metrics := obs.New()

	if *listen != "" {
		cfg.Server.Listen = *listen
	}
	// Each --capture IFACE adds a promiscuous NIC source unless that interface is
	// already configured. These are valid by construction; capture.NewAFPacket
	// does the real check (interface exists, capability present) at open time.
	for _, ifn := range caps {
		if !hasNICInterface(cfg.Capture.Sources, ifn) {
			cfg.Capture.Sources = append(cfg.Capture.Sources, config.CaptureSource{
				Name: ifn, Kind: "nic", Interface: ifn, Promiscuous: true,
			})
		}
	}
	if !cfg.LoopbackOnly() {
		log.Printf("WARNING: server.listen %q is not loopback — put an authenticating reverse proxy in front (PROJECT.md §21)", cfg.Server.Listen)
	}

	bus := events.New()
	store := storage.NewMem(cfg.Storage.MaxFlows, cfg.Storage.MaxFlows)

	// Host and timeline aggregates for Investigation mode. Its aggregator runs on
	// its own goroutine; both pipelines below feed it with one non-blocking send
	// per flow record, so /api/v1/hosts can never stall the packet path
	// (docs/adr/0016, PROJECT.md §19.4-6, §22).
	ins := insight.New(insight.Options{})
	defer func() { _ = ins.Close() }()

	// The detection store behind GET /api/v1/detections (issue #117; ADR 0027).
	// Like insight it runs its own goroutine and is fed by one non-blocking send
	// per verdict, so the alert policy, the (src, dst, class) dedup and the
	// events.AlertCreated publish are all off the packet path (PROJECT.md §22).
	//
	// It is always constructed, even with alerts.enabled=false: the store then
	// suppresses everything but still reports counters, so /api/v1/status can say
	// alerting is off instead of looking like a network with nothing happening.
	alertPol, err := alertPolicy(cfg.Alerts)
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	alerts := alert.New(alertPol, alert.Options{
		MaxRecent:   cfg.Alerts.MaxRecent,
		DedupWindow: time.Duration(cfg.Alerts.DedupWindowSec) * time.Second,
		Bus:         bus,
	})
	defer func() { _ = alerts.Close() }()
	if cfg.Alerts.Enabled {
		log.Printf("alerts: enabled (min_confidence=%.2f dedup_window=%ds max_recent=%d alert_on_disagreement=%t suppress_rules=%d)",
			cfg.Alerts.MinConfidence, cfg.Alerts.DedupWindowSec, cfg.Alerts.MaxRecent, cfg.Alerts.AlertOnDisagreement, len(cfg.Alerts.Suppress))
	} else {
		log.Printf("alerts: disabled by config — /api/v1/detections will stay empty and no AlertCreated event is published")
	}

	rt := inference.NewRuntime(
		inference.NewHeuristic("heuristic-v1", inference.RolePrimary),
	)

	// Scan cfg.Models.Directory, then register every bundle that passes the gate
	// into the model registry (issue #26). Registration makes a model known,
	// inspectable and lineage-linked; it never adds the model to the runtime and
	// never activates cfg.Models.Primary — activation is a separate explicit
	// action (POST /api/v1/models/{id}/activate, PROJECT.md §11, §28.10). One-shot
	// at startup, off any packet path.
	aud := audit.New(cfg.Models.Directory, log.Printf)
	reg := registry.Open(cfg.Models.Directory, log.Printf)
	// A model that was active when the daemon stopped is loaded back as
	// deactivated. That is a real state change and it must be in the audit log,
	// otherwise the model's most recent line still says "activated" while the
	// runtime is running the heuristic (PROJECT.md §21, §28.10).
	for _, id := range reg.Reconciled() {
		aud.Log(audit.EventModelDeactivated, audit.ActorLocal, id,
			"daemon restart: activation does not survive a restart; re-activate explicitly")
	}
	for _, b := range model.Scan(cfg.Models.Directory, cfg.Models.Primary, log.Printf) {
		// Register is idempotent, so the startup sweep re-registers bundles the
		// registry already knows. Only audit a genuinely new registration —
		// otherwise every restart appends a duplicate ModelRegistered line and
		// the log stops being a record of what changed.
		_, known := reg.Get(b.Meta().ModelID)
		e, err := reg.Register(b)
		if err != nil {
			log.Printf("registry: rejected %q: %v", b.Dir(), err)
			continue
		}
		if !known {
			aud.Log(audit.EventModelRegistered, audit.ActorLocal, e.ModelID, "hash="+e.ContentHash+" status="+string(e.Status))
		}
		bus.Publish(events.ModelRegistered, map[string]any{
			"model_id": e.ModelID, "family": e.Family,
			"content_hash": e.ContentHash, "status": string(e.Status),
		})
		log.Printf("registry: registered model %q (%s) — %s; POST /api/v1/models/%s/activate to make it live",
			e.ModelID, e.Family, e.Status, e.ModelID)
	}
	if cfg.Models.Primary != "" {
		if e, ok := reg.Get(cfg.Models.Primary); ok {
			log.Printf("primary %q is registered and valid; POST /api/v1/models/%s/activate to make it live (not auto-activated, PROJECT.md §28.10)",
				e.ModelID, e.ModelID)
		} else {
			log.Printf("primary %q is not a registered model id (no matching valid bundle under %s)", cfg.Models.Primary, cfg.Models.Directory)
		}
	}

	// The human review store loads review.directory once at startup (PROJECT.md
	// §16; ADR 0021). It is off every packet path — a review only ever happens on
	// an explicit PUT /api/v1/review/{flow_id}. It reads the prediction it
	// preserves from the same store the pipeline writes to, and it must exist
	// before the dataset manager, which reads curated labels from it.
	rvs := review.Open(cfg.Review.Directory, store, bus, aud, log.Printf)

	// The dataset manager scans datasets.directory once at startup so the API
	// can list what is already on disk. It is off every packet path: a dataset
	// is only ever built by an explicit POST /api/v1/datasets (PROJECT.md §14,
	// §22; ADR 0015). It reads from the same store the pipeline writes to, and
	// from the review store for a `reviewed` (human-labelled) cut.
	dsm := dataset.Open(cfg.Datasets.Directory, store, rvs, log.Printf)

	// The training run store mirrors external synapse-trainer runs reported over
	// HTTP (PROJECT.md §19.8; ADR 0019). The daemon never launches a trainer; it
	// keeps the latest progress plus a bounded history so the SPA can poll it.
	// One-shot load at startup, off every packet path.
	trs := training.Open(cfg.Training.Directory, aud, log.Printf)

	flowOpt := flow.Options{
		IdleTimeout:      cfg.Capture.FlowIdleTimeout.D(),
		MaxLifetime:      cfg.Capture.FlowMaxLifetime.D(),
		SnapshotInterval: cfg.Capture.SnapshotInterval.D(),
		MaxFlows:         cfg.Capture.MaxFlows,
	}
	var flowID atomic.Uint64
	// One view of every flow table the daemon runs. Both pipelines report into
	// it, so /api/v1/status describes the table that is actually doing the work
	// rather than whichever one happened to be wired (issue #125).
	flowStats := newFlowStatsHub(flowOpt.MaxFlows)
	rc := newReplayController(bus, store, rt, ins, alerts, flowOpt, "local", &flowID, flowStats, metrics)

	// Live capture: open every configured source and hand it to the Manager,
	// which merges them into one stream for a single pipeline goroutine
	// (PROJECT.md §22). A source that cannot open (missing capability, no such
	// interface, bad TLS material) is logged and skipped — the daemon keeps
	// serving the API in a degraded mode, never crashes (PROJECT.md §21). A
	// pcap-over-ip source that opens but cannot reach its sensor surfaces later
	// as a Manager row in state "error"; there is no auto-reconnect yet.
	capMgr := capture.NewManager()
	capMgr.SetLogf(log.Printf) // one line at Close if in-flight packets were discarded (issue #138)
	live := 0
	for _, cs := range cfg.Capture.Sources {
		src, target, err := capturewire.Build(cs, log.Printf)
		if err != nil {
			log.Printf("capture: source %q disabled: %v", cs.Name, err)
			continue
		}
		if err := capMgr.Add(cs.Name, src, capturewire.Meta(cs)); err != nil {
			log.Printf("capture: source %q: %v", cs.Name, err)
			_ = src.Close()
			continue
		}
		live++
		bus.Publish(events.CaptureSourceConnected, map[string]any{
			"name": cs.Name, "kind": cs.Kind, "interface": cs.Interface,
			"destination": cs.Destination, "addr": cs.Addr, "filter": cs.Filter,
		})
		if cs.Kind == "pcap-over-ip" {
			log.Printf("capture: source %q pcap-over-ip to %s (server_name=%q insecure_tls=%t mtls=%t)",
				cs.Name, cs.Addr, cs.ServerName, cs.InsecureTLS, cs.ClientCertFile != "")
		} else {
			log.Printf("capture: source %q (%s) live on %s (snaplen=%d filter=%q)",
				cs.Name, cs.Kind, target, cs.Snaplen, cs.Filter)
		}
	}
	if len(cfg.Capture.Sources) > 0 && live == 0 {
		log.Printf("capture: no live source could start — continuing API-only (degraded)")
	}

	// The daemon-side SYNPOIP collector: a TLS listener that accepts
	// reverse-connecting sensors (`synapse-sensor pcap-over-ip --connect`) and
	// registers one capture.Manager source per accepted peer (issues #43, #103;
	// ADR 0018). Nil when no collector block is configured. Bad TLS material is
	// logged and the daemon keeps serving the API (degraded), exactly like a NIC
	// source that cannot open.
	// sensorRecords carries `flow`- and `feature`-mode sensor records from the
	// collector to the capture pipeline, which drains it on the same goroutine as
	// the merged packet channel (issue #45). It is buffered so a burst of closing
	// flows does not stall a sensor's TLS read loop; when the buffer does fill,
	// the collector blocks and TCP backpressure reaches the sensor, which is the
	// right way to shed record load — records are one per flow, not per packet.
	sensorRecords := make(chan pcapoverip.SensorRecord, 1024)

	var collector *capture.Collector
	if cfg.Capture.Collector.Listen != "" {
		col, cerr := capturewire.BuildCollector(cfg.Capture.Collector, sensorRecords, log.Printf)
		if cerr != nil {
			log.Printf("capture: collector disabled: %v", cerr)
		} else {
			col.OnConnect = func(si capture.SensorInfo) {
				bus.Publish(events.SensorConnected, map[string]any{
					"sensor_id": si.SensorID, "location": si.Location,
					"remote_addr": si.RemoteAddr, "link_type": si.LinkType,
					"filter": si.Filter, "session_id": si.SessionID,
					"agent_version": si.AgentVersion, "os_arch": si.OSArch,
					"source_name": si.SourceName, "mode": si.Mode,
					"protocol_version": si.ProtocolVersion, "payload_schema": si.PayloadSchema,
				})
			}
			col.OnDisconnect = func(si capture.SensorInfo) {
				bus.Publish(events.SensorDisconnected, map[string]any{
					"sensor_id": si.SensorID, "location": si.Location,
					"remote_addr": si.RemoteAddr, "link_type": si.LinkType,
					"filter": si.Filter, "session_id": si.SessionID,
					"source_name": si.SourceName, "mode": si.Mode,
				})
			}
			collector = col
		}
	}

	// The Manager is always wired into the API, even with zero startup sources,
	// so POST /api/v1/captures can add one at runtime and DELETE can remove it
	// (issue #32). The capture pipeline goroutine below always runs for the same
	// reason — a runtime-added source needs a consumer on m.out.
	//
	// flowStats is the api.FlowStatsProvider: it sums the flow tables of both
	// pipelines, so a sensor-fed daemon reports the counters of the table its
	// packets actually built (PROJECT.md §22, §24; issue #125).
	// collector is a *capture.Collector, so passing it directly would hand api a
	// TYPED nil when no collector block is configured: the interface value is
	// non-nil (it carries a type) and every "if sp != nil" guard passes, then the
	// first method call panics on the nil receiver. Convert explicitly.
	var sensors api.SensorStatusProvider
	if collector != nil {
		sensors = collector
	}
	// alerts, ins, trs and rvs are handed over as concrete pointers rather than
	// through an interface, which is exactly what makes them immune to that bug;
	// every one of *alert.Store's methods is nil-receiver safe as well.
	srv := api.New(cfg, bus, store, rt, reg, aud, dsm, rc, flowStats, capMgr, ins, trs, sensors, rvs, alerts)
	srv.SetMetrics(metrics)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP re-reads --config and applies the subset that is safe on a running
	// daemon: the alert policy (thresholds + alerts.suppress) and the log level.
	// Everything else that changed is logged as needing a restart. A file that
	// fails to re-validate leaves the running configuration untouched (issue #59).
	go newReloader(*cfgPath, logger, alerts, cfg).watch(ctx)

	// One pipeline goroutine consumes the merged live-capture stream. It runs
	// even with no startup source so a source added later via
	// POST /api/v1/captures has a consumer on the merged channel. It shares the
	// daemon's IDGen with the replay pipeline so flow IDs stay globally unique
	// (CLAUDE.md).
	go func() {
		st, err := pipeline.Run(ctx, capMgr, rt, bus, store, pipeline.Options{
			Flow: flowOpt, Sensor: "local",
			IDGen:    func() uint64 { return flowID.Add(1) },
			Observer: ins,
			Alerts:   alerts,
			Records:  sensorRecords,
			// This is the table that serves live NICs and every raw-mode sensor.
			// Leaving it unreported was issue #125.
			OnStats: flowStats.Reporter("capture"),
			Metrics: metrics,
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("capture pipeline: %v", err)
		}
		log.Printf("capture pipeline stopped: %d packets, %d flows, %d classifications",
			st.Packets, st.Flows, st.Classifications)
	}()

	// The collector runs on its own goroutine after the pipeline goroutine, so
	// the Manager is already draining m.out when the first sensor registers. A
	// listen failure logs and the daemon keeps serving the API (degraded).
	if collector != nil {
		go func() {
			if err := collector.Run(ctx, capMgr); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("collector: %v", err)
			}
		}()
	}

	logger.Info("synapsed listening",
		"version", version.Version,
		"listen", cfg.Server.Listen,
		"feature_schema", features.SchemaID,
		"models", len(rt.Models()),
		"capture_sources", live,
		"collector", collector != nil,
		"metrics", "/metrics",
		"log_level", logger.Level(),
	)
	if err := srv.Run(ctx); err != nil {
		log.Printf("server: %v", err)
		return 1
	}
	rc.Stop()          //nolint:errcheck // best effort on shutdown
	_ = capMgr.Close() // cancels live sources and drains the fan-in
	time.Sleep(50 * time.Millisecond)
	log.Printf("synapsed stopped")
	return 0
}

// alertPolicy bridges the config block to the alert package's policy. The scalar
// fields are a plain copy — config.ValidateAlerts already rejected an
// out-of-range threshold or an unknown class at load (PROJECT.md §23). The
// suppression rules are compiled here (CIDR parsing, matcher build); an error is
// impossible on a validated config but is returned rather than dropped, because
// a silently discarded suppression rule is exactly what issue #133 forbids.
func alertPolicy(a config.Alerts) (alert.Policy, error) {
	specs := make([]alert.SuppressSpec, len(a.Suppress))
	for i, r := range a.Suppress {
		specs[i] = alert.SuppressSpec{
			Src: r.Src, Dst: r.Dst, DstPort: r.DstPort, Class: r.Class, Note: r.Note,
		}
	}
	rules, err := alert.CompileSuppress(specs)
	if err != nil {
		return alert.Policy{}, fmt.Errorf("alerts.suppress: %w", err)
	}
	return alert.Policy{
		Enabled:               a.Enabled,
		MinConfidence:         a.MinConfidence,
		PerClassMinConfidence: a.PerClassMinConfidence,
		AlertOnDisagreement:   a.AlertOnDisagreement,
		Suppress:              rules,
	}, nil
}

// hasNICInterface reports whether srcs already contains a "nic" source bound to
// iface (mirrors config.hasNICInterface for the --capture merge).
func hasNICInterface(srcs []config.CaptureSource, iface string) bool {
	for _, s := range srcs {
		if s.Kind == "nic" && s.Interface == iface {
			return true
		}
	}
	return false
}
