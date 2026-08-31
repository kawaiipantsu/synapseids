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

	"github.com/kawaiipantsu/synapseids/internal/api"
	"github.com/kawaiipantsu/synapseids/internal/audit"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/storage"
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
	for _, b := range model.Scan(cfg.Models.Directory, cfg.Models.Primary, log.Printf) {
		e, err := reg.Register(b)
		if err != nil {
			log.Printf("registry: rejected %q: %v", b.Dir(), err)
			continue
		}
		aud.Log(audit.EventModelRegistered, audit.ActorLocal, e.ModelID, "hash="+e.ContentHash+" status="+string(e.Status))
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

	flowOpt := flow.Options{
		IdleTimeout:      cfg.Capture.FlowIdleTimeout.D(),
		MaxLifetime:      cfg.Capture.FlowMaxLifetime.D(),
		SnapshotInterval: cfg.Capture.SnapshotInterval.D(),
		MaxFlows:         cfg.Capture.MaxFlows,
	}
	var flowID atomic.Uint64
	rc := newReplayController(bus, store, rt, flowOpt, "local", &flowID)

	// Live capture: open every configured NIC source and hand it to the Manager,
	// which merges them into one stream for a single pipeline goroutine
	// (PROJECT.md §22). A source that cannot open (missing capability, no such
	// interface) is logged and skipped — the daemon keeps serving the API in a
	// degraded mode, never crashes (PROJECT.md §21).
	capMgr := capture.NewManager()
	live := 0
	for _, cs := range cfg.Capture.Sources {
		src, target, err := newCaptureSource(cs)
		if err != nil {
			log.Printf("capture: source %q disabled: %v", cs.Name, err)
			continue
		}
		filterLabel := cs.Filter
		if filterLabel == "" {
			filterLabel = "(all)"
		}
		if err := capMgr.Add(cs.Name, src, capture.SourceMeta{Kind: cs.Kind, Filter: filterLabel}); err != nil {
			log.Printf("capture: source %q: %v", cs.Name, err)
			_ = src.Close()
			continue
		}
		live++
		bus.Publish(events.CaptureSourceConnected, map[string]any{
			"name": cs.Name, "kind": cs.Kind, "interface": cs.Interface,
			"destination": cs.Destination, "filter": cs.Filter,
		})
		log.Printf("capture: source %q (%s) live on %s (snaplen=%d filter=%q)",
			cs.Name, cs.Kind, target, cs.Snaplen, cs.Filter)
	}
	if len(cfg.Capture.Sources) > 0 && live == 0 {
		log.Printf("capture: no live source could start — continuing API-only (degraded)")
	}

	// rc also implements api.FlowStatsProvider: it owns the running replay
	// pipeline and therefore its live flow-table counters (PROJECT.md §22, §24).
	var capProvider api.CaptureStatusProvider
	if live > 0 {
		capProvider = capMgr
	}
	srv := api.New(cfg, bus, store, rt, reg, aud, rc, rc, capProvider)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// One pipeline goroutine consumes the merged live-capture stream. It shares
	// the daemon's IDGen with the replay pipeline so flow IDs stay globally
	// unique (CLAUDE.md).
	if live > 0 {
		go func() {
			st, err := pipeline.Run(ctx, capMgr, rt, bus, store, pipeline.Options{
				Flow: flowOpt, Sensor: "local",
				IDGen: func() uint64 { return flowID.Add(1) },
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("capture pipeline: %v", err)
			}
			log.Printf("capture pipeline stopped: %d packets, %d flows, %d classifications",
				st.Packets, st.Flows, st.Classifications)
		}()
	}

	log.Printf("synapsed %s listening on http://%s  (feature schema %s, %d models, %d live capture source(s))",
		version.Version, cfg.Server.Listen, features.SchemaID, len(rt.Models()), live)
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

// newCaptureSource builds the capture.Source for one configured entry and a
// short human label for the startup log. config.validate has already checked
// the per-kind required fields; the constructors here do the real environment
// checks (interface exists, capability present, binary on PATH) and a failure
// is logged and skipped so the daemon still serves the API (PROJECT.md §21).
func newCaptureSource(cs config.CaptureSource) (capture.Source, string, error) {
	switch cs.Kind {
	case "nic":
		src, err := capture.NewAFPacket(capture.AFPacketConfig{
			Interface:   cs.Interface,
			Promiscuous: cs.Promiscuous,
			Snaplen:     cs.Snaplen,
			Filter:      cs.Filter,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Interface, nil
	case "tcpdump":
		src, err := capture.NewTcpdumpStream(capture.TcpdumpConfig{
			Binary:    cs.Binary,
			Interface: cs.Interface,
			Filter:    cs.Filter,
			Snaplen:   cs.Snaplen,
			ExtraArgs: cs.ExtraArgs,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Interface, nil
	case "ssh":
		src, err := capture.NewSSHTcpdump(capture.SSHConfig{
			SSHBinary:      cs.Binary,
			Destination:    cs.Destination,
			Port:           cs.Port,
			IdentityFile:   cs.IdentityFile,
			RemoteBinary:   cs.RemoteBinary,
			Interface:      cs.Interface,
			Filter:         cs.Filter,
			Snaplen:        cs.Snaplen,
			ExtraSSHArgs:   cs.ExtraSSHArgs,
			KnownHostsMode: cs.KnownHosts,
			Authorized:     cs.Authorized,
		})
		if err != nil {
			return nil, "", err
		}
		return src, cs.Destination + " " + cs.Interface, nil
	default:
		return nil, "", fmt.Errorf("unknown kind %q", cs.Kind)
	}
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
