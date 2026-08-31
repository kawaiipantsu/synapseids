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
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
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

	// Inspect any model bundles under cfg.Models.Directory. This validates each
	// bundle against the frozen contracts and logs the result; it never adds a
	// model to the runtime and never activates cfg.Models.Primary — activation
	// is a separate explicit step, still to be wired (PROJECT.md §11, §28.10).
	// One-shot at startup, off any packet path.
	model.Scan(cfg.Models.Directory, cfg.Models.Primary, log.Printf)

	rt := inference.NewRuntime(
		inference.NewHeuristic("heuristic-v1", inference.RolePrimary),
	)

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
		src, err := capture.NewAFPacket(capture.AFPacketConfig{
			Interface:   cs.Interface,
			Promiscuous: cs.Promiscuous,
			Snaplen:     cs.Snaplen,
			Filter:      cs.Filter,
		})
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
			"name": cs.Name, "kind": cs.Kind, "interface": cs.Interface, "filter": cs.Filter,
		})
		log.Printf("capture: source %q live on %s (promiscuous=%t snaplen=%d filter=%q)",
			cs.Name, cs.Interface, cs.Promiscuous, cs.Snaplen, cs.Filter)
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
	srv := api.New(cfg, bus, store, rt, rc, rc, capProvider)

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
