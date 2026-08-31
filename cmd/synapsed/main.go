// Command synapsed is the SynapseIDS daemon: it manages capture sources, builds
// flows, extracts flow-features-v1 vectors, scores them with the inference
// runtime, persists the results, and exposes a versioned REST API plus one live
// WebSocket channel (PROJECT.md §5.1). Phase 1 wires PCAP replay end to end; live
// capture backends are tracked separately.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/api"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/storage"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

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
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "synapsed — SynapseIDS daemon\n\nUsage:\n  synapsed [--config FILE] [--listen HOST:PORT]\n  synapsed --version\n\nFlags:\n")
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

	// rc also implements api.FlowStatsProvider: it owns the running pipeline and
	// therefore its live flow-table counters (PROJECT.md §22, §24).
	srv := api.New(cfg, bus, store, rt, rc, rc)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("synapsed %s listening on http://%s  (feature schema %s, %d models)",
		version.Version, cfg.Server.Listen, features.SchemaID, len(rt.Models()))
	if err := srv.Run(ctx); err != nil {
		log.Printf("server: %v", err)
		return 1
	}
	rc.Stop() //nolint:errcheck // best effort on shutdown
	time.Sleep(50 * time.Millisecond)
	log.Printf("synapsed stopped")
	return 0
}
