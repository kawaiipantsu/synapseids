package main

import (
	"context"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/obs"
)

// reloader re-reads the config file on SIGHUP and applies the subset that can
// change on a running daemon (issue #59, PROJECT.md §23). Everything else is
// reported as needing a restart; nothing is applied unless the whole file
// re-validates, so a typo can never take the running policy down.
//
// The safe subset is deliberately small: the alert policy (thresholds,
// alert-on-disagreement, and the alerts.suppress rules — issue #133) and the log
// level. A listener, a storage backend, capture sources or flow-engine timing
// all need a restart, because swapping them mid-run means tearing down and
// rebuilding a live goroutine graph.
type reloader struct {
	path   string
	logger *obs.Logger
	alerts *alert.Store

	mu  sync.Mutex
	cur config.Config
}

func newReloader(path string, logger *obs.Logger, alerts *alert.Store, initial config.Config) *reloader {
	return &reloader{path: path, logger: logger, alerts: alerts, cur: initial}
}

// watch blocks, handling SIGHUP until ctx is cancelled. Run it on its own
// goroutine.
func (r *reloader) watch(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			r.reload()
		}
	}
}

// reload is the SIGHUP handler body; separated so a test can drive it directly.
func (r *reloader) reload() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.path == "" {
		r.logger.Warn("SIGHUP ignored: no --config file to reload")
		return
	}

	next, err := config.Load(r.path)
	if err != nil {
		// A bad file must not disturb the running daemon.
		r.logger.Error("config reload failed; keeping the running configuration", "err", err)
		return
	}

	applied, restart := r.apply(r.cur, next)
	r.cur = next

	if len(applied) == 0 && len(restart) == 0 {
		r.logger.Info("config reloaded; no changes")
		return
	}
	r.logger.Info("config reloaded",
		"applied", applied,
		"restart_required", restart,
	)
}

// apply changes what it safely can and returns a human list of what it did and
// what it could not. It never returns an error: a reload is best-effort and the
// log is the record.
func (r *reloader) apply(old, next config.Config) (applied, restartRequired []string) {
	// ---- log level (live) / format (restart) --------------------------------
	if old.Logging.Level != next.Logging.Level {
		if err := r.logger.SetLevel(next.Logging.Level); err != nil {
			r.logger.Warn("config reload: keeping the current log level", "err", err)
		} else {
			applied = append(applied, "logging.level="+next.Logging.Level)
		}
	}
	if old.Logging.Format != next.Logging.Format {
		restartRequired = append(restartRequired, "logging.format")
	}

	// ---- alert policy (live) ------------------------------------------------
	if !reflect.DeepEqual(alertPolicyInput(old.Alerts), alertPolicyInput(next.Alerts)) {
		pol, perr := alertPolicy(next.Alerts)
		if perr != nil {
			// config.Load already validated this; reaching here is a bug, not an
			// operator mistake. Keep the running policy.
			r.logger.Error("config reload: alert policy did not compile; keeping the running one", "err", perr)
		} else {
			r.alerts.SetPolicy(pol)
			applied = append(applied, "alerts.policy")
		}
	}
	// The store's bounds are fixed at construction.
	if old.Alerts.MaxRecent != next.Alerts.MaxRecent {
		restartRequired = append(restartRequired, "alerts.max_recent")
	}
	if old.Alerts.DedupWindowSec != next.Alerts.DedupWindowSec {
		restartRequired = append(restartRequired, "alerts.dedup_window_sec")
	}

	// ---- everything else: restart-only ----------------------------------------
	restartRequired = append(restartRequired, restartOnlyChanges(old, next)...)
	return applied, restartRequired
}

// alertPolicyInput is the part of the alerts block that feeds alert.Policy (as
// opposed to the store bounds), so a change to MaxRecent alone does not look
// like a policy change.
func alertPolicyInput(a config.Alerts) config.Alerts {
	a.MaxRecent = 0
	a.DedupWindowSec = 0
	return a
}

// restartOnlyChanges lists the top-level config sections that differ and cannot
// be applied without a restart. It compares whole sections so one message stands
// for "something in capture changed", which is all an operator needs — the file
// is the detail.
func restartOnlyChanges(old, next config.Config) []string {
	var out []string
	type section struct {
		name string
		a, b any
	}
	for _, s := range []section{
		{"server", old.Server, next.Server},
		{"storage", old.Storage, next.Storage},
		{"capture", old.Capture, next.Capture},
		{"models", old.Models, next.Models},
		{"datasets", old.Datasets, next.Datasets},
		{"training", old.Training, next.Training},
		{"review", old.Review, next.Review},
		{"live", old.Live, next.Live},
		{"retention", old.Retention, next.Retention},
	} {
		if !reflect.DeepEqual(s.a, s.b) {
			out = append(out, s.name)
		}
	}
	return out
}
