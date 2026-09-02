# 0034 — Config hot-reload: SIGHUP, a small safe subset, all-or-nothing validation

**Status:** Accepted, 2026-09-01

## Context

PROJECT.md §23 wants "reload safe configuration subsets without a restart"
(issue #59). Operators tune the alert policy — confidence thresholds and the
`alerts.suppress` expected-behaviour rules (#133) — while watching the detection
feed, and want a new log level for a debugging session, without dropping every
capture connection and flushing the flow table.

## Decision

### Trigger: SIGHUP

The Unix convention, and it composes with `systemctl reload` (the unit gains
`ExecReload=/bin/kill -HUP $MAINPID`). No new API route — reload is an operator
action on the host, not a network-reachable one, which also keeps it outside the
unauthenticated-mutating-route question (#58). A separate `signal.Notify`
channel, independent of the SIGINT/SIGTERM shutdown context.

### The safe subset is deliberately small

| Applied live | Restart required |
|---|---|
| `alerts.enabled`, `alerts.min_confidence`, `alerts.per_class_min_confidence`, `alerts.alert_on_disagreement`, `alerts.suppress[]` | `alerts.max_recent`, `alerts.dedup_window_sec` (store bounds fixed at `New`) |
| `logging.level` | `logging.format` (a running slog handler cannot swap its encoder) |
| | `server`, `storage`, `capture`, `models`, `datasets`, `training`, `review`, `live`, `retention` |

The line is drawn at "can this be swapped without tearing down a live goroutine
graph". The alert policy can: `alert.Store.SetPolicy` sends the new policy down
the same channel occurrences travel, and the single aggregator goroutine — the
only reader of the policy and the per-rule hit slice — applies it with no lock,
the same lock-free whole-value swap `inference.Runtime` uses for its model slice.
The log level can: `slog.LevelVar` is `Set`-at-runtime by design. A listener, a
storage backend, capture sources, flow timing — all of those own running
goroutines and connections, and "reload" of them is really "restart".

`retention` is in the restart column not because it holds goroutines but because
nothing in this build reads it live (it is advisory until a durable backend,
#53/#56); saying "restart" is honest, "applied" would be a lie.

### All-or-nothing validation

The reload runs the full `config.Load` + `validate()`. A syntax error, an
unknown key, an out-of-range threshold or a bad `alerts.suppress` rule logs
`config reload failed; keeping the running configuration` and changes nothing —
the running policy is never taken down by a typo in the file. Only a file that
would have been accepted at startup is applied.

### The output is one structured log line

`config reloaded` with `applied=[…]` and `restart_required=[…]` (or
`no changes`). There is no `ConfigReloaded` bus event — `event-envelope-v1` is
frozen (§9) and this is an operator-facing fact, not a data-plane one.

## Consequences

- New `alert.Store.SetPolicy(Policy)` — blocks until the aggregator applies the
  swap, so the reload log reflects reality. The per-rule `suppress_rules[]` hit
  counts reset on a policy swap (the rules changed; the old totals describe
  nothing).
- New `cmd/synapsed/reload.go` (`reloader`), one goroutine bound to the run
  context. `reload()` is separated from the signal loop so it is unit-tested
  directly.
- `logging.level` is now genuinely dynamic; `logging.format` is documented as
  restart-only in the annotated config.

## Alternatives rejected

- **Reload everything by rebuilding the world.** Swapping the listener, the
  capture manager and both pipelines under load is a large correctness surface
  for a rare operation; a restart is simpler and already fast.
- **A `POST /api/v1/config/reload` route.** Puts a privileged operation on the
  unauthenticated surface (#58) for no gain over SIGHUP.
- **Partial apply on a partially-valid file.** Applying the half that parsed
  leaves the daemon in a state that matches no file on disk — worse to reason
  about than "nothing changed, fix the file".
