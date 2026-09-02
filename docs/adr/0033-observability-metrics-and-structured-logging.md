# 0033 — Observability: hand-rolled `/metrics` and `log/slog`

**Status:** Accepted, 2026-09-01

## Context

PROJECT.md §24 asks for structured logs and a metric set (packet counters,
drops, active flows, flow create/expire rate, feature-extraction rate, inference
latency, inference failures, classifications by class, model disagreement,
storage latency, live-client queue drops, sensor connectivity, training job
state). Issue #55.

Two constraints shape the answer:

- **Zero third-party Go dependencies** (CLAUDE.md). No `prometheus/client_golang`,
  no `zap`/`zerolog`.
- Most of the §24 counters already exist — `events.Bus.Stats`, `wshub.Stats`,
  `storage.Stats`, `capture.SourceStatus`, `alert.Stats`, `insight.Stats`, the
  flow-table `FlowStats`. `/api/v1/status` already aggregates them.

## Decision

### `/metrics` renders what `/api/v1/status` already gathers, plus two histograms

A new `internal/obs` package holds only what no `Stats()` covers:

- `obs.Histogram` — a fixed-bucket cumulative histogram, the exact shape a
  Prometheus histogram takes on the wire (`_bucket{le=…}`, `_sum`, `_count`).
  Hand-rolled, ~120 lines, mutex-guarded `Observe`.
- `obs.Metrics` — the scoring-latency and feature-extraction-latency histograms,
  the per-class verdict tally (a slice of atomics indexed by the frozen schema
  order), and an inference-failure counter.
- `obs.Writer` — the Prometheus 0.0.4 text exposition, written by hand: a `HELP`
  /`TYPE` header once per family, label escaping, deterministic label order.

The daemon builds one `*obs.Metrics`, hands it to **both** pipelines
(`pipeline.Options.Metrics`) for recording and to the API
(`Server.SetMetrics`) for exposition. Recording is a `time.Now` pair plus a
histogram add, done on the pipeline goroutine when a flow closes — never on the
packet loop (§22). A nil `*obs.Metrics` is inert, so replay-only and embedded
callers need not wire one, and `/metrics` still renders every counter it can
reach with empty histograms.

`GET /metrics` lives at `/metrics`, not under `/api/v1`, by Prometheus
convention. It carries no auth of its own — same posture as the mutating routes
(loopback bind + reverse proxy, #58).

**Storage latency is not instrumented.** The Phase 1 store is an in-memory ring;
a put is a slice write. It gets a histogram when a durable backend lands (#53).

### Structured logging is `log/slog`, and the standard `log` package is bridged

`log/slog` is stdlib as of Go 1.27, so there is no dependency question.
`obs.SetupLogging` builds a text or JSON handler at a configured level, calls
`slog.SetDefault`, and — crucially — points the standard `log` package's output
at a bridge writer. Roughly a dozen packages take an injected
`func(string, ...any)` that main backs with `log.Printf`; the bridge means every
one of those lines lands in the structured stream at info level (a `WARNING:` /
`ERROR:` prefix is promoted) without touching those packages. The daemon's own
entry-point lines and the HTTP access log are converted to `slog` with fields.

A full migration of every injected `logf` to a `*slog.Logger` is deliberately
**not** in this change: the bridge makes it unnecessary for correctness, and the
call-site churn would swamp the review. It can happen package by package later.

### Config

A `logging` block (`format`, `level`), validated at load, with
`SYNAPSE_LOG_FORMAT` / `SYNAPSE_LOG_LEVEL` overrides. `config` is a leaf package
and carries its own copy of the valid-value lists (like `alertClassNames`);
`TestLoggingValuesMatchConfig` in `internal/obs` pins the two together.
`obs.SetupLogging` returns a `*obs.Logger` wrapping a `slog.LevelVar`, so
`logging.level` is hot-reloadable (issue #59); `format` is not — a running
handler cannot swap its encoder.

## Consequences

- One new param-free setter on `api.Server` (`SetMetrics`) and one new field on
  `pipeline.Options` (`Metrics`). No change to `api.New`'s (already long)
  signature.
- `/api/v1/status` gains an `inference` block (scored count, failures, p50/p95/p99
  latency read approximately off the histogram, `by_class`).
- Metric names are all `synapseids_`-prefixed; counters end `_total`; capture
  counters carry a `source` label plus a `source="_all"` aggregate.
- The routine-2xx access log stays at info (it was plain text at that level
  before); 4xx/5xx are warnings. `logging.level=debug` is the knob for more.

## Alternatives rejected

- **Vendor `client_golang`.** A spec-level dependency decision for a format small
  enough to write in an afternoon.
- **`/metrics` as its own collector registry** with every subsystem registering
  callbacks. More moving parts than rendering the aggregates the API already
  holds; the two histograms are the only genuinely new instruments.
- **Keep `log.Printf` everywhere, wrap the output in JSON post-hoc.** Loses the
  structured fields that make a log query useful; slog gives them for free on the
  lines that matter.
