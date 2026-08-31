# 0027 — Detections dedup on `(src, dst, class)` in a first-occurrence window, and severity is derived from the class

**Status:** Accepted, 2026-08-31

## Context

`AlertCreated` has been in the frozen `event-envelope-v1` event list since Phase 1,
but nothing in the tree emitted it and there was no `/api/v1/detections` resource
(issue #117). EPIC Phase 5 closed on the strength of the investigation *views*
(Timeline, Hosts, Investigate, Matrix, Review) and the alert feed fell off the
board.

The gap is not "add a route". A verdict stream and a detection feed are different
things, and the two hard questions are what turn one into the other:

1. **What is one detection?** The pipeline produces one verdict per closed flow.
   An nmap `-p1-1000` sweep is 1000 flows, all `scan`, all from one host to one
   host. Publishing 1000 `AlertCreated` events and listing 1000 detections would
   make the feature actively harmful: it would flood the WebSocket at exactly the
   moment an operator needs it, and it would bury the one fact that matters
   ("10.0.0.66 is scanning 10.0.0.1") under a thousand rows.
2. **Where does severity come from?** An operator triages by urgency, not by
   class. `traffic-classes-v1` has no severity field, and it is frozen
   (PROJECT.md §9, §28.5-6).

## Decision 1 — dedup on `(src_ip, dst_ip, class)`, in a window anchored at the first occurrence

`internal/alert` keeps a bounded set of detections keyed by
`(src_ip, dst_ip, class)`. A verdict that hits a live detection for its key
increments `count`, advances `last_ts`, raises `confidence` if higher, ORs
`disagreement`, and appends the flow id — **and publishes nothing**.

### Why the ports are not in the key

They are the whole point. `(src, dst, class, dst_port)` reproduces the 1000-row
flood exactly, because a port sweep varies precisely the field that would be in
the key. Excluding the ports is what collapses a sweep, and it is what makes
`dst_port` on a scan detection mean "the first port we saw", not "the port".
`Detection`'s doc comment says which of its fields come from the first
occurrence, which from the most recent, and which from the highest-confidence
one, because a reader who assumes "all of them describe the same packet" would be
wrong.

### Why the window is anchored, not sliding

A window that slides forward on every hit (`now - last_ts <= window`) collapses a
sustained attack into a single detection that alerts once and then goes silent
forever. A four-hour brute force would produce one `AlertCreated` at minute zero
and nothing after — the operator who joined at hour two sees a stale row rather
than an alert.

So the window is anchored at the detection's **first** occurrence: while
`ts <= first_ts + dedup_window_sec` the detection absorbs; past that, a fresh
detection opens. Sustained activity therefore re-alerts once per window. The
measured result on the reference capture (a real ~3-minute MySQL brute force) is
**three** detections with counts 126 / 121 / 57 rather than one silent row or 304
noisy ones.

### The clock is the record's timestamp, not wall clock

`Store.apply` compares `cl.TS` — packet time — against the window, never
`time.Now()`. A `--speed max` replay of a 30-minute capture completes in a
second; on a wall clock the whole capture would fall inside one 60s window and
dedup would behave differently from live capture, breaking the §26 promise that
replayed traffic reaches the UI exactly as live traffic does. A timestamp *before*
the anchor (sensor clock skew, an out-of-order record) is treated as in-window:
absorbing a late record is better than re-opening a detection because of skew.

### Consequences accepted

- **A detection is a summary, not an index.** `flow_ids` holds the 20 most recent
  *distinct* flows; `count` always reports the true number of occurrences. The
  flow log stays the system of record. `flow_ids` is deduplicated because one
  long-lived flow contributes both periodic snapshot verdicts and a terminal one
  — counting those twice is correct, listing the flow twice is just confusing.
- **Bounded, like everything else fed by packet-derived data** (§21, §28.11). The
  retained set is a fixed ring of `alerts.max_recent` (default 1000), oldest
  evicted first and counted, mirroring `storage.Mem`. `evicted` is on both
  `/api/v1/status` and every `/api/v1/detections` response, so a client can tell
  a window from a history. Evicting a detection also drops its dedup entry, so an
  evicted key can alert again rather than being silently muted forever.

## Decision 2 — severity is derived from the class, in code, and covering the frozen list is a startup gate

`internal/alert` owns a single table:

| class | severity |
|---|---|
| `normal` | *never alerts* |
| `suspicious` | `low` |
| `scan` | `medium` |
| `brute_force`, `web_attack` | `high` |
| `dos_ddos`, `botnet_c2` | `critical` |

Three things follow from where this table lives.

**Not in the schema.** `traffic-classes-v1` describes what a model *predicts*, and
a model predicts a class, never an urgency. "A scan is medium" is an operational
judgement that should be revisable without a schema version — and adding a field
to a frozen contract is not available anyway (§28.5-6).

**Not in config.** An `alerts.severity` override block would let a deployment
produce a class with an empty severity: a detection no `severity=` filter can
select and no operator can triage. `config.Load` rejects the key outright
(`DisallowUnknownFields`), and a test says so on purpose so the intent survives.
What *is* configurable is the thing that should be — the confidence threshold, per
class.

**Missing coverage is a startup error.** `alert.init()` walks
`schema.TrafficClassesV1().Classes` and panics if any non-`normal` class has no
severity, and panics again if the table names a class the schema does not have. A
future `traffic-classes-v2` therefore cannot ship a class that quietly produces
`"severity": ""`; it fails at process start, in both directions.

`internal/config` cannot import `schema` (it is a leaf — see
`docs/architecture.md`), so it carries its own copy of the class names to validate
`per_class_min_confidence` keys, exactly as it already does for
`captureFilterNames`. `TestConfigAlertClassNamesMatchSchema` in `internal/alert`,
which legitimately imports both, fails if the copy drifts.

## Decision 3 — the packet path only does a channel send

`internal/pipeline` publishes `ClassificationCreated` and, on disagreement,
`ModelDisagreementDetected`. It deliberately does **not** publish `AlertCreated`.
Dedup needs mutable state that the packet path must neither own nor lock, so
`Options.Alerts` gets one non-blocking send per verdict (`0 allocations`, pinned by
`TestObserveDoesNotAllocate`) and `alert.Store`'s own goroutine applies the
policy, folds the detection and publishes. This is the pattern `internal/insight`
already established (ADR 0016) rather than a third one: bounded queue, single
aggregator, drops counted, `Sync()` for tests only.

A full queue drops and counts (`status.alerts.dropped`), because losing a
detection is better than stalling ingestion (§17, §22, §24).

## Alternatives rejected

- **A `storage.Store` index.** Would force every future backend (SQLite,
  ClickHouse) to reimplement dedup, and would put a `/api/v1/detections`
  serialisation on the same lock as the packet path.
- **Publishing `AlertCreated` per verdict and deduplicating in the browser.** The
  flood is the problem; moving it downstream does not fix it, and every client
  would have to reimplement the policy.
- **Notification delivery (email / webhook / syslog).** Explicitly out of scope
  for #117 and still unowned; a detection feed is a prerequisite for it, not a
  substitute.
- **Anomaly-driven detections.** Tracked separately (#47). Only supervised class
  verdicts alert today.

## Consequences

- `GET /api/v1/detections[/{id}]`, `alerts.*` counters on `/api/v1/status`, and a
  real `AlertCreated` event on the live channel.
- The route is stricter than the older collection routes: an unknown or
  unparseable query parameter is a `400`, not an ignored one. On a route whose job
  is "show me what matters", a typo that silently widens the result to everything
  is worse than an error.
- **The heuristic is what limits the feed's quality, and that is visible.** On the
  reference capture the classifier misses the nmap recon entirely (#90), so the
  detections are `brute_force` / `web_attack` / `dos_ddos` and there is no `scan`
  row at all. The thresholds were not tuned to hide that: a detection feed that
  reports what the model actually said is the honest input to fixing the model.
