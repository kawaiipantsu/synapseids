# 0016 — Host and time aggregation lives in `internal/insight`, off the packet path

**Status:** Accepted, 2026-08-31

## Context

Phase 5 asks for three views that all need the same thing: aggregates the raw
record stores cannot answer.

- **Host profiles** (PROJECT.md §19.5, issue #39) — per observed address: first
  and last seen, volume, common protocols/ports/peers, classification mix.
- **Investigation mode** (§19.4, issue #40) — the same data pivoted around one
  selected host, plus its flows and verdicts.
- **Classification timeline** (§19.6, issue #41) — classification volume
  bucketed over time, with clicking a range filtering the lists.

What exists today is `storage.Store`: two bounded rings of `FlowRecord` and
`Classification` with no index beyond flow ID. `GET /api/v1/classifications`
already answers `disagreement=`, `class=`, `model=` and `min_confidence=` by
linearly scanning the newest 5000 rows — fine for a filter, useless for "every
host ever seen and how it behaves".

Three constraints shape the answer:

1. **The packet path must not slow down** (§22.1, §28.12). `pipeline.Run`'s flow
   callback already does feature extraction, inference and two store writes on
   the single flow-table goroutine. Whatever we add runs there too.
2. **Host data is untrusted and unbounded by nature** (§21, §28.11). The keys are
   IP strings decoded from packets. A `/16` sweep or a spoofed source range must
   not be able to grow the process without limit — the same discipline the flow
   table's cap and `storage.Mem`'s ring already apply.
3. **`internal/api` must stay off `flow`/`features`/`packet`.** Renderers never
   compute; the aggregation has to live behind something the handler just reads.

## Decision

A new package, **`internal/insight`**, owns the aggregates. It is **not** an
extension of `storage.Store`, and it is **not** a bus subscriber.

### Why not extend `storage.Store`

The aggregates are a derived, in-memory, deliberately lossy read model. Putting
them behind `Store` would oblige every future backend — SQLite, then ClickHouse
(§20) — to reimplement host profiles and bucket rings, when those backends will
want to answer the same questions with `GROUP BY` instead. Worse, it would put
the packet path and `GET /api/v1/hosts` on the same lock: `Mem` guards its rings
with one `sync.RWMutex`, and a reader holding `RLock` while it serialises several
hundred profiles blocks `PutFlow`, and therefore blocks packet ingestion. That is
exactly the coupling §22.1 forbids.

### Why not subscribe to the event bus

The bus is genuinely off the hot path, but it is lossy *by contract*: a slow
subscriber drops events and the drop is counted (§17). Dropping a rendering
update is fine; silently dropping a record that a running counter is
accumulating produces host profiles that are quietly wrong, with no way to tell
how wrong. Counters need a channel whose loss is measured against a known
denominator, not a fan-out that also serves the WebSocket. Deriving from
`ClassificationCreated` was also attractive because the event enum is frozen
(§28.5-6) and we must not add a type — but that argument does not require using
the *bus*, only that we not invent an event, and a direct hand-off invents
nothing.

### What it actually does

`pipeline.Options` grows one nil-safe field, `Observer`, a two-method-free
interface:

```go
type Observer interface {
    Observe(fr *storage.FlowRecord, cl *storage.Classification)
}
```

The pipeline calls it once per flow record, right after the verdict is stored and
published. `insight.Index.Observe` projects the pair into a ~120-byte compact
struct (no feature vector) and does **one non-blocking channel send** onto a
bounded queue, then returns. It takes no lock at all. A single aggregator
goroutine drains the queue and is the only writer of the maps and rings; the API
reads them under an `RWMutex` the packet path never touches. A full queue drops
and counts, like the bus.

Measured on this machine (13th-gen i9, `go test -bench`):

| operation | cost | allocations |
|---|---|---|
| `Observe` (packet-path side) | **88 ns/op** | **0** |
| `apply` (aggregator fold) | 226 ns/op | 0 |

`TestObserveDoesNotAllocate` asserts the zero, so a regression fails the build
rather than quietly re-entering the hot path. The aggregator is ~50× faster than
the feature-extraction and inference work per record it trails, so the queue does
not fill in practice: the end-to-end replay test asserts `Dropped == 0` after a
`--speed max` run.

### Bounding and eviction

Everything is capped, and every discard is counted in `Stats`, which is surfaced
on `GET /api/v1/status` under `insight`.

| structure | default cap | policy on overflow | counter |
|---|---|---|---|
| host map | 2048 hosts | drop the least-recently-active **quarter** in one pass | `hosts_evicted` |
| per-host ports | 128 distinct | keep the top half by count, drop the rest | `keys_pruned` |
| per-host peers | 128 distinct | keep the top half by count, drop the rest | `keys_pruned` |
| per-host recent flows | 16 refs | ring overwrite | — |
| timeline 1s ring | 900 buckets (15 min) | slot reuse | `timeline_late` |
| timeline 10s ring | 720 buckets (2 h) | slot reuse | `timeline_late` |
| timeline 1m ring | 1440 buckets (24 h) | slot reuse | `timeline_late` |
| ingest queue | 8192 | non-blocking drop | `dropped` |

Two consequences are deliberate and documented rather than hidden:

- **Batched eviction, not per-insert LRU.** Pruning a quarter of the host map in
  one O(n) pass every n/4 inserts is amortised O(1); a strict LRU would need a
  scan or an intrusive list on the aggregator's critical loop for no operational
  gain.
- **Top-N is exact for heavy hitters, lossy for long tails.** A scan of 60000
  one-hit ports evicts its own tail, so `top_ports` keeps the ports that matter
  and loses the noise. The per-host *totals* (`flows`, bytes, packets, class
  counts) are never pruned and stay exact. A test asserts precisely this:
  after 2000 one-hit ports plus 50 hits on 443, the totals are exact and 443
  leads the list.

The per-host recent-flow ring stores flow **IDs plus a few scalars**, not
records; the detail handler resolves the full record through `storage.Store.Flow`
if it needs one. 2048 hosts × 16 refs is a couple of megabytes, versus hundreds
if each held a 48-value feature vector.

### Volume vs verdict counting

A long flow emits periodic snapshot records carrying *cumulative* counters, and
each is classified. So:

- **flow counts and byte/packet volume** come only from terminal records — adding
  snapshots would double-count the same bytes;
- **classification counts, class mix and disagreements** come from every record,
  snapshots included, which keeps a host's class mix consistent with what
  `GET /api/v1/classifications` returns.

### API surface

Five read-only routes, in `internal/api/hosts.go` and `internal/api/timeline.go`,
one mux line each. The per-host collections reuse `parseClassFilters` verbatim,
so `class=`, `model=`, `min_confidence=` and `disagreement=` mean exactly what
they mean on `/api/v1/classifications` — operators learn one dialect. The `{ip}`
path value is re-parsed with `net/netip` and canonicalised, so a non-literal is a
`400` and `::ffff:10.0.0.1` cannot address the same profile under two spellings.

The unscoped timeline is served from the incremental ring. A `host=` or `class=`
scoped timeline is bucketed on demand from the newest window of stored
classifications instead: a ring per host would be unbounded, and this reuses the
same bounded scan the filtered classification query already performs.

### Security posture

These routes are read-only, so unlike model activation they need no explicit
action gate (no `TODO(#58)`). But a host profile is sensitive telemetry — it
enumerates every address the sensor has seen and characterises its behaviour — so
it inherits the daemon's loopback-only default and the standing requirement for
an authenticating proxy on any non-loopback listener (§21). Addresses are emitted
as plain JSON string values and rendered as text by the SPA; nothing interpolates
them into markup, and no view uses `dangerouslySetInnerHTML`.

## Consequences

- `api.New` takes a tenth parameter, `*insight.Index`. It may be nil: `/hosts`
  then returns `[]` and `/timeline` an empty series. Every read method on
  `*Index` is nil-safe.
- Both pipelines (live capture and replay) pass the same `Index`, so a replayed
  capture populates the views exactly as live traffic would (§6, §26).
- The aggregates are process-lifetime and vanish on restart. That is acceptable
  while `storage.Mem` is also volatile; when SQLite lands (§20) the host and
  timeline queries are natural candidates to move behind the store as real
  indexes, and this package is small enough to retire.
- `insight.Index.Sync()` exists for tests and the end-to-end replay assertion. The
  API never calls it — a request must not be able to pace the packet path.

## Deliberately deferred to Phase 7

`Profile.BaselineAvailable` and `Profile.AnomalyAvailable` are present and always
`false`; `Series.AnomalyAvailable` likewise. **Behavioural baseline, anomaly
trend, anomaly history and unusual-feature callouts (§19.4, §19.5, §19.6) are not
computed here and are not faked.** A baseline needs the Phase 7 anomaly/drift
work; emitting a zero line or a made-up "normal range" would be worse than
emitting nothing, because an operator cannot tell a fabricated baseline from a
real one. The SPA renders these as explicitly labelled Phase 7 stubs.

Related detections (§19.4) are also absent: there is no detections store and
nothing publishes `AlertCreated`, so `#/detections` keeps its placeholder rather
than being half-built.
