# Architecture

SynapseIDS is a one-way data plane with thin readers hung off the end of it.
Packets become flows, flows become a frozen feature vector, the vector is
scored, and the results are stored and published. The REST API and the live
WebSocket channel only ever read what the pipeline already produced.

This document describes the code as it exists in Phase 1 (PCAP replay end to
end). See [PROJECT.md](../PROJECT.md) §2, §3, §5, §26 for the intended shape and
[CLAUDE.md](../CLAUDE.md) for the package-boundary rules.

## Data plane

```
 capture.Source        packet          flow             features          inference
 ┌───────────┐       ┌────────┐     ┌──────────┐      ┌──────────┐      ┌────────────┐
 │ PCAPFile  │ raw   │ Decode │ pkt │ Table    │ rec  │ Extract  │ vec  │ Runtime    │ result
 │  └ Replay │──────▶│ (L2→L4)│────▶│ lifecycle│─────▶│ 48 values│─────▶│  └Heuristic│───┐
 └───────────┘ frames└────────┘     └────┬─────┘      └──────────┘      └────────────┘   │
      ▲                                  │      internal/pipeline · Run() drives this row │
      │ ctx                              │                                               │
 cmd/synapsed                            │ pipeline.Run() calls, per flow.Record:        │
 replayController                        │   store.PutFlow / PutClassification           │
 (one replay at a time)                  │   bus.Publish(FlowClosed|FlowUpdated,         │
                                         │               FeaturesGenerated,             │
                                         │               ClassificationCreated, …)      │
                                         ▼                                              ▼
                                  ┌─────────────┐                              ┌────────────────┐
                                  │ events.Bus  │                              │ storage.Mem    │
                                  │ fan-out,    │                              │ bounded ring   │
                                  │ bounded subs│                              │ (flows + class)│
                                  └──────┬──────┘                              └───────┬────────┘
                                         │ Subscribe(depth)                           │ Recent*/Flow(id)
                                         ▼                                            ▼
                        ┌───────────────────────────────────────────────────────────────────┐
                        │ internal/api                                                       │
                        │   REST  /api/v1/*        (reads storage + runtime + schema)        │
                        │   pump  batches bus events every live.websocket_batch (100ms)      │
                        │   wshub.Hub  fans each batch to clients, drops the slow ones        │
                        └────────────────────────────────┬──────────────────────────────────┘
                                            HTTP + WebSocket (/api/v1)
                                                         ▼
                              browser (web/ — React SPA)  ·  synapse CLI
```

Adapted from PROJECT.md §3. The SQLite store, sensors and React SPA in that
diagram are not in the tree yet; the offline Python trainer now exists under
`trainer/` but is not yet wired to a running daemon (see
[What is not here yet](#what-is-not-here-yet)).

## The hard rule

`capture → packet → flow → features → inference → (events, storage, api)` is a
**one-way** pipeline (PROJECT.md §2.5, §2.19, §28.4). Data only ever moves right.

- **Measurement lives in `flow` and `features`.** `flow.Record` carries raw
  accumulators; `flow.Record`'s methods and `features.Extract` turn those into
  the 48 numbers. Nothing else computes a feature.
- **Renderers never measure.** `internal/api` imports `storage`, `inference`,
  `schema` — not `flow`, `features` or `packet`. It serves structs the pipeline
  already filled in. `synapse` and the `web/` SPA do the same over HTTP.
- **Normalization is a per-model concern** (PROJECT.md §11). `pipeline.Run`
  hands `inference.Runtime` the **raw** vector. The Phase-1 `Heuristic` reads raw
  values directly. A trained model applies the `normalizer.json` from its own
  bundle: `inference.ONNXModel` takes that as an optional `Normalizer` and
  applies it before handing the vector to the `internal/nn` executor. When none
  is supplied it feeds raw values, exactly like the heuristic. `internal/features`
  ships `Identity` and `Log1p` helpers but the pipeline does not call them.

## Package responsibilities

One row per `internal/` package (plus the two embed packages). "Must not import"
lists the edges that would break the one-way rule; all of them are currently
respected.

| Package | Owns | Imports | Must not import |
|---|---|---|---|
| `packet` | Bounds-checked decode of Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP into the normalized `Packet` (timestamps, tuple, TCP flags/window, lengths). Never keeps payload bytes. | stdlib only | anything else in the tree |
| `capture` | `Source` interface + adapters: `PCAPFile` (classic pcap plus a minimal read-only pcapng reader — SHB/IDB/EPB/SPB, Ethernet or RAW), `Replay` (paces an inner source to wall-clock × speed), `AFPacket` (Phase 3 — stdlib-only Linux `AF_PACKET` raw socket; built-in cBPF filter presets; `Stats.Drops` from `PACKET_STATISTICS`; non-Linux stub), and `PCAPOverIP` (Phase 3 — a framed, authenticated, versioned TLS stream from a remote sensor; sub-package `capture/pcapoverip` holds the SYNPOIP wire protocol, a reference server and a self-signed-cert helper; [ADR 0012](adr/0012-pcap-over-ip-transport.md), `capture/pcapoverip/PROTOCOL.md`). `Manager` runs N sources and merges them into one stream for a single pipeline goroutine, isolating a failed source; it is itself a `Source`, and surfaces a source's TLS `connection_latency_ms` and sensor-advertised filter when the source reports them. `Stats` counters (incl. `Drops`). See [ADR 0010](adr/0010-live-capture-af_packet-and-the-source-manager.md). | `packet`, `capture/pcapoverip` | `flow`, `features`, `inference`, `storage`, `events`, `api`, `config` |
| `flow` | `Key` (direction-normalized 5-tuple), `Record` (raw accumulators + derived-stat methods), `Table` (lifecycle: open, fold, snapshot, close, evict, TIME_WAIT grace). Single-goroutine. | `packet` | `features`, `inference`, `capture`, `storage`, `events`, `api` |
| `schema` | The frozen contracts: typed views of `flow-features-v1`, `traffic-classes-v1`, `BundleMeta` + `ValidateBundle`, and `Architecture` + `ValidateArchitecture` plus the shared `ParameterCount` / `ApproxBytes` / `RoughFLOPs` / `LayerBreakdown` estimate math (ported from the trainer). `init()` panics on drift. | `schemas` | everything else internal |
| `features` | `Extract(flow.Record) → Vector` (the 48 `flow-features-v1` values); `Normalizer` interface with `Identity` / `Log1p` and the fitted `Affine` (`NewStandardNormalizer` / `NewMinMaxNormalizer`). No raw-IP arithmetic. | `flow`, `packet`, `schema` | `inference`, `storage`, `events`, `capture`, `api` |
| `nn` | Dependency-free, CGO-free ONNX executor for the feed-forward MLPs the trainer emits: a hand-rolled protobuf-wire reader plus a batch-1, all-`float32`, deterministic graph runner over a fixed op subset (`Gemm`, `MatMul`, `Add`, `Relu`/`LeakyRelu`/`Sigmoid`/`Tanh`, `BatchNormalization`, `Dropout`, `Softmax`, `Identity`, `Flatten`, `Reshape`, `Constant`). Unknown op → load error; malformed model → error, never a panic. `Load`/`LoadFile`/`Model.Run`. See [ADR 0005](adr/0005-go-onnx-inference-runtime.md). | stdlib only | everything else internal |
| `inference` | `Classifier` interface, `Role`, `Runtime` (scores a vector through every model, records each `ModelOutput`, flags disagreement, picks the primary; `Activate` / `Deactivate` / `SetModels` swap the live model set atomically under an `RWMutex`), the rule-based `Heuristic`, and `ONNXModel` — the adapter that makes a loaded `nn.Model` a `Classifier` (with an optional per-model `Normalizer`). | `features`, `schema`, `nn` | `storage`, `events`, `capture`, `flow`, `api`, `pipeline` |
| `model` | `Load(dir)` for the five-file bundle; `Bundle` (inactive — `Meta` / `Normalizer` / `Metrics` / `Recipe` / `ONNXPath` / `Hash`); `Validate()`, the pre-activation gate; `Scan(dir, primary, logf)`, the startup sweep. `Metadata.DerivedFrom` (optional `derived_from`) feeds registry lineage. Activates nothing. | `features`, `schema` | `inference`, `pipeline`, `api`, `flow`, `packet`, `capture`, `storage`, `events` |
| `registry` | The model registry with lineage (§15, §19.12). `Open(dir, logf)` loads `registry.json` (atomic rewrite, corrupt-tolerant); `Register(*model.Bundle)` gates + records an `Entry`; `List` / `Get` / `Lineage` / `Children` / `Tree` / `Active`; `SetStatus` (`registered` → `active` → `deactivated`, one active at a time, reconciled to `deactivated` on restart). Runs no model. | `model`, `schema` | `api`, `pipeline`, `flow`, `features` |
| `modelrun` | `Build(id, *model.Bundle) → inference.Classifier`: `nn.LoadFile` the graph, bridge the bundle's `normalizer.json` into `inference.Normalizer`, wrap with `inference.NewONNXModel`. The seam from "bundle passed the gate" to "model is scoring". | `features`, `inference`, `model`, `nn` | `api` |
| `audit` | Append-only JSONL (`audit.log`, next to the bundles): one `{ts,event,actor,model_id,detail}` line per `ModelRegistered` / `ModelActivated` / `ModelDeactivated` (§21, §28.14). `actor` is `"local"` until RBAC (#58). Never blocks a request. | stdlib only | `api` |
| `modeltest` | Test-only: `Write(dir, Bundle)` produces a valid, gate-passing five-file bundle with a real runnable 48→8→7 `model.onnx`, so registry/api/modelrun tests exercise register→activate→score without a committed binary fixture. | `nn/onnxbuild` | (tests only) |
| `events` | In-process fan-out `Bus`: `Publish` (non-blocking), `Subscribe(depth)`, per-sub + bus drop counters, monotonic `seq`. Event type constants. | stdlib only | every other internal package (kept a leaf) |
| `storage` | `Store` interface, `FlowRecord` / `Classification` DTOs, `FlowRecordFrom`, and `Mem` (fixed-capacity ring buffers, oldest evicted + counted). | `features`, `flow`, `inference` | `capture`, `events`, `api`, `pipeline` |
| `wshub` | Dependency-free RFC 6455 server (`Upgrade`, text frames, ping/pong, disconnect detection) and `Hub` (per-client bounded send queue, drops slow clients). | stdlib only | `api`, `events`, `pipeline` |
| `pipeline` | The wiring. `Run(ctx, src, rt, bus, store, opt)` consumes a `Source` to completion, driving `flow → features → inference → store + publish` on one goroutine. | `capture`, `events`, `features`, `flow`, `inference`, `storage` | `api`, `wshub` |
| `api` | Versioned REST surface, the `/api/v1/stream` WebSocket, the event `pump` (bus → batched JSON arrays → `Hub`), `ReplayController` and `CaptureStatusProvider` interfaces (the latter backs `GET /api/v1/captures[/{name}]`), the `/api/v1/models*` routes (registry view + explicit `activate` / `deactivate` against the live `Runtime`), static file serving. | `audit`, `capture`, `config`, `events`, `inference`, `model`, `modelrun`, `registry`, `schema`, `storage`, `version`, `wshub`, `web` | `pipeline`, `flow`, `features`, `packet` |
| `config` | Load one JSON file + `SYNAPSE_*` env overrides onto `Default()`; validate; `LoopbackOnly()`. JSON only (see [ADR 0002](adr/0002-flow-features-v1-frozen-and-json-config.md)). | stdlib only | everything else internal |
| `version` | Build metadata stamped by `-ldflags`. | stdlib only | everything else internal |
| `schemas` | `//go:embed` bytes of the three schema JSON documents. | `embed` | — |
| `web` | `//go:embed all:dist` — the built React SPA served at `/` (source in `web/ui/`, committed build output in `web/dist/`; see [ADR 0004](adr/0004-react-spa-and-committed-build-output.md)). `FS()` returns the `dist` subtree. | `embed` | — |

`cmd/synapsed` composes `config` + `events` + `storage.Mem` + `inference.Runtime`
+ `api.Server` and owns the `replayController` (which is the only caller of
`pipeline.Run`). At startup it also calls `model.Scan` over `models.directory` to
load and validate any bundles present — a logging-only diagnostic that adds
nothing to the runtime (see [Model bundles](#model-bundles)). `cmd/synapse` is a
pure HTTP client of the API. `cmd/synapse-sensor` is a version-only placeholder
(Phase 6).

## Flow lifecycle

`flow.Table` (see `internal/flow/table.go`) turns packets into `Record`s. Timers
come from `config.Capture` (`flow_idle_timeout` 30s, `flow_max_lifetime` 5m,
`snapshot_interval` 60s, `max_flows`). PROJECT.md §7.

**States**

- **open** — the first packet for a `Key` (that survives the grace check below)
  allocates an `entry` and a flow ID. Initiator/responder are fixed from that
  packet, except a bare `SYN|ACK` flips them so the true initiator is recorded
  regardless of capture order.
- **accumulate** — `fold()` folds each subsequent packet in: total and
  per-direction packet and byte counts, payload lengths, min/max/sum/sum-of-squares of packet
  size, small/large packet tallies, global and per-direction inter-arrival gaps,
  TCP flag counts, and TCP window sum. Direction is decided by matching the
  packet's source against the stored initiator/responder endpoints, falling back
  to tuple orientation for ICMP.
- **sweep** — `Tick(now)` is called by `pipeline.Run` roughly every 512 packets
  or every 1s of capture time, with `now` = the latest packet timestamp. It
  checks max-lifetime, then idle, then due snapshots.
- **emit** — every snapshot and every close calls the `onFlow` callback with an
  immutable copy of the `Record`, tagged with a `Reason`.

**The five close reasons** (`flow.CloseReason`), each terminal — the entry is
deleted from the table:

| Reason | Constant | Trigger |
|---|---|---|
| `fin_rst` | `ReasonFINRST` | TCP: any `RST` seen, or `FIN` observed in **both** directions. The `Key` then enters the recently-closed set. |
| `idle` | `ReasonIdle` | `now - LastSeen ≥ flow_idle_timeout`. |
| `max_lifetime` | `ReasonMaxLife` | `now - FirstSeen ≥ flow_max_lifetime`. Checked before idle. |
| `capture_end` | `ReasonCapEnd` | `Table.Flush()` — the source is exhausted or the run is cancelled; every remaining flow is closed. |
| `evicted` | `ReasonEvicted` | `max_flows` exceeded on open → the entry with the oldest `LastSeen` is force-closed. Counted separately in `Stats.Evicted`. |

**Snapshots** (`ReasonSnapshot`) are **not** a close. When `snapshot_interval > 0`,
a still-open flow emits a `Record` copy every interval with an incrementing
`SnapshotIndex` (surfaced as feature #47, `snapshot_index`), so a long-lived flow
is classified without waiting for teardown (PROJECT.md §7). The pipeline maps a
snapshot to `FlowUpdated` and a close to `FlowClosed`.

**Recently-closed grace window** — after a `fin_rst` teardown the `Key` is held
in `recentDown` for `graceWindow = 3s`. A non-`SYN` packet for that `Key`
arriving inside the window (a trailing ACK, a lingering retransmit) is dropped
instead of opening a phantom one-packet flow; a `SYN` starts a fresh flow
immediately. `Tick` also ages entries out of `recentDown`.

## Event bus contract

`events.Bus` (see `internal/events/events.go`), PROJECT.md §17, §22.

- **Non-blocking publish.** `Publish(type, data)` stamps an envelope
  (`type`, `ts` RFC3339Nano UTC, monotonic per-process `seq`, `data`) and does a
  non-blocking send to every subscriber. It never waits on a consumer.
- **Bounded per-subscriber queue.** `Subscribe(depth)` allocates a buffered
  channel (`depth`, floored at 1). The API pump subscribes with
  `depth = live.client_queue_size` (default 5000).
- **Drop counter.** A send that would block increments that subscriber's
  `Dropped()` counter and the bus-wide `dropped` counter. `Bus.Stats()` returns
  `(published, dropped, subscribers)`, surfaced at `/api/v1/status` under
  `events`.

**Event types** — from `schemas/events/event-envelope-v1.json` (`frozen: true`),
matched exactly by the constants in `events.go`:

```
CaptureSourceConnected      FeaturesGenerated            ModelRegistered
CaptureSourceDisconnected   ClassificationCreated        ModelActivated
FlowStarted                 ModelDisagreementDetected    ModelDeactivated
FlowUpdated                 AlertCreated                  SensorConnected
FlowClosed                  ReviewUpdated                 SensorDisconnected
                            ReplayStarted
                            ReplayProgress
                            ReplayFinished
```

Phase 1 actually publishes `FlowUpdated`, `FlowClosed`, `FeaturesGenerated`,
`ClassificationCreated`, `ModelDisagreementDetected` (from `pipeline.Run`) and
`ReplayStarted` / `ReplayProgress` / `ReplayFinished` (from `replayController`).
The rest are defined so consumers can bind to them now; nothing emits them yet.
The envelope schema is embedded but is not served over HTTP (only
`/api/v1/schemas/features` and `/api/v1/schemas/classes` are).

## Concurrency

- **`flow.Table` is single-goroutine.** It has no locks and its doc comment says
  so. `pipeline.Run` is the only writer: one goroutine reads the capture
  channel, calls `Observe`/`Tick`/`Flush`, and runs the `onFlow` callback
  (feature extraction, scoring, `store.Put*`, `bus.Publish`) inline. Everything
  in one run is therefore serialized.
- **`events.Bus` and `wshub.Hub` are concurrent-safe.** `Bus` guards its
  subscriber map with an `RWMutex` and uses atomic counters; `Publish` runs
  under `RLock`. `Hub` guards its client set with an `RWMutex`, runs one writer
  goroutine per client, and uses atomic counters. `storage.Mem` guards its rings
  with an `RWMutex`, so API reads race-free against the pipeline's writes.
- **The replay controller runs one replay at a time.** `replayController.Start`
  refuses to start while `status.Running` is set; `Stop` cancels the run's
  context. A separate `progress` goroutine ticks `ReplayProgress` every 500ms.
- **`capture.Manager` fans N live sources into one channel.** One forwarder
  goroutine per source copies packets into a single shared output channel that a
  dedicated `pipeline.Run` consumes — so the `flow.Table` it feeds is still
  touched by exactly one goroutine. Channel sends from many goroutines are safe;
  the fan-in is `-race`-clean. A source that returns a terminal error has its
  forwarder marked `error` and stopped without disturbing the others or the
  pipeline. A once-a-second sampler goroutine computes per-source `pps`/`bps`
  off the packet path. The daemon runs this alongside the replay pipeline; both
  share one `IDGen` so flow IDs stay globally unique.
- **`capture.Replay` paces on the emit goroutine.** For a fractional/×N speed it
  sleeps on a `time.Timer` between packets; at `--speed max` there is no sleep,
  so it calls `runtime.Gosched()` every 256 packets to stay off the scheduler's
  back and keep the API responsive on a single-CPU host (issue #71).
- **The API pump is its own goroutine**, started by `Server.Run`, holding one bus
  subscription and one `time.Ticker`.

## Web UI

The operator console is a TypeScript + React 18 SPA, bundled with Vite 5
([ADR 0008](adr/0008-react-spa-and-committed-build-output.md), PROJECT.md §19,
§27). It is a pure REST + WebSocket client — like `synapse`, it never computes a
feature.

- **Source** is `web/ui/` (`src/**`, `package.json`, `package-lock.json`,
  `vite.config.ts`). `make web` runs `npm ci && npm run build`; `make web-dev`
  serves it with `/api` and `/api/v1/stream` proxied to `127.0.0.1:8080`;
  `make web-check` is `tsc --noEmit`.
- **Build output** is `web/dist/` — content-hashed JS/CSS plus `index.html`,
  **committed to the repo** and embedded by `web/web.go` (`//go:embed all:dist`).
  `go build`, `make build-linux` and CI never run Node. Rebuild and commit
  `web/dist/` after any `web/ui/` change.
- **Routing is hash-based** (`/#/flow-log`): every document request stays on `/`,
  so `internal/api` needs no SPA-fallback route. A `StreamProvider` opens the one
  WebSocket, polls `/api/v1/status` once a second, fans event batches to
  subscribers, and keeps rolling client-side aggregates for the Dashboard.
- **Wired views:** Dashboard, the full-screen Flow Log, the Flow Inspector
  (`GET /api/v1/flows/{id}` joined to `GET /api/v1/schemas/features`), Replay
  control, and the ML ▸ Architecture builder (`POST
  /api/v1/architecture/estimate`; locked 48/7 edges, editable hidden stack, live
  parameter/size/FLOP estimates, `schema.Architecture` export). Every other §19
  route is a "Planned — Phase N" placeholder.

## Model bundles

`internal/model` (issue #25) loads a trained-model bundle and checks it against
the frozen contracts before anything could activate it (PROJECT.md §11, §28.6,
§28.10). See [ADR 0006](adr/0006-model-bundle-format-and-validation.md) for the
exact `metadata.json` / `normalizer.json` shapes.

A bundle is a directory of five files: `model.onnx` (opaque here — only hashed),
`metadata.json` (the §11 descriptor), `normalizer.json` (the fitted per-feature
input transform), and `metrics.json` + `training-recipe.json` (required to be
present and parse, otherwise uninterpreted).

- **`model.Load(dir)`** reads all five, parses the four JSON files, recomputes
  `sha256:<hex>` over the `model.onnx` bytes, and returns an **inactive**
  `*Bundle` (`Meta` / `Normalizer` / `Metrics` / `Recipe` / `ONNXPath` /
  `Hash`). Loading never activates.
- **`Bundle.Validate()`** is the gate. It rejects — naming the field — a missing
  or non-JSON file; a `feature_schema` / sizes mismatch (`schema.ValidateBundle`);
  a missing or wrong-sized `architecture` (`schema.ValidateArchitecture`); an
  empty `family`, non-positive `parameter_count`, or non-RFC3339 `created_at`; a
  `model_hash` without the `sha256:` prefix or not equal to the recomputed hash;
  or a `normalizer.json` with the wrong schema, an unknown method, or (for
  `standard` / `minmax`) not exactly 48 ascending in-order entries with
  `std > 0` / `min < max`.
- **The normalizer bridge.** `Bundle.Normalizer()` returns `features.Identity`
  for method `identity`, or a fitted `features.Affine` for `standard`
  (`(x-mean)/max(std,1e-9)`) / `minmax` (`(x-min)/max(max-min,1e-9)`). This is a
  **per-model** transform on the trained-model path only — the heuristic still
  reads raw features and `pipeline.Run` never installs a normalizer.
- **`model.Scan(dir, primary, log.Printf)`** runs once at `synapsed` startup
  (skipped if `dir` is absent). It `Load`+`Validate`s every immediate
  subdirectory and logs `loaded model "<dir>" (family …, N params) — INACTIVE`
  or `rejected model bundle "<dir>": <reason>`. Nothing is added to
  `inference.Runtime`.
- **`model.Executor`** (`Run([]float32) ([]float32, error)`) and `Bundle.Bind`
  are the unused seam for a future in-bundle execution backend; validation stays
  runtime-free.

## Model registry and explicit activation

`internal/registry` (issue #26) turns the validated bundles from `model.Scan`
into a persistent, inspectable registry with derived-from lineage, and
`internal/modelrun` + `inference.Runtime.Activate` are the seam that makes one of
them live. See [ADR 0009](adr/0009-model-registry-lineage-and-explicit-activation.md).

- **Startup.** `cmd/synapsed` `Open`s the registry over `cfg.Models.Directory`
  (loading `registry.json`), then `Register`s every bundle `Scan` returned. A
  rejected bundle is logged. A bundle named by `models.primary` only gets a log
  line pointing at `POST /api/v1/models/{id}/activate` — **nothing is
  auto-activated** (§28.10). `inference.Runtime` still starts with only the
  heuristic.
- **`Entry`** carries the §11 metadata plus `content_hash`, `artifact_bytes`,
  `derived_from`, `status` (`registered` / `active` / `deactivated`),
  `registered_at`, `activated_at` and the on-disk `dir`. `registry.json` is
  rewritten atomically (temp file + rename); a missing or corrupt file is logged
  and the registry starts empty.
- **Lineage.** `Lineage(id)` walks `derived_from` to the root; `Children(id)` and
  `Tree()` give the forest for the §19.12 UI. A cycle or an unregistered parent
  terminates the walk.
- **Activation** (`POST /api/v1/models/{id}/activate`) re-loads and re-validates
  the bundle, `modelrun.Build`s the `Classifier` (`nn.LoadFile` +
  `normalizer.json` bridge + `inference.NewONNXModel`), then
  `Runtime.Activate(cls)` swaps the live model set atomically and
  `registry.SetStatus(id, "active")` demotes any prior active entry. A
  `ModelActivated` line is appended to `audit.log`. `deactivate` calls
  `Runtime.Deactivate()`, restoring the heuristic. Activation does not survive a
  restart: a persisted `active` entry is reconciled to `deactivated` on load.
- **Audit** (`internal/audit`). Every register / activate / deactivate appends
  one `{ts,event,actor,model_id,detail}` line to `audit.log` (JSONL, next to the
  bundles) and mirrors it to the structured log — the durable record (§21,
  §28.14). `actor` is `"local"` until RBAC (#58). The matching
  `ModelRegistered` / `ModelActivated` / `ModelDeactivated` envelopes — which are
  already members of the frozen `event-envelope-v1` enum — are also published on
  the live bus, so the SPA registry view can update without polling. No new
  envelope type is introduced.

## What is not here yet

Phase 1 is the vertical slice. Everything below is deliberately absent and
tracked as an EPIC (issues exist; see PROJECT.md §26).

| Missing | Present instead | Tracked |
|---|---|---|
| Live capture — tcpdump stream, SSH `tcpdump`; a pcap-filter-expression compiler; PCAP-over-IP client reconnect/backoff; runtime add/remove of sources; live-capture flow-table stats on `/api/v1/status` | **Local NIC capture is wired** (`capture.AFPacket` + `capture.Manager`, `synapsed --capture <iface>` / `capture.sources[]`, `GET /api/v1/captures`; [ADR 0010](adr/0010-live-capture-af_packet-and-the-source-manager.md)). **PCAP-over-IP is wired** (`capture.PCAPOverIP` client + `synapse-sensor pcap-over-ip` reference server over TLS; [ADR 0012](adr/0012-pcap-over-ip-transport.md)) — no auto-reconnect yet. Filters are built-in cBPF presets (`ip`, `ip6`, `ip-any`, `not-arp`) only. `capture.PCAPFile` + `capture.Replay` still handle classic pcap and minimal pcapng. | see EPIC: Phase 3 (#28, #31 done; only #32 capture-sources UI left) |
| Anomaly / location / global / experimental model roles wired end to end | `internal/nn` runs ONNX MLPs; `inference.ONNXModel` adapts them to `Classifier`; `internal/model` loads and validates the five-file bundle; `internal/registry` records it with lineage; `POST /api/v1/models/{id}/activate` compiles it and swaps it into `inference.Runtime` as the single `RolePrimary`, `deactivate` restores `inference.Heuristic` (issues #24–#26; [ADR 0009](adr/0009-model-registry-lineage-and-explicit-activation.md)). Multi-model ensembles (a trained primary *and* a shadow/anomaly peer at once) are not wired yet — `Runtime.SetModels` is the seam. The offline `synapse-trainer` lives in `trainer/` ([ADR 0007](adr/0007-python-trainer-and-bundle-export.md)). | see EPIC: Phase 2 / 7 |
| SQLite (then ClickHouse) persistence | `storage.Mem` bounded ring; `config` recognizes `driver: sqlite` but `validate()` rejects it as "not implemented yet" | see EPIC: Phase 2 (SQLite), Phase 8 (ClickHouse) |
| Distributed sensors — raw/flow/feature modes, sensor identity, reconnect, `/api/v1/sensors` | `cmd/synapse-sensor` prints its version, plus a working `pcap-over-ip` subcommand that serves a capture file to `synapsed` over the framed, authenticated SYNPOIP transport ([ADR 0012](adr/0012-pcap-over-ip-transport.md)) | see EPIC: Phase 6 |
| The rest of the §19 UI — Investigate, Hosts, Detections, Sources, Sensors, Model registry, Training, Datasets, Model compare, Drift, Performance, Storage, Settings | React SPA (`web/ui/`, built into the embedded `web/dist/`) with the Dashboard, Flow Log, Flow Inspector, Replay control and the Architecture builder wired; every other route is a "Planned — Phase N" placeholder | see EPIC: Phase 2 / 3 / 4 / 5 / 6 / 7 (per view) |
| Anomaly model, model compare, drift, human review, datasets, training UI | — | see EPIC: Phase 4, Phase 5, Phase 7 |
| YAML config, retention sweeper, host/investigation/detection API groups | JSON config; rings are size-bounded, not time-bounded | see EPIC: Phase 2 ([ADR 0002](adr/0002-flow-features-v1-frozen-and-json-config.md)), Phase 5 |

---

⟦THUGS⟧ (c) 2026
