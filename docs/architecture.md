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

Adapted from PROJECT.md §3. The SQLite store and sensors in that diagram are not
in the tree yet. The offline Python trainer under `trainer/` does not run inside
the daemon (PROJECT.md §5.4) but now reports run progress to it over HTTP for the
live training dashboard (`internal/training`, `/api/v1/training*`,
[ADR 0019](adr/0019-external-training-runs-reported-over-http.md)); it does not
yet hand back a registered model bundle end to end (see
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
| `capture` | `Source` interface + adapters: `PCAPFile` (classic pcap plus a minimal read-only pcapng reader — SHB/IDB/EPB/SPB, Ethernet or RAW), `Replay` (paces an inner source to wall-clock × speed), `AFPacket` (Phase 3 — stdlib-only Linux `AF_PACKET` raw socket; built-in cBPF filter presets; `Stats.Drops` from `PACKET_STATISTICS`; non-Linux stub), `BPFDevice` (Phase 6 — the FreeBSD half of the same job: stdlib-only `/dev/bpf`, ioctl request numbers derived by hand from `sys/ioccom.h` and pinned against `syscall.BIOC*` at FreeBSD compile time, `BIOCSDIRECTION` for an inbound-only WAN sensor, `Stats.Drops` from `BIOCGSTATS`; the read-chunk splitter `parseBPFChunk` is **untagged and table-tested on Linux** so only the fd/ioctl plumbing is FreeBSD-gated; non-FreeBSD stub — [ADR 0014](adr/0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md)), the platform-neutral `NewLive`/`LiveSource` front door over those two (plus `RawPackets` for undecoded frames and `LiveStreamer`, which adapts a live NIC to a `pcapoverip.StreamFunc` for `synapse-sensor`), the subprocess sources `TcpdumpStream` / `SSHTcpdump` (Phase 3 — `tcpdump -w -` locally or over `ssh`; shared `pcapSubprocess` lifecycle, `ssh` gated on `authorized:true` per §28.18), and `PCAPOverIP` (Phase 3 — a framed, authenticated, versioned TLS stream from a remote sensor **the daemon dials**; sub-package `capture/pcapoverip` holds the SYNPOIP wire protocol, a reference server and a self-signed-cert helper). `Collector` (Phase 6 — the mirror image: a long-lived TLS **listener** that accepts sensors which dialled *in*, speaks the SYNPOIP **client** role on each accepted connection (the accepting side sends the ClientHello — PROTOCOL.md §6, no wire change), and registers each peer as its own `Manager` source (`kind: "pcap-over-ip-listen"`, `origin: "collector"`) via the internal `sessionSource` adapter, removing it when the stream ends. Bounded accept (`max_sensors`, default 32, plus a half-open-connection guard), mTLS via `client_ca_file`, and `OnConnect`/`OnDisconnect` hooks the daemon turns into `SensorConnected` / `SensorDisconnected` events. Its `Sensors()` projection is `GET /api/v1/sensors` — [ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)). Both SYNPOIP postures route by **sensor mode** (Phase 6, #45 — [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md)): `raw` yields packets as before, while `flow` and `feature` decode `0x04` / `0x05` record frames and deliver them to `pipeline.Options.Records` through the shared `recordRoute`, bypassing the packet channel entirely; whether a source supplies a record channel *is* its SYNPOIP v2 capability advertisement, so a daemon with nowhere to put records cleanly rejects a record-mode sensor. `SourceMeta.Mode` and `Stats.Records` / `RecordBytes` carry the mode and the record throughput into the capture-sources view, kept separate from the packet counters rather than reinterpreting them. The classic/pcapng stream decode is the shared `decodePCAPStream` engine (`pcapstream.go`), used by `PCAPFile`, the subprocess sources and the PCAP-over-IP client. `Manager` runs N sources and merges them into one stream for a single pipeline goroutine, isolating a failed source; it is itself a `Source`, and surfaces a source's TLS `connection_latency_ms`, sensor-advertised filter and `origin` (`config` / `api` / `collector`) when known. `Add` works before **or** after `Packets()` (dynamic fan-in) and `Remove` cancels, closes and joins a source's forwarder — the two runtime routes `POST` / `DELETE /api/v1/captures` sit directly on top ([ADR 0013](adr/0013-runtime-capture-source-management.md)). `Stats` counters (incl. `Drops`). See [ADR 0010](adr/0010-live-capture-af_packet-and-the-source-manager.md), [ADR 0011](adr/0011-subprocess-capture-tcpdump-and-ssh.md), [ADR 0012](adr/0012-pcap-over-ip-transport.md), `capture/pcapoverip/PROTOCOL.md`. | `packet`, `capture/pcapoverip` | `flow`, `features`, `inference`, `storage`, `events`, `api`, `config`, `capturewire` |
| `capture/pcapoverip` | The SYNPOIP wire protocol: framing, the v1/v2 handshake and capability negotiation, and the `0x04` flow / `0x05` feature **record** payloads (§45). It imports `flow` and `features` **by design** — a v2 record *is* a domain record, so its byte layout and schema binding are the transport's business. Both are leaves (`flow` → `packet`; `features` → `flow`, `packet`, `schema`), so the graph stays a DAG; `internal/capture` itself still imports neither. See [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md) §4. | `packet`, `flow`, `features`, `schema` | `capture`, `inference`, `storage`, `events`, `api`, `pipeline` |
| `flow` | `Key` (direction-normalized 5-tuple), `Record` (raw accumulators + derived-stat methods), `Table` (lifecycle: open, fold, snapshot, close, evict, TIME_WAIT grace). Single-goroutine. | `packet` | `features`, `inference`, `capture`, `storage`, `events`, `api` |
| `schema` | The frozen contracts: typed views of `flow-features-v1`, `traffic-classes-v1`, `BundleMeta` + `ValidateBundle`, and `Architecture` + `ValidateArchitecture` plus the shared `ParameterCount` / `ApproxBytes` / `RoughFLOPs` / `LayerBreakdown` estimate math (ported from the trainer). `init()` panics on drift. | `schemas` | everything else internal |
| `features` | `Extract(flow.Record) → Vector` (the 48 `flow-features-v1` values); `Normalizer` interface with `Identity` / `Log1p` and the fitted `Affine` (`NewStandardNormalizer` / `NewMinMaxNormalizer`). No raw-IP arithmetic. | `flow`, `packet`, `schema` | `inference`, `storage`, `events`, `capture`, `api` |
| `nn` | Dependency-free, CGO-free ONNX executor for the feed-forward MLPs the trainer emits: a hand-rolled protobuf-wire reader plus a batch-1, all-`float32`, deterministic graph runner over a fixed op subset (`Gemm`, `MatMul`, `Add`, `Relu`/`LeakyRelu`/`Sigmoid`/`Tanh`, `BatchNormalization`, `Dropout`, `Softmax`, `Identity`, `Flatten`, `Reshape`, `Constant`). Unknown op → load error; malformed model → error, never a panic. `Load`/`LoadFile`/`Model.Run`. See [ADR 0005](adr/0005-go-onnx-inference-runtime.md). | stdlib only | everything else internal |
| `inference` | `Classifier` interface, `Role`, `Runtime` (scores a vector through every model, records each `ModelOutput`, flags disagreement, picks the primary; `Activate` / `Deactivate` / `SetModels` swap the live model set atomically under an `RWMutex`), the rule-based `Heuristic`, and `ONNXModel` — the adapter that makes a loaded `nn.Model` a `Classifier` (with an optional per-model `Normalizer`). **`Explainer` / `Explanation`** (#38, [ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md)): `Heuristic.Classify` and `Heuristic.Explain` share one private `evaluate(v, explain bool)`, so the `FiredRule` list — stable rule id, human detail, and the named feature values the condition compared — is produced by the *same* evaluation that produced the verdict and cannot drift from it. `ClassWeights` reports the real pre-softmax weights (a test asserts they soft-max back to `Classify`'s scores exactly). `*ONNXModel` deliberately does **not** implement `Explainer`: per-feature attribution needs gradients or SHAP, `nn` exposes no weights, and a linear proxy rendered in an explanation panel reads as an explanation — so `UnavailableExplanation` says so in words instead. | `features`, `schema`, `nn` | `storage`, `events`, `capture`, `flow`, `api`, `pipeline` |
| `model` | `Load(dir)` for the five-file bundle; `Bundle` (inactive — `Meta` / `Normalizer` / `Metrics` / `Recipe` / `ONNXPath` / `Hash`); `Validate()`, the pre-activation gate; `Scan(dir, primary, logf)`, the startup sweep. `Metadata.DerivedFrom` (optional `derived_from`) feeds registry lineage. Activates nothing. | `features`, `schema` | `inference`, `pipeline`, `api`, `flow`, `packet`, `capture`, `storage`, `events` |
| `registry` | The model registry with lineage (§15, §19.12). `Open(dir, logf)` loads `registry.json` (atomic rewrite, corrupt-tolerant); `Register(*model.Bundle)` gates + records an `Entry`; `List` / `Get` / `Lineage` / `Children` / `Tree` / `Active`; `SetStatus` (`registered` → `active` → `deactivated`, one active at a time, reconciled to `deactivated` on restart). Runs no model. | `model`, `schema` | `api`, `pipeline`, `flow`, `features` |
| `modelrun` | `Build(id, *model.Bundle) → inference.Classifier`: `nn.LoadFile` the graph, bridge the bundle's `normalizer.json` into `inference.Normalizer`, wrap with `inference.NewONNXModel`. The seam from "bundle passed the gate" to "model is scoring". | `features`, `inference`, `model`, `nn` | `api` |
| `audit` | Append-only JSONL (`audit.log`, next to the bundles): one `{ts,event,actor,subject_type,subject,model_id,detail}` line per `ModelRegistered` / `ModelActivated` / `ModelDeactivated`, per `DatasetCreated` / `DatasetDerived` / `DatasetDeleted`, and per `TrainingStarted` / `TrainingCompleted` / `TrainingFailed` (§21, §28.14-15). `Log` keeps the model shape (`subject_type:"model"`, `model_id` populated); `LogSubject` carries any subject (`model` / `dataset` / `training`). `actor` is `"local"` until RBAC (#58). Never blocks a request. **Read path** (#36, [ADR 0022](adr/0022-auditable-model-activation-workflow.md)): `Tail(n, Filter)` returns records newest-first by seeking to EOF and scanning backwards in 64 KiB chunks — bounded by `MaxTail` (1000 records) and `MaxScanBytes` (8 MiB back from EOF), so the whole file is never read. A torn trailing line is skipped, a missing file reads as empty. `Filter` (`subject_type` / `subject` / `event` / `From`-`To`) compares `subject_type` as an opaque string, so a subject type added later (review lines, #42) is filterable with no change here. Append-only forever — nothing here can rewrite or delete a line. | stdlib only | `api`, `training` |
| `review` | The human review loop (§16; issues #42, #64; [ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md)). `Open(dir, src, bus, aud, logf)` loads `<dir>/<flow id>.json` (atomic rewrite, corrupt-tolerant, mirroring `training`); `Put(flowID, state, label, note)` / `Get` / `StateOf` / `List(filter)` / `Stats` / `Queue(rows, opt)`. **The §16 invariant is structural:** the model's prediction lives in an *unexported* `prediction` value with no exported constructor or setter, and `Put` has no prediction parameter — the store captures it itself, once, on the first review, and every later write copies it forward. `correct` derives its label from the prediction; `incorrect` requires a differing class; `unsure` / `ignored_pattern` / `unreviewed` assert none. `Queue` ranks by **margin** (`p_top1 - p_top2` ascending, reported as `uncertainty = 1 - margin`; normalised entropy alongside), or by `disagreement`, or by recency, and excludes terminal states while keeping `unsure`. Not capped — reviews are human-paced, and hand-labelled ground truth is the most expensive data here. Publishes `events.ReviewUpdated`; audits every write with `subject_type:"review"`. | `audit`, `events`, `inference`, `schema`, `storage` | `api`, `dataset` (only) |
| `dataset` | Versioned, immutable datasets (§14, §19.10; issue #33). `Open(dir, src, rv, logf)` scans `<dir>/<id>/<version>/{dataset.csv,manifest.json}` — the layout *is* the index, no second file to drift; missing/corrupt is tolerated. `Create(spec)` selects from the flow store (the `GET /api/v1/classifications` filter vocabulary plus time/proto/IP/limit), writes the trainer-shaped CSV (48 frozen feature columns + `label`, one row per flow, sorted by flow id) and a manifest carrying every §14 field, staged in a temp directory and `rename`d into place. `content_hash` = sha256 over a domain separator + both schema names + the exact CSV bytes, so identical rows hash identically. Refuses a duplicate `(id, version)`, a non-slug id (traversal impossible by construction), and a selection of zero rows / one class / under 20 rows; warns on class imbalance, absent classes, duplicate rows and evicted flows. `Derive` records lineage; `Delete` is allowed and audited. `labeling_source` is `model_prediction:<ids>` for a default cut; a `Selection.Reviewed` cut (`reviewed.go`, issue #42) reads the human review store instead of the classification ring, writes the **operator's** label into the CSV, and is the only path that may write `human_review` (or `human_review+model_prediction:<ids>` for a mixed `include_ignored` cut) — see [ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md). Both paths share `finish()`, so a curated cut inherits every guarantee: immutability, content hash, deterministic row order, and the zero-rows / one-class / `MinRows` refusals. `Stats(id, version)` (`stats.go`, issues #37/#67) reads the version's `dataset.csv` **back from disk** and derives the Dataset Explorer bundle — per-feature distributions/histograms, the 48×48 Pearson matrix, protocol/port splits, a bounded `|z|>6` outlier list, and a top-3 PCA projection by stdlib-only cyclic Jacobi; because the CSV is immutable the bundle is cached by `content_hash` for the process lifetime. See [ADR 0015](adr/0015-versioned-datasets-on-disk.md), [ADR 0020](adr/0020-dataset-explorer-and-in-tree-pca.md). | `features`, `review`, `schema`, `storage` | `api` (only) |
| `training` | The run store behind the live training dashboard (§19.8; issue #35; [ADR 0019](adr/0019-external-training-runs-reported-over-http.md)). The Go daemon never launches training — an external `synapse-trainer` process registers a run and POSTs one progress dict per epoch over HTTP; this package mirrors that state. `Open(dir, aud, logf)` loads `<dir>/<run id>.json` (atomic rewrite, corrupt-tolerant); `Start(meta)` / `AppendProgress(id, dict)` / `Finish(id, final)` / `Fail(id, reason)` / `List` / `Get`. `recipe` and `final` are `json.RawMessage` pass-through; `history` is capped at `HistoryCap` (1000, oldest dropped); a `running` run with no update for `StaleAfter` (15 min) reads back as `stale` (computed on read, never persisted). Writes `TrainingStarted` / `TrainingCompleted` / `TrainingFailed` to `audit`; publishes nothing on the event bus (`event-envelope-v1` is frozen). | `audit` | `api`, `pipeline`, `flow`, `features`, `inference` |
| `modeltest` | Test-only: `Write(dir, Bundle)` produces a valid, gate-passing five-file bundle with a real runnable 48→8→7 `model.onnx`, so registry/api/modelrun tests exercise register→activate→score without a committed binary fixture. | `nn/onnxbuild` | (tests only) |
| `events` | In-process fan-out `Bus`: `Publish` (non-blocking), `Subscribe(depth)`, per-sub + bus drop counters, monotonic `seq`. Event type constants. | stdlib only | every other internal package (kept a leaf) |
| `storage` | `Store` interface, `FlowRecord` / `Classification` DTOs, `FlowRecordFrom`, and `Mem` (fixed-capacity ring buffers, oldest evicted + counted). **`FlowHistory(id)`** (#38, [ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md)) returns every retained *version* of one flow — the periodic `ReasonSnapshot` records plus the terminal one, oldest first — so the Flow Inspector can show how a long flow's counters and verdict evolved. `Mem` keys history as `map[uint64][]flowVersion` and bounds it twice: globally by the flow ring (each retained version owns exactly one live ring slot, so total versions can never exceed `max_flows`) and per flow by `FlowHistoryCap` (64, oldest dropped first, counted in `Stats.FlowVersionsDropped`). A version is identified by an internal monotonic sequence number, **not** by `SnapshotIndex` — `flow.Table` increments that on the live entry, so a terminal record inherits the last snapshot's index and the old `(id, SnapshotIndex)` bookkeeping could delete a still-current entry (a spurious `404` from `GET /api/v1/flows/{id}`; regression-tested). | `features`, `flow`, `inference` | `capture`, `events`, `api`, `pipeline` |
| `insight` | The investigation read model (§19.4-6): bounded, incrementally maintained host profiles, classification-timeline bucket rings, and the **traffic matrix** (`matrix.go`, #68). Fed by `pipeline` through the nil-safe `pipeline.Observer` hook — `Observe` does one non-blocking send onto a bounded queue (**77 ns, zero allocations**) and a single aggregator goroutine owns every map, so `GET /api/v1/hosts` can never take a lock the packet path contends on. Caps: 2048 hosts (least-recently-active quarter evicted in batches), 128 distinct ports/peers per host (lowest-count half discarded), 900×1s / 720×10s / 1440×1m buckets, and **4096 `(initiator, responder)` pairs** (lighter half by `(flows, bytes)` discarded — 2048 hosts permits ~4.2 M pairs, so the matrix is deliberately a **bounded top-N and not a grid**, and every response carries `partial` / `pairs_evicted`). The matrix fold is **38 ns/op, 0 allocs** on an existing cell, taking the full aggregator fold from 226 → **245 ns/op**; `Index.Matrix` is the expensive side (1.33 ms over 4096 pairs) and holds only the read lock. A filtered matrix cannot come from the incremental table, so it is folded on demand from the stored window through the *same* projection — the split `/api/v1/timeline` already makes. Every discard is counted and surfaced on `/api/v1/status` under `insight`. Computes no baseline and no anomaly score — those are Phase 7 ([ADR 0016](adr/0016-host-and-time-aggregation-for-investigation.md), [ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)). | `inference`, `schema`, `storage` | `capture`, `flow`, `features`, `packet`, `events` |
| `alert` | The detection feed (§17, issue #117; [ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)). `Policy` (per-class confidence thresholds + `alert_on_disagreement`) decides whether a verdict is a finding; `Store` is a bounded, **deduplicating** ring of recent `Detection`s keyed on `(src_ip, dst_ip, class)` inside a window anchored at the first occurrence, so a 1000-port sweep is one detection with `count: 1000`. Fed by `pipeline.Options.Alerts` (the same nil-safe `Observer` shape `insight` uses) with one non-blocking, **zero-allocation** send per verdict; a single aggregator goroutine folds the detection and publishes `events.AlertCreated` **only on a new detection**, so the WebSocket stays quiet under a scan (§22). `Severity` is *derived* from the traffic class — never added to the frozen `traffic-classes-v1` — and `init()` panics if the table and the frozen class list disagree in either direction. Bounded by `max_recent` with oldest-first eviction + counter, mirroring `storage.Mem`; every method is nil-receiver safe. | `events`, `inference`, `schema`, `storage` | `api`, `pipeline`, `config`, `capture`, `flow`, `packet`, `features` |
| `report` | The downloadable investigation artefact (§19.3-4, issue #66). `Build(Sources, Options)` aggregates `storage.Store` + `insight` + `inference.Runtime` into one self-contained `Report` — build stamp (version/commit/date), scope, host profile, in-scope class breakdown, timeline, top peers/ports/protocols, active model set, and the notable flows (disagreements and non-`normal` verdicts) with their per-model outputs and named raw `flow-features-v1` values. Deterministic given the same state, so its content is assertable. Renders as JSON, or as **one standalone HTML file via `html/template`** — inline `<style>` only, no external reference, no script; contextual escaping is the control that keeps packet-derived strings out of the markup (§28.11). Bounds: 500 notable flows (max 2000), a 5000-verdict scan. Measures nothing new and computes no baseline; every limit and every eviction counter it reads becomes an explicit "partial view" / "not available in this build" note in the output ([ADR 0023](adr/0023-downloadable-investigation-reports.md)). | `features`, `inference`, `insight`, `schema`, `storage`, `version` | `api`, `pipeline`, `capture`, `flow`, `packet`, `events` |
| `wshub` | Dependency-free RFC 6455 server (`Upgrade`, text frames, ping/pong, disconnect detection) and `Hub` (per-client bounded send queue, drops slow clients). | stdlib only | `api`, `events`, `pipeline` |
| `pipeline` | The wiring. `Run(ctx, src, rt, bus, store, opt)` consumes a `Source` to completion, driving `flow → features → inference → store + publish` on one goroutine. `Options.Observer` is an optional one-method hook handed each record + verdict, so a read model (`insight`) can be fed from the one place that has both without the pipeline importing it. `Options.Alerts` is the second such hook, for `internal/alert`: the pipeline publishes `ClassificationCreated` / `ModelDisagreementDetected` but deliberately **not** `AlertCreated`, because dedup needs state the packet path must not own or lock (#117, [ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)). | `capture`, `events`, `features`, `flow`, `inference`, `storage` | `api`, `wshub`, `insight`, `alert` |
| `api` | Versioned REST surface, the `/api/v1/stream` WebSocket, the event `pump` (bus → batched JSON arrays → `Hub`), `ReplayController` and `CaptureStatusProvider` interfaces (the latter backs `GET`/`POST /api/v1/captures` and `GET`/`DELETE /api/v1/captures/{name}` — it carries `Add`/`Remove` as well as `List`/`Get`, so the package never touches a concrete `*capture.Manager`), the `/api/v1/models*` routes (registry view + explicit `activate` / `deactivate` against the live `Runtime`), the `/api/v1/datasets*` routes (list / create / derive / download / delete, addressed by one url-escaped `<id>@<version>` segment because a dataset id may contain a `/`), the `/api/v1/training*` routes (list / register / progress / fail / one-run poll — the trainer-facing POSTs are loopback-only, `TODO(#58)`; see [ADR 0019](adr/0019-external-training-runs-reported-over-http.md)), the `/api/v1/review*` routes (`review.go`: the ranked queue, the review list, per-flow get and the `PUT`/`POST` write — loopback-only, `TODO(#58)`; the queue reuses `parseClassFilters` so `class`/`model`/`min_confidence`/`disagreement` mean exactly what they do on `/api/v1/classifications`, and the write body has no field that could set the prediction; see [ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md)), the two Flow Inspector siblings `GET /api/v1/flows/{id}/explain` and `GET /api/v1/flows/{id}/snapshots` (`flows.go` / `flow_snapshots.go`, #38 — deliberately *not* folded into `GET /api/v1/flows/{id}`, whose `storage.FlowRecord` shape several views depend on and a test now pins; see [ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md)), `GET /api/v1/detections[/{id}]` (`detections.go`, #117 — the deduplicated detection feed from `alert.Store`, with `class`/`severity`/`min_confidence`/`since`/`limit`; deliberately **stricter** than the older collection routes: an unknown or unparseable parameter is a `400`, not an ignored one; see [ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)), the `/api/v1/hosts*` and `/api/v1/timeline` investigation routes (read-only, served from `insight`; the `{ip}` path value is re-parsed with `net/netip` and the per-host collections reuse the exact `/api/v1/classifications` filter parsing), `GET /api/v1/matrix` (`matrix.go`, #68 — the bounded traffic matrix, answered from `insight`'s incremental table when unfiltered and folded on demand when not, reporting `source`/`partial`/`truncated` either way), the `/api/v1/sensors` routes plus `GET /api/v1/sensors/topology` (`topology.go`, #46 — grouped by reported location, with an explicit `unassigned` bucket and a per-sensor `flow_attribution` verdict; the `sensor=`/`location=` scope joins `classFilters`, which is why `parseClassFilters` is a `*Server` method — resolving `location=` needs the `SensorStatusProvider`; see [ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)), static file serving. | `alert`, `audit`, `capture`, `capturewire`, `config`, `dataset`, `events`, `inference`, `insight`, `model`, `modelrun`, `registry`, `review`, `schema`, `storage`, `training`, `version`, `wshub`, `web` | `pipeline`, `flow`, `features`, `packet` |
| `capturewire` | The composition seam between the declarative config and the capture adapters: `Build(cs, logf)` turns one `config.CaptureSource` into a live `capture.Source` (+ a short log label), `Meta(cs)` builds the Manager's `SourceMeta`, `ResolvePOIPToken(cs)` reads `token_file` / `SYNAPSE_POIP_TOKEN`. It exists because `capture` is a data-plane leaf that must not import `config`, and `internal/api` cannot import `cmd/synapsed` — so the daemon's startup loop and `POST /api/v1/captures` share this one builder ([ADR 0013](adr/0013-runtime-capture-source-management.md)). Off the packet path. | `capture`, `config` | everything on the data plane (`packet`, `flow`, `features`, `inference`, `pipeline`, `storage`, `events`) |
| `config` | Load one JSON file + `SYNAPSE_*` env overrides onto `Default()`; validate; `LoopbackOnly()`; `ValidateCaptureSource(cs)` — the single copy of the per-source capture rules, shared by the file loader and `POST /api/v1/captures`. `ValidateAlerts(a)` — the `alerts` block's ranges and `per_class_min_confidence` keys (#117). Because `config` is a leaf it carries its own copy of the `traffic-classes-v1` class names, exactly as it does for `captureFilterNames`; `TestConfigAlertClassNamesMatchSchema` in `internal/alert` fails if the copy drifts. JSON only (see [ADR 0002](adr/0002-flow-features-v1-frozen-and-json-config.md)). | stdlib only | everything else internal |
| `version` | Build metadata stamped by `-ldflags`. | stdlib only | everything else internal |
| `schemas` | `//go:embed` bytes of the three schema JSON documents. | `embed` | — |
| `web` | `//go:embed all:dist` — the built React SPA served at `/` (source in `web/ui/`, committed build output in `web/dist/`; see [ADR 0004](adr/0004-react-spa-and-committed-build-output.md)). `FS()` returns the `dist` subtree. | `embed` | — |

`cmd/synapsed` composes `config` + `events` + `storage.Mem` + `inference.Runtime`
+ `api.Server`, owns the `replayController`, and runs one live-capture
`pipeline.Run` over the `capture.Manager` — always, even with no configured
source, so a source added later through `POST /api/v1/captures` has a consumer
(both pipelines share one `IDGen`). Configured sources are built through
`capturewire.Build`, the same helper the REST handler uses. It also `Open`s the
`review.Store` over `review.directory` and then the `dataset.Manager` over
`datasets.directory` (in that order — the manager reads curated labels from the
review store), handing both the same `storage.Store` the pipeline writes to — a
one-shot scan at startup, off every packet path, since a dataset is only ever
built by an explicit `POST /api/v1/datasets` and a review only ever by an
explicit `PUT /api/v1/review/{flow_id}`. At startup
it also calls `model.Scan` over `models.directory` to
load and validate any bundles present — a logging-only diagnostic that adds
nothing to the runtime (see [Model bundles](#model-bundles)). `cmd/synapse` is a
pure HTTP client of the API. `cmd/synapse-sensor` is the remote capture agent
(PROJECT.md §5.3): it captures on a local NIC or replays a file and streams raw
records over SYNPOIP, either listening for the daemon to dial (`--listen`) or
dialling the daemon's collector itself (`--connect`, for a sensor behind NAT). It
announces a real identity — `--sensor-id` / `SYNAPSE_SENSOR_ID` / hostname,
`--location` / `SYNAPSE_SENSOR_LOCATION`, plus its build version and `os/arch` —
in the handshake's session id, and `gen-cert` writes a self-signed pair for a
testing collector ([ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)).
Sensor `flow` / `feature` modes are still open (#45).

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

Every emitted record — each snapshot and the terminal one — is stored as its own
*version* of the flow and is retrievable in order from `storage.FlowHistory(id)`
and `GET /api/v1/flows/{id}/snapshots` (#38,
[ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md)). Counters in a
snapshot are **cumulative**, so consumers that total bytes or flows must use
terminal records only — `insight` and `dataset` already do.

One wrinkle to know: `SnapshotIndex` is incremented on the *live* table entry, so
a long flow's **terminal record inherits the last snapshot's index** rather than
resetting to `0` as the frozen schema text for feature 47 describes. Nothing
depends on it being unique any more (storage keys versions by an internal
sequence number), and `/snapshots` notes it — but feature 47 feeds the golden
vectors and every dataset CSV, so correcting it is a separate reviewed change.

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
`CaptureSourceConnected` / `CaptureSourceDisconnected` come from the startup
loader and the runtime `POST` / `DELETE /api/v1/captures` handlers, and
`SensorConnected` / `SensorDisconnected` from the daemon-side SYNPOIP collector
as reverse-connecting sensors attach and drop — `{sensor_id, location,
remote_addr, link_type, filter, session_id, source_name}`, plus
`agent_version` / `os_arch` on connect ([ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)).
`AlertCreated` comes from `internal/alert`'s aggregator goroutine, **not** from
`pipeline.Run`: it carries a whole `alert.Detection` and is published **once per
new detection**, never on a dedup increment, so a 1000-port sweep produces one
event rather than a thousand (issue #117,
[ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)).
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
- **The fan-in is dynamic.** `Manager.Add` may be called after `Packets()` is
  running: the new forwarder is launched under the manager mutex against the
  same live `out` channel, and the sampler picks the source up on its next tick
  because it walks the live source map. `Manager.Remove` cancels the source,
  closes it and **joins** its forwarder (each one closes a `done` channel on
  exit) before returning, then drops the row — so a `DELETE` leaves no goroutine
  behind and a following `GET` is a `404`. This is what backs
  `POST` / `DELETE /api/v1/captures` ([ADR 0013](adr/0013-runtime-capture-source-management.md)).
  Because a runtime-added source needs a consumer, `cmd/synapsed` always starts
  the capture pipeline goroutine, even with zero configured sources.
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
  `make web-check` is `tsc --noEmit`; `make web-test` runs the SPA unit tests
  under node's built-in runner (`web/ui/test/`, `web/ui/tsconfig.test.json`) —
  no test framework is installed, only `@types/node`.
- **Build output** is `web/dist/` — content-hashed JS/CSS plus `index.html`,
  **committed to the repo** and embedded by `web/web.go` (`//go:embed all:dist`).
  `go build`, `make build-linux` and CI never run Node. Rebuild and commit
  `web/dist/` after any `web/ui/` change.
- **Routing is hash-based** (`/#/flow-log`): every document request stays on `/`,
  so `internal/api` needs no SPA-fallback route. A `StreamProvider` opens the one
  WebSocket, polls `/api/v1/status`, `/api/v1/captures` and
  `/api/v1/sensors/topology` once a second in a single `Promise.allSettled` so the
  ingest counters are sampled in lock-step, fans event batches to subscribers, and
  keeps rolling client-side aggregates for the Dashboard.
- **Rates are derived, never assumed.** The capture/sensor/replay counters are
  cumulative on the wire, so `lib/rates.ts` differentiates successive readings by
  the *real* elapsed time between them — the same thing `capture.Manager.sample`
  does server-side. One reading is not a rate (the card says "measuring…", not
  0/s) and a counter moving backwards is a reset, not negative traffic
  (issue #118, PROJECT.md §16).
- **Wired views:** Dashboard, the full-screen Flow Log, the Flow Inspector
  (`GET /api/v1/flows/{id}` joined to `GET /api/v1/schemas/features`), Replay
  control, **CAPTURE ▸ Sources** (§19.14 — a 1 Hz poll of `GET /api/v1/captures`
  showing state/pps/bps/drops/decode-errors/last-packet/filter/latency/error per
  source, plus a per-kind add form on `POST /api/v1/captures` and a confirmed
  remove on `DELETE`; the "I am authorised to monitor this target" checkbox
  mirrors the server's §28.18 gate and blocks submit until ticked, and no inline
  token field is ever offered — `token_file` only, §23), and the ML ▸
  Architecture builder (`POST /api/v1/architecture/estimate`; locked 48/7 edges,
  editable hidden stack, live parameter/size/FLOP estimates,
  `schema.Architecture` export), **LIVE ▸ Hosts** (§19.5 — sortable/filterable
  observed-host table from `GET /api/v1/hosts`: first/last seen, flows, bytes
  in/out, top protocols and ports, class mix as a stacked bar, disagreement
  count; a row click pivots to Investigate), **LIVE ▸ Investigate** (§19.4 —
  `#/investigate?host=<ip>` scopes the whole page to one address: volume and
  packet tiles, first/last seen, disagreement count, top peers and service ports,
  class mix, protocols, the host-scoped classification timeline, and filterable
  verdict + flow lists backed by `GET /api/v1/hosts/{ip}/classifications` and
  `.../flows`), and **LIVE ▸ Timeline** (§19.6 — the daemon-wide stacked
  classification timeline from `GET /api/v1/timeline` with a disagreement
  overlay; dragging a range filters the verdict list beneath it, and the same
  chart component is embedded host-scoped on Investigate), **LIVE ▸ Matrix**
  (§19.4-5, #68 — the traffic matrix from `GET /api/v1/matrix` as a canvas heat
  grid of initiators × responders, cells tinted by the pair's worst non-`normal`
  class and shaded by `sqrt(share)` of the heaviest cell, with the pair list
  beneath and click-through to Investigate for either endpoint; a canvas rather
  than DOM cells for the same reason the Dataset Explorer's correlation matrix is
  one, and the daemon's `partial` / `truncated` / `pairs_evicted` / `source` flags
  are all rendered so a bounded top-N is never presented as a full grid), and
  **CAPTURE ▸ Sensors** (§19.15, #46 — `GET /api/v1/sensors/topology` grouped by
  reported location with per-location aggregates and a health chip, the
  `unassigned` bucket rendered as an exception, and click-to-scope on both a
  location and a sensor; the scope links appear **only** where the daemon says
  `flow_attribution: "records"`, and a raw-mode sensor gets a `counters only`
  affordance explaining why filtering to it would match nothing — see
  [ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)), and **LIVE ▸
  Detections** (§19.1/§19.4, #117 — the deduplicated alert feed over
  `GET /api/v1/detections` with server-side class / severity / min-confidence /
  `since` filters, the occurrence `count` as its own column because one row can
  stand for hundreds of probes, the first-seen → last-seen span, the per-model
  outputs and the daemon's own `reason`, and click-through to the Flow Inspector
  and to Investigate). Every other §19 route is a "Not built yet" placeholder
  naming its **open** tracking issue.
- **The detections backend exists** (#117): `GET /api/v1/detections[/{id}]`,
  `alerts.*` on `/api/v1/status`, and a real `AlertCreated` on the live channel
  ([ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)). The SPA view
  above was built against that contract on a separate branch.
- **Dashboard ingest cards** (§19.1, #118): *Active flows* reads
  `status.flow.active`; *Packets / sec* and *Throughput* are rates derived from
  the cumulative `/api/v1/captures` + `/api/v1/sensors/topology` counters plus a
  running replay's packet counter (§6 lists Replay as a capture source).
  Throughput excludes the replay on purpose — `status.replay` has no byte counter,
  so the card says so rather than multiplying packets by a guessed frame size.
  *Sensor health* renders `/api/v1/sensors/topology`, distinguishing
  `collector: false` ("off — no collector configured") from a collector with no
  sensor connected. **A working endpoint with nothing to report is an idle state,
  not a greyed "needs API".**
- **Detections degrades honestly on a daemon without the endpoint.**
  `client.getDetections` maps a 404 to `state: 'unavailable'`, and both the route
  and the Dashboard card say "not available in this build", once, with no retry
  loop, no spinner and no console error — the SPA half shipped while #117 was
  still on a sibling branch and needed no change when it landed. It is also
  verified in isolation against `web/ui/test/fixtures/detections.json`, a
  byte-for-byte instance of the contract, so the view stays testable without a
  daemon.
- **Deliberately labelled stubs** on Hosts and Investigate, each naming its open
  issue (#47 anomaly model, #63 per-host baselines, #49 drift): behavioural
  baseline, anomaly trend/history and unusual-feature callouts. The API reports
  `baseline_available: false` / `anomaly_available: false` and the SPA says so
  rather than inventing a baseline. No placeholder anywhere in the SPA cites a
  development phase any more: a phase number goes stale the instant its epic
  closes, which turned correct "this is missing" notices into apparent broken
  promises (#118). A **downloadable report** carries the same
  statement as an explicit note, because a file read a week later has none of the
  UI's context (§19.4, [ADR 0023](adr/0023-downloadable-investigation-reports.md)).
- **Report downloads:** Investigate has an HTML/JSON **Download report** control
  that carries the currently-brushed timeline range and the active filters; each
  Hosts row has a `report` link. Both are plain `<a href>` navigations to
  `/api/v1/reports/*`, so the daemon renders and names the file and the browser's
  own download path is used — the SPA holds no document in memory.

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
  one `{ts,event,actor,subject_type,subject,model_id,detail}` line to `audit.log`
  (JSONL, next to the bundles) and mirrors it to the structured log — and
  `GET /api/v1/audit` reads it back, newest-first and bounded, so the trail is
  something an operator can actually inspect (#36,
  [ADR 0022](adr/0022-auditable-model-activation-workflow.md)). Activating B
  while A is active also writes A's implicit `ModelDeactivated`, and a restart's
  active→deactivated reconciliation is audited too, so the last line about a
  model never claims it is live when it is not — the durable record (§21,
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
| Live capture — a pcap-filter-expression compiler; client reconnect/backoff and a subprocess supervisor / auto-restart; SSH dial-latency and tcpdump kernel-drop parsing; live-capture flow-table stats on `/api/v1/status`; editing a source in place and persisting a runtime source back to the config file | **Phase 3 is done — EPIC #3 is complete (#28–#32).** Local NIC, local tcpdump-stream, SSH remote-tcpdump and PCAP-over-IP capture are all wired (`capture.AFPacket`, `capture.TcpdumpStream`, `capture.SSHTcpdump`, `capture.PCAPOverIP` + `capture.Manager`; `synapsed --capture <iface>` / `capture.sources[]` with `kind` `nic` / `tcpdump` / `ssh` / `pcap-over-ip`; `synapse-sensor pcap-over-ip` reference server). Sources can be **added and removed at runtime** — `POST /api/v1/captures` / `DELETE /api/v1/captures/{name}` on the dynamic `Manager` fan-in, driven by the `CAPTURE ▸ Sources` SPA view (§19.14) — and `GET /api/v1/captures` reports state / pps / bps / drops / decode errors / last packet / filter / connection latency / error / origin. ADRs [0010](adr/0010-live-capture-af_packet-and-the-source-manager.md), [0011](adr/0011-subprocess-capture-tcpdump-and-ssh.md), [0012](adr/0012-pcap-over-ip-transport.md), [0013](adr/0013-runtime-capture-source-management.md). `nic` filters are built-in cBPF presets only; `tcpdump` / `ssh` take a raw tcpdump filter expression. `kind:"ssh"` and non-loopback / insecure `pcap-over-ip` require `"authorized": true` (§21, §28.18). The mutating routes are unauthenticated and loopback-only (#58). No auto-restart on subprocess exit or stream drop. `capture.PCAPFile` + `capture.Replay` still handle classic pcap and minimal pcapng. | EPIC: Phase 3 **closed**; the remainder are tracked follow-ups |
| Anomaly / location / global / experimental model roles wired end to end | `internal/nn` runs ONNX MLPs; `inference.ONNXModel` adapts them to `Classifier`; `internal/model` loads and validates the five-file bundle; `internal/registry` records it with lineage; `POST /api/v1/models/{id}/activate` compiles it and swaps it into `inference.Runtime` as the single `RolePrimary`, `deactivate` restores `inference.Heuristic` (issues #24–#26; [ADR 0009](adr/0009-model-registry-lineage-and-explicit-activation.md)). Multi-model ensembles (a trained primary *and* a shadow/anomaly peer at once) are not wired yet — `Runtime.SetModels` is the seam. The offline `synapse-trainer` lives in `trainer/` ([ADR 0007](adr/0007-python-trainer-and-bundle-export.md)). | see EPIC: Phase 2 / 7 |
| SQLite (then ClickHouse) persistence | `storage.Mem` bounded ring; `config` recognizes `driver: sqlite` but `validate()` rejects it as "not implemented yet" | see EPIC: Phase 2 (SQLite), Phase 8 (ClickHouse) |
| ~~Distributed sensors — sensor topology (#46) and the traffic-matrix/topology views (#68)~~ | **Done (#46, #68, [ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)) — these were the last open children of EPIC Phase 5 and Phase 6.** `GET /api/v1/sensors/topology` groups the connected sensors by the location each one reported, with per-location aggregates (sensor/running count, summed pps/bps/packets/bytes/drops/records, modes in use, newest `last_packet`) and a `down`/`degraded`/`ok` health verdict; sensors reporting no location land in an explicit `unassigned` bucket, sorted last, and **no location is invented for them**. `GET /api/v1/matrix` is the who-talks-to-whom matrix: per ordered `(initiator, responder)` pair the flow count, byte volume and class mix, plus `threat_class` (the highest-count non-`normal` class) so an attack pair is visible even when `normal` dominates it. It is a **bounded top-N of 4096 pairs, not a hosts × hosts grid** — 2048 hosts permits ~4.2 M pairs — and reports `partial` / `truncated` / `pairs_evicted` / `source` so a client cannot mistake it for complete. **The scoping interaction (§19.15) is wired only where it is real:** `sensor=` / `location=` join the shared `classFilters` dialect on `/flows`, `/classifications`, `/hosts/{ip}/*`, `/review/queue`, `/reports/*` and `/matrix`, and they match `Classification.Sensor` — which holds a genuine sensor id for `flow`/`feature`-mode sensors but the literal `"local"` for raw-mode ones, whose packets merge into one channel and one flow table before a flow record exists. So the topology response marks every sensor's `flow_attribution` (`records` \| `none`) and the SPA offers the scope links only where they work; an unresolvable `location=` is a `400`, never a silently empty `200`. Real sensor attribution for raw mode needs sensor identity on `packet.Packet` **and** in `flow.Key` (otherwise two sensors' identical 5-tuples merge into one flow) — a data-plane change, deliberately deferred. `#/sensors` and `#/matrix` (canvas heat grid + pair list, click-through to Investigate) replace the Phase-6 placeholder. Prior work this builds on: **sensor modes (#45, [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md))**: `synapse-sensor --mode raw\|flow\|feature`. `raw` is unchanged; `flow` runs the flow engine on the sensor and ships `flow-record-v1` records (`0x04`), `feature` also runs feature extraction and ships only the 48 `flow-features-v1` values (`0x05`) — **no packet content crosses the wire**. Each mode joins the daemon's pipeline further along (flow table → feature extraction → inference), on the same single goroutine, and remote flow ids are remapped through the daemon's shared `IDGen` with the sensor's kept as `sensor_flow_id`. SYNPOIP **v2** negotiates it: the fixed hello `version` stays `1` and the ceiling rides as `max_version` in the hello metadata, so v1 peers are unaffected byte for byte, and a `flow`/`feature` sensor talking to a v1 daemon is refused with the typed `0x06 mode-unsupported` rather than silently downgraded. Payloads are schema-bound in the accept and refused on mismatch (§28.5-6). Measured on a 68 814-packet / 1 176-flow capture: `flow` is ~1.4 % and `feature` ~1.8 % of `raw` on the wire, and all three modes produce identical classifications. `synapse-sensor pcap-over-ip` serves a capture file **or a live NIC** (`--iface`) over the framed, authenticated SYNPOIP transport ([ADR 0012](adr/0012-pcap-over-ip-transport.md)), on Linux (`AF_PACKET`) and FreeBSD (`/dev/bpf`), either listening (`--listen`) or **dialling the daemon** (`--connect`) with reconnect + backoff. `synapsed` now ships the other half: a `capture.collector` config block stands up a TLS listener (`capture.Collector`) that accepts sensors, registers one `Manager` source per peer (`kind: "pcap-over-ip-listen"`), publishes `SensorConnected` / `SensorDisconnected`, and serves `GET /api/v1/sensors[/{id}]` — bounded by `max_sensors`, authenticated by the presented bearer token plus optional mTLS, and gated on `authorized: true`. The SYNPOIP roles and wire format are **unchanged** (PROTOCOL.md §6); sensor identity (id, location, agent version, `os/arch`) rides in the accept's `session_id`. [ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md). The OPNsense plugin (`contrib/opnsense/`, [ADR 0014](adr/0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md), [docs](opnsense-sensor.md)) packages the sensor as an `os-synapseids-sensor` FreeBSD `.pkg` with a **Services → SynapseIDS Sensor** UI — **untested on hardware.** Still open: per-sensor tokens, the collector's rejection counters on `/api/v1/status`, record modes on the dialled (`--listen`) posture, record batching, and raw-mode sensor attribution (above). | #43, #103, #45, **#46, #68 closed** — EPIC Phase 5 and Phase 6 have no open children left |
| The rest of the §19 UI — Model compare, Drift, Performance, Storage, Settings | React SPA (`web/ui/`, built into the embedded `web/dist/`) with the Dashboard, Flow Log, Flow Inspector, Replay control, Capture Sources, the Architecture builder, the Model **registry** (§19.12), the Dataset **Manager** (§19.10), the Dataset **Explorer** (§19.11), the **Training dashboard** (§19.8, polls `/api/v1/training/{id}`), **Hosts, Investigate, Timeline and Review**, the **traffic Matrix** (§19.4-5, #68), **Sensors topology** (§19.15, #46) and **Detections** (§19.1/§19.4, #117) wired; every other route is a "Not built yet" placeholder naming its open issue | #48 (compare), #49 (drift), #55 (performance), #53 (storage), #54/#59 (settings) |
| ~~Detections — an `/api/v1/detections` resource, an alert store, anything publishing `AlertCreated`~~ | **Backend done (#117, [ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)).** `internal/alert` is an alert `Policy` (per-class confidence thresholds + `alert_on_disagreement`) plus a bounded, **deduplicating** detection store keyed on `(src_ip, dst_ip, class)` in a window anchored at the first occurrence — a 1000-port sweep is one detection with `count: 1000` and **one** `AlertCreated`, not a thousand of each (§22). `GET /api/v1/detections` filters on `class` / `severity` / `min_confidence` / `since` / `limit` and reports `total` / `returned` / `evicted`; `GET /api/v1/detections/{id}` is the single object. `severity` is *derived* from the class (`normal` never alerts; `suspicious`→`low`, `scan`→`medium`, `brute_force`/`web_attack`→`high`, `dos_ddos`/`botnet_c2`→`critical`) and covering the frozen class list is a startup gate, not a silent `""`. Counters on `/api/v1/status` under `alerts`. **`LIVE ▸ Detections` and the Dashboard's *Recent detections* card** render it (#118): the deduplicated `count` as its own column, server-side class/severity/min-confidence/`since` filters, and click-through to the Flow Inspector. Both were written against this contract while it was still on a sibling branch and needed no change when it landed; on a daemon without the endpoint a 404 renders as "not available in this build" — a state, not an error and not a spinner. **Not done:** notification delivery (email/webhook/syslog), anomaly-driven detections (#47), per-detection acknowledge/close state, and persistence — detections live in a 1000-entry ring and do not survive a restart. **The feed's quality is the heuristic's:** on a real nmap+brute-force capture the classifier misses the recon entirely (#90), so there is no `scan` detection at all; the thresholds were not tuned to hide it. | #117 **closed**; notification delivery and #47 remain |
| Behavioural baselines, anomaly trend/history, unusual-feature callouts on a host (§19.4-6) | Host profiles and the classification timeline are real; the baseline/anomaly fields exist and are reported as `baseline_available: false` / `anomaly_available: false` rather than fabricated ([ADR 0016](adr/0016-host-and-time-aggregation-for-investigation.md)) | #47 (anomaly model), #63 (per-host baselines) under EPIC: Phase 7 (#7) |
| **Phase 4** — the human review loop, train/val/test planning in the UI, | The **dataset manager** is done: `internal/dataset` materialises versioned, immutable, content-hashed datasets from stored classifications, `/api/v1/datasets*` exposes them, and `ML ▸ Datasets` drives it ([ADR 0015](adr/0015-versioned-datasets-on-disk.md), issue #33). **Training recipes** with multi-dataset weighting are done in `trainer/` ([ADR 0017](adr/0017-multi-dataset-training-mixtures.md), issue #34). The **live training dashboard** is done: `internal/training` mirrors external `synapse-trainer` runs reported over HTTP, `/api/v1/training*` exposes them, and `ML ▸ Training` polls and renders loss curves / per-class metrics / the confusion matrix ([ADR 0019](adr/0019-external-training-runs-reported-over-http.md), issue #35). The **Dataset Explorer** (§19.11) is done too — `GET /api/v1/datasets/{ref}/stats` and `ML ▸ Dataset Explorer` give feature distributions, the 48×48 correlation matrix, protocol/port splits, outliers and a stdlib-only PCA projection ([ADR 0020](adr/0020-dataset-explorer-and-in-tree-pca.md), issues #37/#67; UMAP deferred). Splitting is reproducible but happens **in the trainer** (`synapse_trainer.mixture` / `Dataset.split`), not here. Because there is no review loop, every dataset's `labeling_source` is `model_prediction:<ids>` — the daemon's own predictions, never presented as ground truth. | issue #42 (review), #36 (activation workflow), rest of EPIC: Phase 4 |
| ~~The human review loop and curated datasets~~ | **Done (#42, #64).** `internal/review` stores the five §16 states per flow with the model's original prediction preserved *structurally* alongside the human label; `/api/v1/review*` serves the ranked queue (margin-based uncertainty for active learning, plus disagreement and recency), the review records and the write route; `LIVE ▸ Review` drives it and hands a prefilled `reviewed` selection to `ML ▸ Datasets`, which can now write `labeling_source: human_review`. Every write is audited and publishes `ReviewUpdated`. See [ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md). Reviews are deliberately uncapped, and a flow whose verdict has aged out of the bounded ring can no longer be reviewed. | EPIC: Phase 5 — #42 and #64 **closed** |
| ~~The Flow Inspector's normalized inputs, snapshot history and explanation panel~~ | **Done (#38).** `GET /api/v1/flows/{id}/explain` reports, per model that actually scored the flow, what it received — `kind: raw` for the `Heuristic` (which reads raw values, stated in words rather than shown as an identity table) or `kind: normalized` with raw→normalized pairs resolved from the **active** registry entry's own `normalizer.json` (cached per `<model id>@<content hash>`). The **explanation** is exact for the heuristic: the `FiredRule` list names each rule that matched and the feature values its condition compared, plus the real pre-softmax `class_weights`; an empty list is reported as "no rule fired, the standing `normal` prior decided this" rather than as an empty panel. For a trained ONNX model it is `kind: unavailable` — no gradients, no SHAP, and deliberately **no linear proxy**. `GET /api/v1/flows/{id}/snapshots` serves the retained version history (`storage.FlowHistory`), each version paired with the verdict computed from it by an exact `TS`↔`LastSeen` join. **No baseline column and no anomaly number**: both are `{available: false, note}` with no value field, and a test asserts the raw JSON carries nothing else. See [ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md). | EPIC: Phase 5 — #38 **closed** |
| **Phase 4** — train/val/test planning in the UI, | The **dataset manager** is done: `internal/dataset` materialises versioned, immutable, content-hashed datasets from stored classifications, `/api/v1/datasets*` exposes them, and `ML ▸ Datasets` drives it ([ADR 0015](adr/0015-versioned-datasets-on-disk.md), issue #33). **Training recipes** with multi-dataset weighting are done in `trainer/` ([ADR 0017](adr/0017-multi-dataset-training-mixtures.md), issue #34). The **live training dashboard** is done: `internal/training` mirrors external `synapse-trainer` runs reported over HTTP, `/api/v1/training*` exposes them, and `ML ▸ Training` polls and renders loss curves / per-class metrics / the confusion matrix ([ADR 0019](adr/0019-external-training-runs-reported-over-http.md), issue #35). The **Dataset Explorer** (§19.11) is done too — `GET /api/v1/datasets/{ref}/stats` and `ML ▸ Dataset Explorer` give feature distributions, the 48×48 correlation matrix, protocol/port splits, outliers and a stdlib-only PCA projection ([ADR 0020](adr/0020-dataset-explorer-and-in-tree-pca.md), issues #37/#67; UMAP deferred). Splitting is reproducible but happens **in the trainer** (`synapse_trainer.mixture` / `Dataset.split`), not here. The **human review loop** is done too (#42, #64), so a dataset's `labeling_source` is now either `model_prediction:<ids>` — the daemon's own predictions, never presented as ground truth — or `human_review` for a curated cut built from operator decisions ([ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md)). | issue #36 (activation workflow), rest of EPIC: Phase 4 |
| YAML config, retention sweeper, detection API group | JSON config; rings are size-bounded, not time-bounded. The host/investigation API group now exists (`/api/v1/hosts*`, `/api/v1/timeline`) but its aggregates are process-lifetime and volatile, like `storage.Mem` | see EPIC: Phase 2 ([ADR 0002](adr/0002-flow-features-v1-frozen-and-json-config.md)), Phase 5 |
| **Phase 4** — the human review loop, train/val/test planning in the UI, | The **dataset manager** is done: `internal/dataset` materialises versioned, immutable, content-hashed datasets from stored classifications, `/api/v1/datasets*` exposes them, and `ML ▸ Datasets` drives it ([ADR 0015](adr/0015-versioned-datasets-on-disk.md), issue #33). **Training recipes** with multi-dataset weighting are done in `trainer/` ([ADR 0017](adr/0017-multi-dataset-training-mixtures.md), issue #34). The **live training dashboard** is done: `internal/training` mirrors external `synapse-trainer` runs reported over HTTP, `/api/v1/training*` exposes them, and `ML ▸ Training` polls and renders loss curves / per-class metrics / the confusion matrix ([ADR 0019](adr/0019-external-training-runs-reported-over-http.md), issue #35). The **Dataset Explorer** (§19.11) is done too — `GET /api/v1/datasets/{ref}/stats` and `ML ▸ Dataset Explorer` give feature distributions, the 48×48 correlation matrix, protocol/port splits, outliers and a stdlib-only PCA projection ([ADR 0020](adr/0020-dataset-explorer-and-in-tree-pca.md), issues #37/#67; UMAP deferred). Splitting is reproducible but happens **in the trainer** (`synapse_trainer.mixture` / `Dataset.split`), not here. Because there is no review loop, every dataset's `labeling_source` is `model_prediction:<ids>` — the daemon's own predictions, never presented as ground truth. | issue #42 (review), #36 (activation workflow), rest of EPIC: Phase 4 |

---

⟦THUGS⟧ (c) 2026
