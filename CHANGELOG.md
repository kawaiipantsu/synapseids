# Changelog

All notable changes to SynapseIDS are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `/api/v1/status` now carries a `flow` object — the live flow table's `active`,
  `started`, `closed`, `snapshots` and `evicted` counters plus the configured
  `max` (`capture.max_flows` / `SYNAPSE_MAX_FLOWS`) — so oldest-idle eviction
  pressure is observable without attaching to the packet path (PROJECT.md §22,
  §24). It is sourced from the running replay pipeline's flow table via a new
  `pipeline.Options.OnStats` hook that fires on the flow-table tick cadence,
  never per packet.
- The pipeline logs a throttled warning (the first eviction of a run, then every
  1000th) when the flow table is full and starts evicting, pointing at
  `capture.max_flows`.
- `internal/capture` now reads **minimal pcapng** as well as classic pcap
  (GitHub issue #73). The hand-rolled reader handles a single Section Header
  Block (either byte order), Interface Description Blocks (link type, snap
  length, `if_tsresol` timestamp resolution), Enhanced Packet Blocks and Simple
  Packet Blocks, for Ethernet or RAW link types. Every declared block length is
  bounded before allocation and the trailing length is verified. Multi-section
  files, mid-file endianness changes and non-Ethernet/RAW link types are still
  refused with the existing `editcap -F pcap` hint.
- `testdata/pcap/http.pcapng` — a hand-encoded pcapng twin of `http.pcap`,
  produced by `testdata/gen` and covered by a test that asserts it decodes to
  the same packets, flows and `flow-features-v1` vectors as the classic file.
- `/api/v1/status` `live` object now also reports `ws_clients`,
  `ws_client_drops` and `ws_frames_batched` — the last being the count of
  batched WebSocket frames produced by the pump (one per flush, independent of
  the connected-client count). The existing `clients`, `frames_out` and
  `client_drops` keys are unchanged (issue #70).
- `internal/features/interarrival_test.go` — regression tests that pin the
  `interarrival_*` missing-value sentinels (flow-features-v1 indices 15–20)
  through `features.Extract`: a 1-packet flow reads `0` for mean/min/max/stddev,
  a 2-packet flow reports the single gap with stddev still `0`, a 3-packet flow
  with unequal gaps has a non-zero stddev, and `forward_interarrival_mean` stays
  `0` until a direction has two packets (#72).
- **Operator SPA** (`web/ui/`) — a TypeScript + React 18 single-page app built
  with Vite 5, replacing the vanilla-JS rolling-log shell (PROJECT.md §19, §27;
  issue #20, EPIC #1). Hash-routed (`/#/flow-log`), so `internal/api` is
  unchanged. The dark-terminal palette, per-class colours and `⟦THUGS⟧ · (c)
  2026` mark are carried over. Wired Phase-1 views:
  - **Flow Log** — the vanilla rolling log ported to React and extended:
    pause/resume that buffers backend events instead of dropping them,
    resume-to-latest, configurable max retained rows, compact/comfortable
    density, class / min-confidence / protocol / text-search filters, suspicious
    / low-confidence / disagreement row highlighting, kiosk full-screen
    (Fullscreen API), keyboard nav (↑/↓ select, Enter inspect, Space pause), and
    click-to-open Flow Inspector.
  - **Flow Inspector** — a drawer over `GET /api/v1/flows/{id}` +
    `GET /api/v1/schemas/features`: full 5-tuple and direction, timing,
    packet/byte and TCP metadata, all 48 raw feature values joined to the schema,
    the full class-probability vector, per-model outputs and the disagreement
    flag. Normalized inputs, snapshot history and human-review status are labelled
    Phase-2 stubs.
  - **Dashboard** — live counters from `/api/v1/status` plus client-side
    aggregation of the classification stream: classifications/sec and flow-event/sec
    uPlot sparklines, class and protocol breakdowns, rolling-window top talkers and
    destination ports, hosts seen, and the loaded-model list. Cards with no data
    source yet are greyed and marked "needs API".
  - **Replay control** — the footer path / speed / start / stop / status bar
    (same endpoints as before) plus a CAPTURE ▸ Replay page with a live
    ReplayStarted/Progress/Finished event feed.
  - App shell with the full §19 navigation tree; every non-Phase-1 route renders
    a "Planned — Phase N" placeholder naming its tracking epic.
- New Make targets: `web` (build the SPA into `web/dist/`), `web-dev` (Vite dev
  server proxying `/api` + `/api/v1/stream` to `127.0.0.1:8080`), `web-check`
  (`tsc --noEmit`).
- [ADR 0008](docs/adr/0008-react-spa-and-committed-build-output.md) — records the
  TS + React + Vite 5 stack, uPlot, hash routing and the committed-`web/dist/`
  decision.

- **`internal/nn`** — a dependency-free, CGO-free executor for the feed-forward
  neural networks the trainer produces (PROJECT.md §10, EPIC Phase 2). A
  hand-rolled reader for the ONNX protobuf-wire subset (`ModelProto` /
  `GraphProto` / `NodeProto`, `float32` and little-endian `raw_data`
  `TensorProto` initializers, `ValueInfoProto` shapes — no protobuf library)
  feeds a deterministic, batch-1, all-`float32` graph executor. Supported ops:
  `Gemm` (α/β, transA/transB), `MatMul`, `Add` (broadcast — residual blocks
  work), `Relu`, `LeakyRelu`, `Sigmoid`, `Tanh`, `BatchNormalization`
  (inference-time affine fold), `Dropout` (identity), `Softmax`, `Identity`,
  `Flatten`, `Reshape` (constant shape) and `Constant` (folded to an
  initializer). Any other op is a hard load-time error (`nn: unsupported op
  %q`); a malformed model returns an error, never a panic. Public API: `Load`,
  `LoadFile`, `Model.Run`, `Model.InputSize` / `OutputSize` / `OpCounts`. See
  [ADR 0005](docs/adr/0005-go-onnx-inference-runtime.md).
- **`inference.ONNXModel`** — adapts a loaded `nn.Model` to the `Classifier`
  interface, so trained models score through the same `Runtime` as the heuristic
  and each model's output is recorded (PROJECT.md §12). Takes an optional
  per-model `Normalizer` (`func(features.Vector) [48]float64`) supplied from the
  bundle's `normalizer.json`; with none, raw feature values are fed, matching
  the heuristic path. The distribution is defensively clamped and renormalised.
- **`internal/nn/onnxbuild`** — a small ONNX `ModelProto` writer used only by
  tests and by `internal/nn/testdata/gen`, which regenerates the committed
  `internal/nn/testdata/model.onnx` fixture (`go run
  ./internal/nn/testdata/gen`).

- **Model bundle validation gate** (`internal/model`, issue #25) — the daemon
  now reads a self-describing model bundle and refuses an incompatible one
  before it could ever be activated (PROJECT.md §11, §28.6, §28.10):
  - `model.Load(dir)` parses the five-file bundle (`model.onnx`, `metadata.json`,
    `normalizer.json`, `metrics.json`, `training-recipe.json`) and returns an
    **inactive** `*Bundle` — loading never activates anything.
  - `Bundle.Validate()` rejects, naming the offending field: a missing or
    non-JSON file; a `feature_schema` / `input_size` / `output_schema` /
    `output_size` that is not `flow-features-v1` (48) / `traffic-classes-v1` (7);
    an absent or wrong-sized `architecture`; an empty `family`,
    non-positive `parameter_count`, or non-RFC3339 `created_at`; a `model_hash`
    without the `sha256:` prefix or that does not match the SHA-256 recomputed
    over the `model.onnx` bytes; a `normalizer.json` with the wrong feature
    schema, an unknown method, or (for `standard` / `minmax`) not exactly 48
    ascending in-order entries with `std > 0` / `min < max`.
  - `schema.Architecture` / `schema.HiddenLayer` types and
    `schema.ValidateArchitecture` keep the frozen input/output-layer contract
    checks alongside `schema.ValidateBundle`.
  - `features.Affine` (`NewStandardNormalizer` / `NewMinMaxNormalizer`) — a
    fitted per-feature z-score / min-max transform implementing the existing
    `features.Normalizer` interface; `internal/model` builds it from
    `normalizer.json` (`identity` → `features.Identity`). It is a per-model
    concern applied on the trained-model path only; the pipeline never installs
    it.
  - `cmd/synapsed` scans `models.directory` at startup, logging
    `loaded model "<dir>" … — INACTIVE` or `rejected model bundle "<dir>": …`
    per subdirectory. No model is added to the inference runtime and
    `models.primary` is not activated — activation remains a separate explicit
    step, still to be wired.
  - `model.Executor` interface + `Bundle.Bind` are defined (unused) as the seam
    the Phase 2 ONNX runtime (issue #24) will implement.

### Changed

- `capture.ErrNotPCAP` now reads "not a pcap file (need a classic pcap or pcapng
  capture)"; the replay-start `409` and the capture docs describe the wider
  accepted set.
- `docs/features-v1.md` now spells out the inter-arrival missing-value contract:
  a flow with fewer than two packets in the relevant direction has no defined
  inter-arrival distribution, so `0` is the deliberate `default_missing`
  sentinel, not a measured value. Documentation only — matches the
  already-frozen `schemas/features/flow-features-v1.json`; no schema or code
  change.
- `web/` now embeds the committed Vite build output (`web/dist/`, `//go:embed
  all:dist`) instead of a single hand-written `index.html`. The Go build stays
  Node-free, offline and cross-compilable; rebuild the bundle with `make web`
  and commit `web/dist/` after editing anything under `web/ui/`. `web.FS()` keeps
  its signature, so `internal/api` is untouched.
- `make clean` also removes `web/ui/node_modules`, `web/ui/.vite` and
  `*.tsbuildinfo` (it leaves the committed `web/dist/` in place).

### Removed

- `web/index.html` — the vanilla-JS placeholder shell; its behaviour is ported
  into the SPA's Flow Log and Replay control.

### Fixed

- `capture.Replay` at `--speed max` now yields the scheduler (`runtime.Gosched`)
  every 256 packets. The unpaced emit loop previously had no blocking point, so
  on a single-CPU host a long replay could monopolise the Go scheduler and delay
  `/api/v1` responses. The paced speeds are unchanged — they already block on a
  timer. (#71)

## [0.1.0] - 2026-08-31

First tagged release: the Phase 1 vertical slice plus the full build, packaging
and CI foundation. It classifies replayed PCAP traffic end to end with a
transparent rule-based model — real trained models, live capture and persistence
land in later phases.

### Added

- Repository foundation: MIT licence, Git Flow layout, `PROJECT.md` specification,
  `CLAUDE.md` engineering guide, community-health files.
- **Phase 1 vertical slice** — one working path from a capture file to a live
  classification, with no third-party Go dependencies:
  - `internal/packet`: bounds-checked Ethernet / 802.1Q / IPv4 / IPv6 (bounded
    extension-header chain) / TCP / UDP / ICMPv4 / ICMPv6 decoders producing a
    small normalized `packet.Packet`. Malformed input is counted, never a panic.
  - `internal/capture`: the `Source` interface plus a hand-rolled classic-`pcap`
    reader (µs and ns magic, LE/BE, `EN10MB` and `RAW` link types; `pcapng` is
    refused with a conversion hint) and a `replay` adapter that paces any Source
    to wall-clock × {0.5, 1, 2, 10, max}.
  - `internal/flow`: direction-normalized 5-tuple `Key`; a `Table` that owns flow
    lifetime — close on FIN-both / RST / idle timeout / max lifetime / capture
    end, periodic `snapshot` records for long-lived flows, a bounded flow cap
    with oldest-idle eviction, and a grace window that absorbs the TIME_WAIT
    tail.
  - Frozen contracts under `schemas/`: `flow-features-v1` (48 per-flow features,
    each with unit / calculation / missing-value / normalization metadata),
    `traffic-classes-v1` (7 classes), `event-envelope-v1`. `internal/schema`
    embeds them and provides `ValidateBundle` — the compatibility gate a trained
    model must pass before it can run.
  - `internal/features`: `flow-features-v1` extraction from a flow record, using
    only derived behavioural/context values — no raw IP addresses. `Normalizer`
    interface (identity + log1p) kept as a per-model concern.
  - `internal/inference`: `Classifier` interface, model `Role`s
    (primary/location/global/experimental/anomaly), and a `Runtime` that scores a
    vector with every loaded model and records each model's output plus a
    disagreement flag. A transparent rule-based `Heuristic` model stands in until
    Phase 2 brings trained ONNX models.
  - `internal/events`: an in-process fan-out bus with bounded per-subscriber
    queues and a drop counter; publishing never blocks ingestion.
  - `internal/storage`: the `Store` interface and an in-memory bounded-ring
    implementation with eviction counters. SQLite is tracked separately.
  - `internal/api`: the versioned REST surface (`/api/v1/status`, `flows`,
    `flows/{id}`, `classifications`, `models`, `schemas/*`, `replay`) plus a
    request logger. Binds to loopback by default; a non-loopback listener is
    logged as a warning.
  - `internal/wshub`: a dependency-free RFC 6455 server and a fan-out `Hub` that
    gives every client a bounded send queue and drops — never blocks on — a slow
    client. The daemon batches event envelopes into one frame per interval.
  - `internal/pipeline`: the single wiring `capture → flow → features → inference
    → events + storage` that both live capture and replay run through.
  - `web/index.html`: a dependency-free single-page rolling flow-classification
    log — live WebSocket feed, pause/resume, class / min-confidence filters,
    retained-row cap, replay controls. A React SPA is tracked separately.
  - `cmd/synapsed` (daemon), `cmd/synapse` (admin CLI — every verb is an HTTP
    call to `synapsed`), `cmd/synapse-sensor` (Phase 6 placeholder).
  - `testdata/gen` builds the committed `http.pcap` / `portscan.pcap` /
    `udp.pcap` fixtures; golden feature vectors under
    `internal/features/testdata/` guard the frozen schema. An end-to-end test
    asserts `portscan.pcap` classifies as `scan` and `http`/`udp` as `normal`.
- Build system: a `Makefile` with the development loop and a Linux-only
  cross-compile matrix — `linux/amd64`, `linux/386`, `linux/arm64`, `linux/arm`
  (v7) — building all three binaries, `CGO_ENABLED=0`, `-trimpath`,
  version-stamped. `make dist` produces a per-arch `.tar.gz` (all three binaries
  + man pages) plus `SHA256SUMS`; `make deb` produces four `.deb` packages
  (`amd64`, `i386`, `arm64`, `armhf`) via `dpkg-deb` with DEP-5 copyright and a
  Debian changelog, no `Depends`. `make release-check` verifies a clean tree, a
  matching changelog heading, a free tag and cross-compilation to all four
  targets.
- CI: `Test` (fmt-check, vet, test, race), `Cross-build` (+ a stale-fixture
  check), `Lint` (golangci-lint) and `Vulnerability scan` (govulncheck) on every
  push and PR; a `Branch flow` check that fails a PR opened against the wrong
  base. A `Release` workflow builds every archive and package and publishes a
  GitHub release with `SHA256SUMS` attached on a `v*` tag.
- `install.sh`: an arch-detecting installer that verifies the download against
  `SHA256SUMS` and never calls `sudo`.
- `contrib/`: hardened systemd units, sysusers/tmpfiles, an annotated example
  config, an nginx TLS reverse-proxy sample, logrotate and AppArmor profiles, and
  backup / retention / authorized-remote-capture helper scripts.
- `docs/`: architecture, the REST + WebSocket API, the frozen `flow-features-v1`
  reference, packaging, and three ADRs.
- `README.md` with the project overview, box-art views of the rolling log and
  flow inspector, install and usage, and the phase roadmap; `assets/` logo and
  pipeline diagram.
- GitHub issue templates (bug / feature / idea), a pull-request template, and
  `dependabot.yml` (gomod + github-actions, and pip reserved for the trainer).

### Changed

- `synapse` now accepts flags on either side of the subcommand, so
  `synapse classifications --limit 50` and `synapse replay f.pcap --speed max`
  work as written (Go's `flag` package otherwise stops at the first bare word).
- `flow-features-v1` `bytes_forward` / `bytes_backward` `calc` text corrected to
  "IP datagram lengths (IP header included)" — the values were always the full
  datagram length; only the description was wrong.

### Known limitations

- The classifier is a hand-written heuristic, not a trained model; treat its
  verdicts as a demonstration of the pipeline, not detection quality.
- Storage is in-memory only — history is lost on restart and bounded by
  `storage.max_flows`.
- Only classic `pcap` files are read (not `pcapng`); only file replay, no live
  capture.
- Configuration is JSON, not the YAML shown in `PROJECT.md` §23.
- `.deb` packages are unsigned; integrity is via `SHA256SUMS`.
