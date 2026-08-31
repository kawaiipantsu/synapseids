# Changelog

All notable changes to SynapseIDS are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`trainer/` — the Phase 2 Python training service** (`synapse-trainer`,
  issues #21 + #23). A standalone PEP 621 package, separate from the Go tree, that
  turns a labelled `flow-features-v1` dataset into a deployable model bundle:
  - `synapse_trainer.schema` re-reads the frozen `schemas/features/flow-features-v1.json`
    and `schemas/outputs/traffic-classes-v1.json` (or `$SYNAPSE_SCHEMA_DIR`) —
    `INPUT_SIZE` 48, `OUTPUT_SIZE` 7, `FEATURE_NAMES`, `CLASS_NAMES`,
    `check_compatible` (rejects a dataset whose schema name or column count
    disagrees).
  - `architecture` — `HiddenLayer` / `Architecture` with a **locked** 48-in /
    7-out contract and an editable hidden stack; `parameter_count`,
    `estimated_size_bytes`, `rough_flops`, JSON round-trip (the compute half of
    issue #22).
  - `normalize` — pure-numpy `standard` / `minmax` / `identity` scaler emitting
    the exact `normalizer.json` (48 ordered per-feature entries; `std` floored at
    `1e-9`, never `min >= max`).
  - `dataset` — CSV loader (48 schema-named feature columns + `label`) and a
    reproducible, stratified-when-scikit-learn-is-present split that never leaks
    the test set into training.
  - `recipe` — parse + validate `training-recipe.json` (dataset weights and
    train/val/test fractions must each sum to ~1.0; all fields but `datasets`
    default).
  - `train` — builds the PyTorch MLP, trains with the recipe's
    optimizer/scheduler/early-stopping/class-weighting/seed, yields per-epoch
    progress dicts (with an optional `progress_url` POST), and computes accuracy,
    macro P/R/F1, per-class metrics and confusion matrix. `torch` is imported
    behind a guard.
  - `export` (**issue #23**) — `export_bundle` writes `model.onnx`
    (`torch.onnx.export`, opset 17, fixed batch 1, input `features` `[1,48]`,
    output `scores` `[1,7]`, softmax included), `metadata.json` (the contract the
    Go bundle-gate validates; `model_hash` is a sha256 of the written ONNX bytes),
    `normalizer.json`, `metrics.json` and `training-recipe.json`. The JSON
    builders are torch-free.
  - `synapse-trainer` CLI: `train --recipe --data --out [--name]` and
    `inspect-arch --recipe` (parameter count / size / FLOPs, no torch).
  - `trainer/tests/` — pytest suite that passes with only `numpy` installed
    (torch/onnx asserts self-skip); `trainer/examples/` with a sample recipe and
    dataset header.
- CI: `.github/workflows/trainer-ci.yml` (issue #61) — a `trainer/**`-scoped
  workflow, separate from the Go `ci.yml`: a fast job on numpy + pytest, and a
  slower job that installs the CPU PyTorch/ONNX wheels and runs the export tests.
- `docs/adr/0007-python-trainer-and-bundle-export.md` — records Python + PyTorch
  per §27, the guarded-import approach, opset 17 / fixed batch 1, and the exact
  five-file bundle contract as the trainer↔daemon interface.

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
