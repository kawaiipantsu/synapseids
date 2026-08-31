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
