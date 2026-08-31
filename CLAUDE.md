# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What SynapseIDS is

A neural-network **network intrusion detection and live traffic-classification**
platform. A Go data plane turns captured or replayed packets into versioned
bidirectional flow features, scores those features with one or more models, and
streams every result to a live web UI. Training (Python/ONNX) and the React SPA
come later.

`PROJECT.md` is the authoritative specification and engineering contract. When the
spec and the code disagree, the spec wins; changing it is a deliberate act, not a
side effect of implementation. It has a numbered **"Coding Rules for Claude"**
(§28) that governs this repo — read it.

**Repo:** `github.com/kawaiipantsu/synapseids` · **Go 1.27** · `CGO_ENABLED=0` everywhere · **zero third-party dependencies** (see Constraints).

## Current state (Phase 1 — vertical slice)

Done and wired end to end:

```
PCAP file ─▶ packet decode ─▶ flow engine ─▶ flow-features-v1 (48) ─▶ heuristic
            classifier ─▶ REST /api/v1 + live WebSocket ─▶ rolling flow-log (web/)
```

`synapse replay <file.pcap>` runs a capture through the **same** pipeline live
traffic will, so the UI behaves identically. Not yet built (each is a tracked
GitHub issue under an `EPIC: Phase N`): live NIC/tcpdump/SSH/PCAP-over-IP capture,
the Python trainer + ONNX inference runtime + model bundles, SQLite/ClickHouse
storage, distributed `synapse-sensor`, anomaly/drift/comparison, the React SPA.

## Commands

```bash
make help                     # every target
make fmt vet test build       # the pre-commit loop — run all four
make race                     # tests under the race detector (CI runs this)
make coverage lint security   # HTML coverage / golangci-lint / govulncheck
make generate                 # rebuild testdata/pcap/*.pcap from testdata/gen
make build-linux              # 3 binaries × 4 arches: amd64, 386, arm64, arm(v7)
make dist deb                 # release tarballs + .deb packages + SHA256SUMS
make run ARGS='--listen 127.0.0.1:8080'
```

Narrower runs:

```bash
go test ./internal/flow/ -run TestFINTeardown -v
go test ./internal/features/ -run TestGolden -update   # deliberately re-freeze the golden vectors
go test ./internal/pipeline/ -run TestPortScanEndToEnd
```

Quick manual check:

```bash
make build && ./synapsed --listen 127.0.0.1:8080 &
./synapse replay testdata/pcap/portscan.pcap --speed max
./synapse classifications        # portscan flows → SCAN; http/udp → NORMAL
# open http://127.0.0.1:8080/ for the live rolling log
```

## Architecture — what spans multiple files

A strictly one-way data plane; renderers and the API never compute features.

```
cmd/synapsed ─▶ internal/pipeline ─▶ (per flow) features.Extract ─▶ inference.Runtime
                     │                                                     │
     capture.Source ─┘                          events.Bus ◀──────────────┘
     (pcapfile + replay)                        storage.Store
                                                internal/api  (REST + wshub WebSocket)
```

- **`internal/packet`** — decodes Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP into a small
  `packet.Packet`. Bounds-checked; malformed input is counted and skipped, never a
  panic (§28.11). Nothing downstream sees raw bytes.
- **`internal/capture`** — `Source` interface + adapters. `pcapfile` is a
  hand-rolled classic-pcap reader plus a minimal read-only pcapng reader
  (`pcapng.go`: one section, Ethernet/RAW, SHB/IDB/EPB/SPB; multi-section or
  exotic-link pcapng is refused with an `editcap` hint). `replay` paces any
  Source to wall-clock × {0.5,1,2,10,max}.
- **`internal/flow`** — `Key` is the direction-normalized 5-tuple. `Table` owns
  lifetime: close on FIN-both / RST / idle / max-lifetime / capture-end; periodic
  `snapshot` records for long flows; a bounded flow cap with oldest-idle eviction;
  a short "recently closed" grace window so a trailing ACK does not spawn a
  phantom flow. **`Table` is single-goroutine** — feed it from one place.
- **`internal/schema` + `/schemas/*.json`** — the frozen contracts:
  `flow-features-v1` (48 features, embedded JSON), `traffic-classes-v1` (7
  classes), `event-envelope-v1`. `ValidateBundle` is the gate a trained model
  must pass before it can run.
- **`internal/features`** — `Extract(flow.Record) → Vector` computes the frozen
  list. **No raw IP addresses** — only derived behavioural/context values (§8).
  `Normalizer` is a *per-model* concern: the heuristic reads raw values; a trained
  model applies its bundle's `normalizer.json`.
- **`internal/inference`** — `Classifier` interface, `Role`
  (primary/location/global/experimental/anomaly), and `Runtime` which scores a
  vector with every model and **keeps each model's output plus a disagreement
  flag** — never just the combined verdict (§12). `Heuristic` is a transparent
  rule-based stand-in for Phase 1.
- **`internal/events`** — non-blocking fan-out bus; a slow subscriber drops events
  (counted), it never stalls ingestion (§17, §22).
- **`internal/storage`** — `Store` interface; `Mem` is a bounded ring with
  eviction counters. SQLite is a tracked issue.
- **`internal/api` + `internal/wshub`** — one versioned REST surface and one live
  WebSocket channel that carries **batched** event envelopes (JSON arrays) with
  per-client backpressure. Raw packets are never streamed to clients (§18).
- **`internal/pipeline`** — the single wiring both live capture and replay use.

### Things that will bite you

- **Never reorder or re-meaning a released schema.** `flow-features-v1` /
  `traffic-classes-v1` are frozen. A new need is `flow-features-v2` or a new model
  family, not an edit (§8, §9, §28.5-6). The golden test
  (`internal/features/testdata/*.golden.json`) fails on any drift; `-update` only
  when the change is intentional and reviewed.
- **The heuristic scores raw features; trained models score normalized ones.**
  `pipeline` hands the runtime the raw `Vector`. Do not sneak a global normalizer
  back into the pipeline.
- **Flow IDs must be globally unique** across the daemon's lifetime — the daemon
  passes a shared `IDGen`; a bare `flow.Table` counter is per-instance and only
  fine in a single test.
- **Keep the packet path off the slow path.** Storage and WebSocket work must not
  block `pipeline.Run`'s packet loop (§22).
- **Defensive only.** No exploitation, no counter-attack, no traffic modification.
  The product observes, classifies, explains, alerts (§28.17).

## Constraints

- **Zero third-party Go dependencies.** The pcap reader, the L2–L4 decoders and
  the RFC 6455 WebSocket server are all hand-rolled stdlib-only, which guarantees
  clean cross-compilation to `386`/`arm` and an offline build. Adding a dependency
  is a spec-level decision: justify it in the PR, and it must be pure Go
  (`CGO_ENABLED=0` and the four Linux targets are non-negotiable — §27, §28.16).
- **Config is JSON** for now (`internal/config`), not YAML — native YAML is a
  tracked issue. One explicit file + `SYNAPSE_*` env overrides for secrets (§23).
- **Committed PCAP fixtures are allowed here** (unlike some sibling repos): §25 and
  §31.9 mandate golden PCAP → feature-vector tests. `testdata/gen/` builds them;
  commit both.

## Git workflow

Git Flow. `feature/<name>` and `fix/<name>` branch from `develop` and merge back
via PR; `release/<version>` merges into `main` **and** `develop` with an annotated
`v`-prefixed tag on `main`; `hotfix/<...>` branches from `main`. Merges use
`--no-ff` for releases, squash for features. Conventional-commit prefixes
(`feat: fix: build: docs: test: chore: refactor: ci:`). **Never commit feature
work directly to `main`** — the *Branch flow* check and the `main`/`develop`
rulesets reject it. Remote is `git@github.com:kawaiipantsu/synapseids.git`.

## Task discipline

Do not claim it works without running `make test` (and the manual replay check for
pipeline changes). Cite `PROJECT.md` or the stdlib rather than inventing protocol
behaviour. Avoid unrelated refactors. A change is done when: implemented, tested,
`make fmt vet test build` green, cross-build green if you touched anything
build-affecting, user-facing behaviour documented in `docs/` and `CHANGELOG.md`
under `[Unreleased]`, errors handled, formatted. Record significant architecture
decisions as ADRs in `docs/adr/`.
