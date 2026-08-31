<p align="center"><img src="assets/github-header-banner.png" alt="SynapseIDS" width="100%"></p>

<div align="center">

# SynapseIDS

**Neural-network network intrusion detection & live traffic classification — packets become flows, flows become features, features get classified, and every verdict streams to your screen.**

<br/>

![Go](https://img.shields.io/badge/Go-1.27%2B-0E3A4B?style=for-the-badge&logo=go&logoColor=35C1D6)
![Platform](https://img.shields.io/badge/Linux-amd64%20·%20i386%20·%20arm64%20·%20armhf-0E3A4B?style=for-the-badge&logo=linux&logoColor=35C1D6)
![CGO](https://img.shields.io/badge/CGO-disabled-35C1D6?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-0E3A4B?style=for-the-badge)
![Status](https://img.shields.io/badge/status-early%20development-35C1D6?style=for-the-badge)
![Scope](https://img.shields.io/badge/scope-defensive--only-0E3A4B?style=for-the-badge)

<br/>

<samp>one Go daemon · replay runs the real pipeline · 48-feature frozen contract · live WebSocket rolling log · four static Linux targets + `.deb`</samp>

</div>

<br/>

> [!IMPORTANT]
> **SynapseIDS is in early development — this is Phase 1 of an [8-phase plan](#roadmap).** No release is tagged yet; build from source today.
>
> **Working now:** PCAP replay → the flow engine → the frozen `flow-features-v1` vector (48 features) → a transparent rule-based classifier → the `/api/v1` REST surface → a React operator console at `/` (Dashboard, full-screen Flow Log, Flow Inspector, Replay control) fed by a live WebSocket. Replay runs the *exact* pipeline live capture will.
>
> **Not here yet:** live NIC / tcpdump / SSH capture, trained ONNX models wired into the daemon, SQLite persistence (storage is in-memory only), distributed `synapse-sensor` agents, and the rest of the [§19](PROJECT.md) UI beyond the four Phase-1 views (every other route in the SPA is a "Planned — Phase N" placeholder). The offline Python trainer that produces model bundles now lives in [`trainer/`](trainer/) (Phase 2, not yet wired to the daemon). See [the roadmap](#roadmap).

<br/>

## 📑 Table of Contents

- [✨ Why SynapseIDS](#why)
- [🖥️ What it looks like](#look)
- [🧠 The pipeline](#pipeline)
- [📦 Install](#install)
- [🚀 Usage](#usage)
- [🧪 Development](#development)
- [🗺️ Roadmap](#roadmap)
- [🔐 Security](#security)
- [📄 License](#license)

<br/>

<a id="why"></a>

## ✨ Why SynapseIDS

| | |
|---|---|
| 🔻 **One pipeline, packets to verdict** | `capture → packet decode → flow engine → flow-features-v1 → inference runtime → REST + WebSocket → rolling log`. Every stage is a separate Go package behind an explicit interface; nothing downstream knows whether a packet came from a file or a NIC. |
| 🧊 **Frozen, versioned contracts** | `flow-features-v1` is 48 ordered numeric features; `traffic-classes-v1` is 7 ordered classes. Both are embedded in the binary, served at `/api/v1/schemas/*`, and self-checked on startup. A released schema is never reordered — a change means a new version — and a model whose contract does not match is rejected *before* it runs. |
| 🎛️ **Ensemble-ready inference** | The runtime scores every flow through all loaded models, stores each model's own class vector (not just the merged verdict), and flags disagreement as a first-class signal. Phase 1 loads one model — `heuristic-v1`, role `primary` — and the ensemble plumbing is already there for the ONNX models in Phase 2. |
| 🔁 **Replay is not a special case** | `synapse replay` feeds packets through the identical `flow → features → inference → store → events` path as live capture, so the rolling log behaves the same for a captured file and (later) a live interface. |
| 🔎 **Transparent Phase-1 classifier** | The stand-in model is rule-based and readable: a firm `normal` baseline, explicit rules for `scan` / `dos_ddos` / `brute_force` / `web_attack` / `botnet_c2`, and `suspicious` for "odd but not conclusive" rather than forcing a guess into an attack class. |
| 📦 **Zero-dependency data plane** | Pure Go, `CGO_ENABLED=0`, standard library only — `go.mod` has no third-party `require`. Four static Linux targets (`amd64`, `386`, `arm64`, `arm` v7) plus a `.deb` for each, built by `make`. |
| 🛡️ **Defensive only** | SynapseIDS observes, classifies, explains, and alerts. It has no capability to attack, modify, or inject traffic, by design. The management API binds to `127.0.0.1` unless you change it. |

<br/>

<a id="look"></a>

## 🖥️ What it looks like

### The full-screen rolling flow-classification log

The primary product view — a kiosk-style stream that appends a row per classified flow and never blocks the capture path behind it.

```text
  Synapse▪IDS   flows 512 · classified 512 · clients 3 · ● live      min conf [  0 ]  class [ all ▾ ]  [ Pause ] [ Clear ]
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  time          sensor   source                 →  destination           proto   class        confidence      models
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  17:41:09.204  local    10.20.4.18:51222       →  93.184.216.34:443     TCP    ┃NORMAL     ┃  ▇▇▇▇▇▇▇▇  96.1%   P:normal 96
  17:41:09.271  local    10.20.7.41:44118       →  10.20.8.9:445         TCP    ┃  SCAN     ┃  ▇▇▇▇▇▇▇▇  99.3%   P:scan 99
  17:41:09.286  local    10.20.7.41:44119       →  10.20.8.9:139         TCP    ┃  SCAN     ┃  ▇▇▇▇▇▇▇▇  99.3%   P:scan 99
  17:41:09.301  local    10.20.7.41:44120       →  10.20.8.9:3389        TCP    ┃  SCAN     ┃  ▇▇▇▇▇▇▇▇  99.3%   P:scan 99
  17:41:09.560  local    10.20.4.18:51230       →  1.1.1.1:53            UDP    ┃NORMAL     ┃  ▇▇▇▇▇▇▇▇  96.1%   P:normal 96
  17:41:09.771  local    10.20.4.18:51231       →  93.184.216.34:443     TCP    ┃NORMAL     ┃  ▇▇▇▇▇▇▇▇  96.1%   P:normal 96
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  replay:  [ testdata/pcap/portscan.pcap        ]  [ max ▾ ]  [ Start ] [ Stop ]   idle                        ⟦THUGS⟧ · (c) 2026
```

<sub>Illustrative. The page at <code>http://127.0.0.1:8080/</code> renders exactly these columns and streams new rows over WebSocket; the class cell is colour-coded per class, rows below 60% confidence are dimmed, and model disagreement draws an accent bar on the left edge. <b>Pause</b> freezes the view without dropping backend events, and a replay appears in the same stream. Phase-1 replays report sensor <code>local</code>; multi-sensor names arrive with distributed capture (Phase 6). Every <code>NORMAL</code> verdict from the Phase-1 heuristic sits at ~96.1% by construction; port-scan probes land at ~99.3%.</sub>

### The flow inspector

Select any row to explain the verdict against the raw feature vector and every model's output.

```text
  FLOW #4    10.0.0.66:40015  →  10.0.0.1:1723   TCP           Phase 5 view · data: GET /api/v1/flows/4
  ────────────────────────────────────────────────────────────────────────────────────────────────
  direction     initiator → responder             close reason   fin_rst          snapshot #0
  first seen    13:00:00.045Z                     last seen      13:00:00.046Z    duration  0.001 s
  packets       fwd 1  ·  bwd 1                    bytes          fwd 40  ·  bwd 40
  tcp flags     SYN 1  ·  ACK 1  ·  RST 1         payload mean   0 B

  flow-features-v1 (raw)            value        normal band
  packets_per_second               2000.0       0.5 – 40
  syn_ack_ratio                    1.00         0.7 – 1.4
  packet_size_mean                 40 B         400 – 900 B
  small_packet_ratio               1.00         0.0 – 0.3
  packet_direction_ratio           0.50         ~0.5
  dest_port_is_wellknown           0            1 for a known service

  traffic-classes-v1     normal   scan   dos_ddos  brute_force  botnet_c2  web_attack  suspicious
  heuristic-v1 (primary)  0.001   0.999    0.000      0.000        0.000      0.000       0.000
                          →  verdict   SCAN   99.9%

  model            role           class   score    note
  heuristic-v1     primary        scan    0.999    lone SYN answered only by RST
  —                experimental   —       —        ONNX shadow model loads in Phase 2
  disagreement:  none (1 model)          anomaly score:  —  (anomaly model is Phase 7)
```

<sub>Illustrative. The SPA's Flow Inspector drawer is live in Phase 1: click any row in the Flow Log to see the full 5-tuple, timing, packet/byte and TCP metadata, all 48 raw <code>flow-features-v1</code> values joined to the schema, the full class-probability vector and every model's output. Values come from <code>GET /api/v1/flows/{id}</code> + <code>GET /api/v1/schemas/features</code>. Normalized inputs, snapshot history and human-review status are labelled Phase-2 stubs; the "normal band" reference column arrives with trained baselines in Phase 2.</sub>

### and from the CLI

```console
$ synapsed --listen 127.0.0.1:8080 &
2026/08/31 17:40:58 synapsed 0.1.0-dev listening on http://127.0.0.1:8080  (feature schema flow-features-v1, 1 models)

$ synapse replay testdata/pcap/portscan.pcap --speed max
{
  "id": "replay-1756662058123456789",
  "speed": "max"
}

$ synapse classifications
  13:00:00.000 TCP   local        10.0.0.66:40000 -> 10.0.0.1:21           SCAN         99.9%
  13:00:00.003 TCP   local        10.0.0.66:40001 -> 10.0.0.1:22           SCAN         99.3%
  13:00:00.006 TCP   local        10.0.0.66:40002 -> 10.0.0.1:23           SCAN         99.3%
  13:00:00.009 TCP   local        10.0.0.66:40003 -> 10.0.0.1:25           SCAN         99.3%
  13:00:00.012 TCP   local        10.0.0.66:40004 -> 10.0.0.1:53           SCAN         99.3%
  13:00:00.015 TCP   local        10.0.0.66:40005 -> 10.0.0.1:80           SCAN         99.9%
  13:00:00.018 TCP   local        10.0.0.66:40006 -> 10.0.0.1:110          SCAN         99.3%
  13:00:00.021 TCP   local        10.0.0.66:40007 -> 10.0.0.1:135          SCAN         99.3%
  ...
  # 20 most recent (24 flows total, one per probed port); pass --limit for more.
  # Replaying testdata/pcap/http.pcap or udp.pcap instead prints NORMAL ~96.1%.
```

<br/>

<a id="pipeline"></a>

## 🧠 The pipeline

<p align="center"><img src="assets/architecture.svg" alt="SynapseIDS pipeline: capture source → packet decode → flow engine → flow-features-v1 → inference runtime → REST + WebSocket → web UI" width="100%"></p>

A capture source — a PCAP file today, a NIC / tcpdump stream / remote sensor later — produces decoded packets. The **flow engine** groups them into bidirectional flows on a direction-normalized 5-tuple and closes a flow on TCP FIN/RST, a 30 s idle gap, a 5 min lifetime cap, or capture end; long-lived flows emit a snapshot every 60 s so a verdict never waits indefinitely for a flow to finish.

Each closed or snapshotted flow becomes one **`flow-features-v1`** vector: 48 numeric features derived only from that flow — packet and byte counts, rates, size statistics, inter-arrival timing, TCP-flag tallies, direction ratios, and internal/external context — and never from raw IP addresses. The **inference runtime** scores the vector through every loaded model, keeps each model's full class distribution and top class, and sets a disagreement flag when non-anomaly models pick different classes.

The verdict plus the flow record go into the in-memory store (the most recent ~50,000 of each) and onto an in-process **event bus**; a full subscriber drops events and counts them rather than stalling ingestion. The API pump batches those events to WebSocket clients every 100 ms, and the page at `/` renders the stream as the rolling log. `synapse replay` runs this identical path, which is why replayed and live traffic look the same on screen.

The Phase-2 **`synapse-trainer`** (Python/PyTorch, in [`trainer/`](trainer/)) is the offline other half: it reads a labelled `flow-features-v1` dataset and exports a self-describing bundle — `model.onnx` (opset 17, softmax baked in) plus `metadata.json`, `normalizer.json`, `metrics.json` and `training-recipe.json` — that a Go ONNX runtime will validate and load. See [ADR 0007](docs/adr/0007-python-trainer-and-bundle-export.md) for the bundle contract.

The output contract, **`traffic-classes-v1`** (frozen, 7 classes):

- `normal` — benign traffic
- `scan` — host / port / service discovery
- `dos_ddos` — denial of service or distributed denial of service
- `brute_force` — credential brute force against a service
- `botnet_c2` — botnet command-and-control channel
- `web_attack` — web application attack (injection, traversal, RCE attempt)
- `suspicious` — anomalous but unattributed — **a supervised catch-all class, not an anomaly score.** A separate novelty/anomaly model is Phase 7.

<br/>

<a id="install"></a>

## 📦 Install

Requires **Go 1.27+**. No C toolchain and no third-party Go modules. _No release is tagged yet — build from source. `make dist && make deb` produce the `.tar.gz` archives, `.deb` packages and `SHA256SUMS` that the release workflow attaches to a tag._

### 🔨 From source

```bash
git clone https://github.com/kawaiipantsu/synapseids.git
cd synapseids
make build            # builds synapsed, synapse, synapse-sensor — CGO_ENABLED=0, static
./synapsed --version
```

### 🌍 Cross-compile (all four Linux targets)

```bash
make build-linux      # dist/synapseids_<ver>_linux_{amd64,386,arm64,arm}/{synapsed,synapse,synapse-sensor}
```

<div align="center">

| `make` target | `GOARCH` | `.deb` arch | `uname -m` |
|:--|:--|:--:|:--|
| 🐧 `linux/amd64` | `amd64` | `amd64` | `x86_64` |
| 🐧 `linux/386` | `386` | `i386` | `i686` |
| 🐧 `linux/arm64` | `arm64` | `arm64` | `aarch64` |
| 🐧 `linux/arm` (v7, `GOARM=7`) | `arm` | `armhf` | `armv7l` |

</div>

### 📦 Debian / Ubuntu

```bash
sudo dpkg -i synapseids_<version>_amd64.deb      # or _i386 / _arm64 / _armhf
```

One package (`synapseids`) carries all three binaries, a man page each, and DEP-5 copyright. No `Depends` — the binaries are static.

### ⚡ One line (Linux, no sudo)

```bash
curl -fsSL https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/install.sh | sh
```

Detects your arch, downloads the matching release archive, verifies it against `SHA256SUMS`, and installs all three binaries to `~/.local/bin` (or `/usr/local/bin` when writable). Pin with `SYNAPSEIDS_VERSION=v0.1.0`; redirect with `SYNAPSEIDS_INSTALL=/opt/bin`.

<br/>

<a id="usage"></a>

## 🚀 Usage

```bash
# 1. start the daemon — management API on 127.0.0.1:8080 by default
synapsed &

# 2. open the live rolling log
xdg-open http://127.0.0.1:8080/

# 3. replay a committed fixture through the real pipeline
synapse replay testdata/pcap/portscan.pcap --speed max

# 4. read the results back
synapse status
synapse classifications --limit 50
curl -s http://127.0.0.1:8080/api/v1/status | jq .
curl -s 'http://127.0.0.1:8080/api/v1/classifications?limit=50' | jq .
```

**`synapsed`** — `--config FILE` (JSON config), `--listen HOST:PORT` (default `127.0.0.1:8080`), `--capture IFACE` (repeatable — capture live traffic from a NIC, Phase 3), `--version`. Binding off loopback logs a warning; put an authenticating proxy in front.

Live capture (Phase 3): `synapsed --capture eth0` opens an `AF_PACKET` raw socket and runs the interface through the same pipeline a replay uses; `GET /api/v1/captures` then shows it counting packets, bytes, pps/bps and kernel drops. Equivalent JSON config: `capture.sources: [{ "name": "eth0", "kind": "nic", "interface": "eth0", "promiscuous": true, "filter": "" }]` (`filter` is `""` or a built-in cBPF preset — `ip`, `ip6`, `ip-any`, `not-arp`); or set `SYNAPSE_CAPTURE_IFACE`. Needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for promiscuous mode) — not root; the `contrib/systemd` unit grants both. A source that cannot open is logged and skipped, and the API keeps serving.

**`synapse`** talks to a running `synapsed` and holds no logic of its own:

| Command | Does |
|:--|:--|
| `synapse status` | daemon status: counters, loaded models, replay state |
| `synapse models` | loaded models — `id` · `family` · `role` |
| `synapse flows [--limit N]` | recent flows (JSON) |
| `synapse classifications [--limit N]` | recent verdicts as the rolling-log table above |
| `synapse replay <file.pcap> [--speed 0.5\|1\|2\|10\|max]` | start a PCAP replay |
| `synapse replay-stop` | stop the running replay |
| `synapse version` | CLI build metadata |

| Flag | Default | Env |
|:--|:--|:--|
| `--server URL` | `http://127.0.0.1:8080` | `SYNAPSE_SERVER` |
| `--limit N` | `20` | — |
| `--speed S` | `1` | — |

**REST** (`/api/v1`): `status` · `flows` · `flows/{id}` · `classifications` · `models` · `captures` · `captures/{name}` · `schemas/features` · `schemas/classes` · `replay` (GET/POST) · `replay/stop` (POST) · `stream` (WebSocket).

<br/>

<a id="development"></a>

## 🧪 Development

```bash
make fmt vet test build      # the pre-commit loop
make race                    # tests under the race detector
make coverage                # writes coverage.html
make generate                # rebuild testdata/pcap/*.pcap from testdata/gen
make lint                    # golangci-lint when installed, else go vet
make security                # govulncheck when installed
make release-check           # fmt-check + vet + lint + test + cross-build
```

The web console lives in `web/ui/` (TypeScript + React + Vite 5). The **Go build never runs Node** — the bundle in `web/dist/` is committed and embedded (`//go:embed all:dist`, [ADR 0004](docs/adr/0004-react-spa-and-committed-build-output.md)). After editing anything under `web/ui/`, rebuild and commit `web/dist/`:

```bash
make web                     # npm ci && vite build  → web/dist/  (commit the result)
make web-dev                 # Vite dev server, proxies /api + /api/v1/stream to :8080
make web-check               # tsc --noEmit
```

### 🌳 Git flow

`main` is tagged releases only and accepts merges from `release/*` and `hotfix/*` only · `develop` integrates · work happens on `feature/<name>` off `develop`. A PR opened against the wrong base fails the **Branch flow** check. CI also runs `fmt-check`, `vet`, `test`, `race`, cross-build, lint and `govulncheck` on every push/PR to `main` and `develop`, and fails if `testdata/pcap` is stale (run `make generate` and commit).

See [CONTRIBUTING.md](CONTRIBUTING.md) and [PROJECT.md](PROJECT.md) — `PROJECT.md` is the authoritative spec and its §28 "Coding Rules" govern the codebase.

<br/>

<a id="roadmap"></a>

## 🗺️ Roadmap

<div align="center">

| Phase | | Scope | Status |
|:--:|:--|:--|:--:|
| 1 | Vertical slice | PCAP replay → flow engine → `flow-features-v1` → rule-based classifier → REST + WebSocket → React operator console (Dashboard, Flow Log, Flow Inspector, Replay); 4-arch build matrix, CI, `.deb` + `install.sh` packaging | ✅ this release |
| 2 | Real inference | Python trainer, configurable hidden layers, ONNX export, Go ONNX inference, model bundles + registry, contract validation | ⬜ |
| 3 | Live capture | local interface, tcpdump stream, SSH tcpdump, capture-source UI, capture performance metrics | ⬜ |
| 4 | Dataset & training workflow | dataset manager, multi-dataset training recipes, live training dashboard, confusion matrices, model activation flow | ⬜ |
| 5 | Investigation | flow inspector, host profiles, investigation mode, classification timeline, human-review queue, curated datasets | ⬜ |
| 6 | Distributed sensors | `synapse-sensor`, authenticated encrypted transport, raw/flow/feature modes, sensor topology, location metadata | ⬜ |
| 7 | Advanced ML | anomaly autoencoder, model comparison, shadow models, disagreement views, drift monitoring, model lineage | ⬜ |
| 8 | Scale | AF_PACKET/eBPF capture, ClickHouse, NATS/Kafka, distributed & GPU inference, QUIC sensor transport — only when measurements demand it | ⬜ |

</div>

Each phase and its sub-tasks are tracked as GitHub issues (epics + children).

<br/>

<a id="security"></a>

## 🔐 Security

- **Defensive only.** SynapseIDS observes, classifies, explains, and alerts. There is no exploitation, counter-attack, or traffic-modification capability, and none will be added.
- **Localhost by default.** The management API binds to `127.0.0.1:8080`; the daemon logs a warning if it is bound anywhere else. Use an authenticating reverse proxy for remote access.
- **Untrusted input.** All packet-derived data is treated as untrusted. Uploaded PCAP paths are checked and request bodies are size-capped, queues are bounded, and a model whose feature/output contract does not match is rejected before it runs.
- **No auto-activation.** Newly trained models (Phase 2+) are never activated automatically; activation is an explicit, audit-logged operator action.
- **Remote capture** (Phase 3+) only against systems you are authorized to monitor. In Phase 1 `synapsed` opens no outbound connections — it reads PCAPs and serves the local API.

Report a vulnerability privately — see [SECURITY.md](SECURITY.md).

<br/>

<a id="license"></a>

## 📄 License

[MIT](LICENSE). See [PROJECT.md](PROJECT.md) for the full system specification and [CHANGELOG.md](CHANGELOG.md) for release history.

<br/>

<div align="center">
<sub>⟦ <b>THUGS</b> ⟧ &nbsp;·&nbsp; (c) 2026 &nbsp;·&nbsp; observe · classify · explain · alert</sub>
</div>
