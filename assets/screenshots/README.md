# Screenshots

Captures of SynapseIDS actually running. Everything here is **real output** from
the daemon, the CLI and the React SPA — no mockups, no hand-edited numbers.

Regenerate them after a UI change; see [How these were made](#how-these-were-made).

## Web UI (`web/ui`, served by `synapsed` at `/`)

| | |
|---|---|
| [`webui-dashboard.png`](webui-dashboard.png) | **LIVE ▸ Dashboard** (§19.1) — live counters from `/api/v1/status`, uPlot classifications/sec and flow-event/sec sparklines, class and protocol breakdowns, rolling top talkers and destination ports. Cards with no data source yet are greyed and marked *needs API*. |
| [`webui-flow-log.png`](webui-flow-log.png) | **LIVE ▸ Flow Log** (§19.2) — the primary product view. Rows append live off the WebSocket; pause/resume buffers instead of dropping, plus density, max-rows, class / min-confidence / protocol / text filters and a kiosk toggle. |
| [`webui-flow-log-brute-force.png`](webui-flow-log-brute-force.png) | Flow Log filtered to `brute_force` — a real MySQL credential-stuffing run against `10.10.10.21:3306`, picked out of ordinary browsing traffic. |
| [`webui-flow-log-scan.png`](webui-flow-log-scan.png) | Flow Log filtered to `scan` while a port-scan capture replays. |
| [`webui-flow-log-wide.png`](webui-flow-log-wide.png) | The same view at 1920×1080, roughly what a wallboard shows. |
| [`webui-flow-inspector.png`](webui-flow-inspector.png) | **Flow Inspector** (§19.3) — opened from a row: the full `traffic-classes-v1` probability vector, per-model outputs, the disagreement flag, 5-tuple and direction, timing, packet/byte and TCP metadata. |
| [`webui-flow-inspector-features.png`](webui-flow-inspector-features.png) | The Inspector scrolled to **all 48 raw `flow-features-v1` values**, joined to the frozen schema so each row carries its name, calculation and unit. |
| [`webui-capture-sources.png`](webui-capture-sources.png) | **CAPTURE ▸ Sources** (§19.14) — two live sources of different kinds added at runtime, with packets/bytes/pps/bps/drops/decode-errors/last-packet/filter, plus the add-source form and its mandatory *"I am authorised to monitor this target"* assertion (§28.18). |
| [`webui-replay.png`](webui-replay.png) | **CAPTURE ▸ Replay** — drive a PCAP through the same pipeline live traffic uses, at 0.5× … max. |
| [`webui-architecture.png`](webui-architecture.png) | **ML ▸ Architecture** (§19.9) — locked 48-input / 7-output layers, an editable hidden stack, and live parameter-count / size / FLOP estimates that match what the trainer reports. |

## CLI and daemon

| | |
|---|---|
| [`cli-replay-classify.png`](cli-replay-classify.png) | `synapse replay … --speed max` then `synapse classifications` — a port scan coming back as `SCAN` at 99.3%. |
| [`cli-real-world.png`](cli-real-world.png) | A 27 MB real-world capture (68,810 packets) replayed at max speed, with the resulting class histogram and the brute-force flows it found. |
| [`cli-captures.png`](cli-captures.png) | Live capture sources, the §28.18 authorisation gate rejecting an unauthorised remote source with `HTTP 400`, and `DELETE` removing sources at runtime. |
| [`cli-status.png`](cli-status.png) | `synapse status` — the daemon's health, storage, event-bus, flow-table and WebSocket counters. |
| [`cli-daemon-start.png`](cli-daemon-start.png) | `synapsed --version` and the startup log line. |

## How these were made

The web-UI images are real browser screenshots of a running daemon, captured
headlessly at 2× device-pixel-ratio. The CLI images are **real captured
transcripts** typeset in the project palette — the text is exactly what the
commands printed, only the typography is applied.

The traffic behind them is a locally captured file containing ordinary browsing
plus an `nmap` scan and a MySQL brute-force attempt, together with the committed
synthetic fixtures under `testdata/pcap/`. Per PROJECT.md §28.18, only
authorised or synthetic captures are used.

The capture tooling lives outside the repository on purpose — it needs a browser
and a Node/puppeteer install, and neither belongs in a tree whose Go build is
deliberately dependency-free (§28.16). To redo them:

1. `make build && ./synapsed --listen 127.0.0.1:8300`
2. Feed it traffic — `./synapse replay <file.pcap> --speed max`, and/or
   `POST /api/v1/captures` a live source.
3. Point a headless Chrome at `http://127.0.0.1:8300/#/<route>` for each view,
   and capture the CLI transcripts with plain shell redirection.

Note that several views only look interesting while data is flowing: the Flow Log
keeps a bounded window of recent rows in the browser, so a class filter finds
nothing unless traffic of that class is streaming at the time.
