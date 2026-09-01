# `synapse.json` — annotated reference

THUGS(red) SynapseIDS · `synapsed --config /etc/synapseids/synapse.json`

JSON has no comments, so this file documents every key in
[`synapse.json`](synapse.json). It is authoritative against
`internal/config/config.go`; cross-reference PROJECT.md §23 (Configuration),
§7 (Flow Engine), §18 (API), §20 (Storage), §21 (Security).

## How the daemon loads config

1. Start from the built-in defaults (`config.Default()`).
2. If `--config FILE` is given, decode the JSON on top of the defaults. Unknown
   keys are a **hard error** (`DisallowUnknownFields`) — keep the file exactly to
   the schema below; do not leave stray keys.
3. Apply `SYNAPSE_*` environment overrides — these **always win** over the file
   (see `contrib/systemd/synapsed.env`).
4. Validate. A validation failure exits non-zero before the listener opens.

Missing keys are allowed (they keep the default); the shipped `synapse.json`
sets all of them explicitly so nothing is a surprise.

### Duration format

Durations are Go duration strings parsed by `time.ParseDuration`: a number plus a
unit, units `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`. **There is no day or week
unit** — 30 days is `"720h"`, 90 days is `"2160h"`. A bare number is nanoseconds.

## `server`

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `server.listen` | string `host:port` | `127.0.0.1:8080` | `127.0.0.1:8080` | Bind address for the REST API and the `/api/v1/stream` WebSocket. Must contain a `:`. Bound to loopback by default (PROJECT.md §21); a non-loopback value is allowed but logged as a `WARNING` at startup — put an authenticating TLS reverse proxy in front (`contrib/nginx/`). Env: `SYNAPSE_LISTEN`; CLI: `--listen`. |
| `server.web_root` | string (dir path) | `""` | `""` | Directory of static UI assets served at `/`. Empty = serve the binary's built-in page. Set to e.g. `/usr/share/synapseids/web` once the SPA package is installed. Env: `SYNAPSE_WEB_ROOT`. |

## `storage`

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `storage.driver` | string enum | `memory` | `memory` | Persistence backend. Only `"memory"` is functional in this build. `"sqlite"` passes enum validation but then **fails** with "not implemented yet (tracked); use memory". ClickHouse is a future option (PROJECT.md §20). |
| `storage.path` | string (file path) | `./data/synapse.db` | `/var/lib/synapseids/synapse.db` | On-disk location for file-backed drivers. **Ignored by the `memory` driver.** Set to a path inside the unit's `StateDirectory` so a future sqlite backend needs no unit change. Env: `SYNAPSE_STORAGE_PATH`. |
| `storage.max_flows` | int | `50000` | `50000` | Capacity of the in-memory ring buffers. Applies to **both** the recent-flows ring and the recent-classifications ring; older records are evicted (eviction is counted and visible in `/api/v1/status`). Distinct from `capture.max_flows`. Raise for a longer scrollback at the cost of RAM. |

## `capture`

Flow-engine timing (PROJECT.md §7). All four are also consumed by PCAP replay,
which runs the identical pipeline.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `capture.flow_idle_timeout` | duration | `30s` | `30s` | A flow with no packets for this long is closed and emits its final record. Must be `> 0`. |
| `capture.flow_max_lifetime` | duration | `5m` | `5m` | Hard cap on a single flow's wall-clock lifetime; the flow is closed even if still active. Must be `> 0`. |
| `capture.snapshot_interval` | duration | `60s` | `60s` | Long-lived flows emit a periodic snapshot record on this cadence so classification does not wait for the flow to close (PROJECT.md §7). |
| `capture.max_flows` | int | `200000` | `200000` | Upper bound on the live flow table (concurrent tracked flows). Must be `>= 1`. When full, the oldest idle flow is evicted. Env: `SYNAPSE_MAX_FLOWS` (ignored unless `> 0`). |
| `capture.sources` | array | `[]` | `[]` | Live capture inputs opened at startup (Phase 3). Each is an object — see below. `--capture IFACE` and `SYNAPSE_CAPTURE_IFACE` append a promiscuous NIC source without editing the file. A source that fails to open is logged and skipped; the daemon keeps serving the API. |

> **These objects are also the runtime API body.** One `capture.sources[]` entry
> is exactly the JSON `POST /api/v1/captures` takes, and it is checked by the
> same validator, so anything valid here is valid there and vice versa
> (`DELETE /api/v1/captures/{name}` removes it again). Nothing posted at runtime
> is written back to this file — it lives until the daemon restarts. The
> mutating routes are unauthenticated and rely on the loopback bind (issue #58);
> see [docs/api.md](../../docs/api.md) and
> [ADR 0013](../../docs/adr/0013-runtime-capture-source-management.md).

### `capture.sources[]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | — | Unique label shown in `GET /api/v1/captures`. Required. |
| `kind` | string | — | `"nic"` (local `AF_PACKET` interface), `"tcpdump"` (local `tcpdump -w -` subprocess), `"ssh"` (authorized remote `ssh … tcpdump -w -`) or `"pcap-over-ip"` (a framed authenticated TLS stream from a remote sensor, see below). Required. |
| `interface` | string | — | For `nic`/`tcpdump`: local NIC name (`eth0`, `lo`, …). For `ssh`: the **remote** interface. Required for `nic`/`tcpdump`/`ssh`; unused by `pcap-over-ip`. |
| `promiscuous` | bool | `false` | `nic` only. Put the interface into promiscuous mode. Needs `CAP_NET_ADMIN`. |
| `snaplen` | int | `0` → `262144` | Bytes copied per frame. `0` uses the default; max `262144`. |
| `filter` | string | `""` | **Meaning is per-kind.** `nic`: `""` (everything) or a built-in cBPF preset — `ip`, `ip6`, `ip-any`, `not-arp`. `tcpdump`/`ssh`: a raw tcpdump filter expression (`"tcp port 80 or udp"`), tokenised and passed as arguments, never through a shell. |
| `binary` | string | `"tcpdump"` / `"ssh"` | `tcpdump`: the capture binary. `ssh`: the ssh client binary. |
| `extra_args` | string[] | `[]` | `tcpdump` only. Extra tcpdump arguments, inserted before the filter tokens. |
| `destination` | string | — | `ssh` only. `user@host` or an `ssh_config` alias. Required for `ssh`. |
| `port` | int | `0` | `ssh` only. SSH port; `0` = ssh default. |
| `identity_file` | string | `""` | `ssh` only. Private-key path (`ssh -i`). |
| `remote_binary` | string | `"tcpdump"` | `ssh` only. tcpdump binary on the remote host. |
| `known_hosts` | string | `"strict"` | `ssh` only. `"strict"` (`StrictHostKeyChecking=yes`) or `"accept-new"` (trust on first use). |
| `extra_ssh_args` | string[] | `[]` | `ssh` only. Extra ssh arguments, inserted before the destination. |
| `authorized` | bool | `false` | **`ssh` only — required `true`.** An explicit assertion that you are authorised to monitor `destination` (PROJECT.md §21, §28.18). A `kind:"ssh"` source without it is a config error. |

Opening any NIC source needs `CAP_NET_RAW`; promiscuous mode also needs
`CAP_NET_ADMIN`. Running as root is **not** required — grant the capabilities
(`setcap cap_net_raw,cap_net_admin+eip /usr/bin/synapsed`, or use the
`contrib/systemd` unit, which sets `AmbientCapabilities`). A `tcpdump` source
needs `tcpdump` on `PATH` and the same capture privilege. On a permission /
lookup error the daemon logs a line and continues API-only.

`ssh` runs with `-o BatchMode=yes` so it never blocks on an interactive prompt —
a password-only host fails fast; use a key. The subprocess is managed directly
(no temporary files) and is **not** restarted automatically if it exits — the
source shows `state:"error"` on `GET /api/v1/captures`.

Example:

```json
"sources": [
  { "name": "wan", "kind": "nic", "interface": "eth0", "promiscuous": true, "snaplen": 0, "filter": "ip-any" },
  { "name": "span0", "kind": "tcpdump", "interface": "eth1", "filter": "tcp or udp", "snaplen": 65535 },
  { "name": "edge-fw", "kind": "ssh", "destination": "sensor@10.0.0.9", "interface": "eth0",
    "filter": "not port 22", "identity_file": "/etc/synapseids/id_ed25519",
    "known_hosts": "accept-new", "authorized": true }
]
```

### `capture.sources[]` (kind `pcap-over-ip`)

A framed, authenticated TLS stream from a remote sensor (the **SYNPOIP**
protocol — `internal/capture/pcapoverip/PROTOCOL.md`,
`docs/adr/0012-pcap-over-ip-transport.md`). Full worked example and cert-generation
steps: `contrib/config/synapse.pcap-over-ip.json` + `contrib/config/pcap-over-ip.md`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `addr` | string | — | Sensor `host:port`. Required. |
| `token_file` | string (path) | `""` | File holding the bearer token. An inline `token` is **refused** (PROJECT.md §23); `SYNAPSE_POIP_TOKEN` in the environment is the alternative. |
| `server_name` | string | host of `addr` | TLS SNI / certificate name to verify. |
| `ca_file` | string (path) | `""` | PEM bundle verifying the sensor certificate. Empty = system roots. |
| `client_cert_file` / `client_key_file` | string (path) | `""` | Client certificate for mutual TLS. Both or neither. |
| `insecure_tls` | bool | `false` | Skip sensor certificate verification. Logs a loud warning; requires `authorized`. |
| `authorized` | bool | `false` | Operator asserts authority to monitor `addr` (§21) and accepts any `insecure_tls` / token-less choice (§28.18). **Required** for a non-loopback `addr`, for `insecure_tls`, or with no token. |

No auto-reconnect yet: a dropped stream shows `state: "error"` in
`GET /api/v1/captures` until `synapsed` restarts.

```json
"sources": [
  { "name": "hq-sensor", "kind": "pcap-over-ip", "addr": "10.20.0.9:4789",
    "server_name": "hq-sensor.internal", "token_file": "/etc/synapseids/pcap-over-ip.token",
    "ca_file": "/etc/synapseids/hq-sensor-ca.pem", "authorized": true }
]
```

### `capture.collector`

The daemon-side SYNPOIP **listener** for sensors that dial *in*
(`synapse-sensor pcap-over-ip --connect`) — a firewall behind NAT, typically.
Each accepted sensor becomes its own capture source (`kind:
"pcap-over-ip-listen"`, `origin: "collector"`) and appears on
`GET /api/v1/sensors`. It is its own block rather than a `sources[]` kind because
it is a listener that registers a source per peer, not a source that dials one
target. See `docs/adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md`
and `contrib/config/synapse.collector.json`.

**Off by default** — `listen: ""` means no extra listening socket.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | string | `""` | TLS listen `host:port`. Empty **disables** the collector. Env: `SYNAPSE_COLLECTOR_LISTEN`. |
| `cert_file` / `key_file` | string (path) | `""` | The daemon's **server** certificate and key — in this direction the daemon is the TLS server. Both **required** when `listen` is set. `synapse-sensor gen-cert` writes a self-signed pair for testing. |
| `token_file` | string (path) | `""` | File holding the bearer token the collector **presents** in its ClientHello; the sensor verifies it with `crypto/subtle`. An inline `token` is **refused** (PROJECT.md §23); `SYNAPSE_COLLECTOR_TOKEN` is the alternative. |
| `client_ca_file` | string (path) | `""` | PEM bundle. When set, mutual TLS is **required** — and this is the only thing that authenticates the sensor. Strongly recommended for any non-loopback `listen`. |
| `max_sensors` | int | `0` (= 32) | Cap on concurrent **registered** sensors. Past it a connection is refused before any handshake work (PROJECT.md §21). A second, looser bound (`max_sensors + 16`) caps connections still handshaking. |
| `authorized` | bool | `false` | **Required** to enable the collector: the operator asserts they are authorised to ingest traffic from the sensors that will connect (§21, §28.18). |

Because the SYNPOIP roles do not invert with the TCP direction (PROTOCOL.md §6),
the token proves the *daemon* to the sensor and the client certificate proves the
*sensor* to the daemon. A missing or unreadable certificate is logged once and
`synapsed` keeps serving the API without the collector.

```json
"collector": {
  "listen": "0.0.0.0:4789",
  "cert_file": "/etc/synapseids/collector.crt",
  "key_file": "/etc/synapseids/collector.key",
  "token_file": "/etc/synapseids/collector.token",
  "client_ca_file": "/etc/synapseids/sensors-ca.pem",
  "max_sensors": 32,
  "authorized": true
}
```

## `models`

Model selection (PROJECT.md §11–§12). Parsed and validated now; **bundle loading
is Phase 2** — Phase 1 always runs the built-in transparent `heuristic-v1`
classifier as `primary` regardless of these values.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `models.directory` | string (dir path) | `./data/models` | `/var/lib/synapseids/models` | Directory that will be scanned for self-describing model bundles (`model.onnx` + `metadata.json` + `normalizer.json` + …). Env: `SYNAPSE_MODELS_DIR`. |
| `models.primary` | string (model id) | `""` | `""` | Id of the model to treat as `primary`. Empty = let the runtime pick. Newly trained models are never auto-activated (PROJECT.md §21, §28.10); setting this is the explicit activation step once bundle loading exists. |

## `alerts`

The detection policy and the bounded detection store behind
`GET /api/v1/detections` (issue #117, PROJECT.md §17; see
[ADR 0027](../../docs/adr/0027-detection-dedup-and-derived-severity.md)).

A verdict becomes a *detection* when its class is not `normal` **and** either it
clears the confidence threshold for its class, or the ensemble disagreed and
`alert_on_disagreement` is set. Detections are then **deduplicated** on
`(src_ip, dst_ip, class)`, so a 1000-port scan is one detection with
`count: 1000` and **one** `AlertCreated` event — not a thousand of each.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `alerts.enabled` | bool | `true` | `true` | `false` suppresses every detection. The store still runs and still reports counters, so `/api/v1/status` says "alerting is off" rather than looking like a quiet network. |
| `alerts.min_confidence` | float `[0,1]` | `0.70` | `0.7` | Global floor a verdict's `score` must reach. Out of range → the daemon refuses to start. |
| `alerts.per_class_min_confidence` | object `{class: float[0,1]}` | `{"suspicious": 0.85}` | same | Per-class override of the floor. Keys must be `traffic-classes-v1` class names; `normal` is rejected because it never alerts. **A table in the file replaces the default rather than merging into it.** `suspicious` is the supervised catch-all — the class a model reaches for when it is least sure — so it carries a higher bar by default. |
| `alerts.alert_on_disagreement` | bool | `true` | `true` | Raise a detection for a *below-threshold* verdict when the alert-driving models predicted more than one top class. A disagreement is a finding in its own right (PROJECT.md §12); the detection's `reason` says so. |
| `alerts.max_recent` | int `>= 1` | `1000` | `1000` | How many detections are retained. Oldest evicted first and counted as `alerts.evicted` on `/api/v1/status` and on every `/api/v1/detections` response. Detections are **not persisted** — they do not survive a restart. |
| `alerts.dedup_window_sec` | int `>= 1` | `60` | `60` | How long one `(src_ip, dst_ip, class)` detection keeps absorbing further occurrences before a fresh detection is opened. The window is anchored at the **first** occurrence, not slid forward, so sustained activity re-alerts once per window instead of going permanently quiet. The clock is the record's own timestamp (packet time), so a `--speed max` replay dedups exactly as live capture would. |

**There is no `alerts.severity`.** Severity is derived from the traffic class in
code — `normal` never alerts; `suspicious`→`low`, `scan`→`medium`,
`brute_force`/`web_attack`→`high`, `dos_ddos`/`botnet_c2`→`critical` — because a
per-deployment override could produce a class with an empty severity that no
filter can select and no operator can triage. Adding the key is a load error.

### `alerts.suppress` — expected-behaviour rules

A list of rules that turn a correctly-classified verdict into a **non-detection**
because the traffic, while genuinely attack-shaped, is authorised: a DarkWeb
monitor's outbound lookups, a vulnerability scanner, uptime probing, backup
replication, CDN health-checks. Without it the tool is unusable on any host that
does security research — it trains its operator to ignore it.

```jsonc
"alerts": {
  "suppress": [
    // The gateway itself runs authorised recon all day.
    { "src": "203.0.113.7", "class": "scan",
      "note": "edge box is our DarkWeb monitor (ticket OPS-1421)" },
    // A backup target that looks like a one-way flood every night.
    { "dst": "10.20.0.0/24", "dst_port": 873, "class": "dos_ddos",
      "note": "rsync replication to the DR site" }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `src` / `dst` | string | IP or CIDR the flow's initiator / responder must fall within. `""` = any; a bare address is one host. Pin `src` for outbound, `dst` for inbound. |
| `dst_port` | int `[0,65535]` | Responder port. `0` = any. |
| `class` | string | A `traffic-classes-v1` class name. `""` = any alertable class. `normal` is rejected. |
| `note` | string | **Required.** Why this traffic is expected. Echoed in `/api/v1/status` as `alerts.suppress_rules[].note`. |

A matched verdict is **still scored and still stored as a classification** — it
stays in `/api/v1/flows`, `/api/v1/classifications` and the flow log. Only the
detection is skipped: no `/api/v1/detections` row, no `AlertCreated`. Matches are
counted (`alerts.suppressed_by_rule`, and per rule in `alerts.suppress_rules`)
so the decision is auditable and a rule that matches nothing shows `matched: 0`.

Rules are evaluated in file order, first match wins, and the classifier is never
told about them — suppression is a reporting decision, not a modelling one.
Default: no rules.

## `logging`

Structured logs (issue #55, PROJECT.md §24). The daemon logs through `log/slog`;
these two keys pick the encoder and the threshold.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `logging.format` | string enum | `text` | `text` | `text` = human-readable `key=value` lines; `json` = one JSON object per line, for a log pipeline. An unknown value is a load error. Env: `SYNAPSE_LOG_FORMAT`. **Not** hot-reloadable — a running handler cannot swap its encoder; the change takes effect on restart. |
| `logging.level` | string enum | `info` | `info` | `debug`, `info`, `warn` or `error`. `debug` adds per-flow and per-request detail. Env: `SYNAPSE_LOG_LEVEL`. **Hot-reloadable**: `SIGHUP` applies a new level to the running process immediately. |

Every package's logs — including the many that take an injected `log.Printf` —
route through the same handler; a line the code prefixes `WARNING:` / `ERROR:` is
promoted to that level.

## `live`

WebSocket fan-out tuning (PROJECT.md §18, §22).

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `live.websocket_batch` | duration | `100ms` | `100ms` | Flush interval for batched event envelopes to WebSocket clients. A batch also flushes early at 256 events. Lower = snappier UI, more frames; `<= 0` falls back to 100ms. |
| `live.client_queue_size` | int | `5000` | `5000` | Per-subscriber bounded queue depth (event bus and live hub). A client that cannot keep up has events **dropped**, counted as `client_drops` in `/api/v1/status` — the ingest path never blocks on a slow browser. Must be `>= 1`. |

## `retention`

History windows (PROJECT.md §20). Retention policy must be configurable; these
are the knobs. With the `memory` driver the rings are self-bounding by
`storage.max_flows`, so these values are **advisory** until a durable backend
(sqlite/ClickHouse) lands — keep them meaningful now so the durable backend
inherits a sane policy, and see `contrib/cron/synapseids-retention` for an
external backstop.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `retention.flows` | duration | `720h` (30d) | `720h` | How long flow records / feature vectors are kept. |
| `retention.classifications` | duration | `2160h` (90d) | `2160h` | How long classification/verdict history is kept. |

## Validation summary

`synapsed` refuses to start if any of these fail:

- `server.listen` is empty or has no `:`
- `storage.driver` is not `memory` or `sqlite`
- `storage.driver` is `sqlite` (explicitly rejected as unimplemented)
- `capture.flow_idle_timeout <= 0` or `capture.flow_max_lifetime <= 0`
- `capture.max_flows < 1`
- a `capture.sources[]` entry with an empty/duplicate `name`; `snaplen` outside
  `[0, 262144]`; an unknown `kind` (not `nic` / `tcpdump` / `ssh` / `pcap-over-ip`);
  a `nic` / `tcpdump` entry with an empty `interface`; a `nic` entry with an
  unknown `filter` preset; an `ssh` entry with an empty `destination` or
  `interface`, `authorized` not `true`, or a `known_hosts` other than `strict` /
  `accept-new`
- a `pcap-over-ip` source with no `addr`, an inline `token`, only one of
  `client_cert_file` / `client_key_file`, or — without `authorized: true` — a
  non-loopback `addr`, `insecure_tls`, or no `token_file`
- `live.client_queue_size < 1`
- `alerts.min_confidence` outside `[0,1]`; `alerts.max_recent < 1`;
  `alerts.dedup_window_sec < 1`; an `alerts.per_class_min_confidence` key that is
  not a `traffic-classes-v1` class name or is `normal`, or a value outside `[0,1]`
- an `alerts.suppress[]` rule with no matchers (`src`/`dst`/`dst_port`/`class`
  all empty), an unparseable `src`/`dst`, a `dst_port` outside `[0,65535]`, a
  `class` that is not a `traffic-classes-v1` name or is `normal`, or an empty
  `note`
- `logging.format` other than `text` / `json`, or `logging.level` other than
  `debug` / `info` / `warn` / `error`
- any unknown key is present in the file
