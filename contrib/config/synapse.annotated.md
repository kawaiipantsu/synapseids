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

## `models`

Model selection (PROJECT.md §11–§12). Parsed and validated now; **bundle loading
is Phase 2** — Phase 1 always runs the built-in transparent `heuristic-v1`
classifier as `primary` regardless of these values.

| Key | Type | Default | This file | Meaning |
|---|---|---|---|---|
| `models.directory` | string (dir path) | `./data/models` | `/var/lib/synapseids/models` | Directory that will be scanned for self-describing model bundles (`model.onnx` + `metadata.json` + `normalizer.json` + …). Env: `SYNAPSE_MODELS_DIR`. |
| `models.primary` | string (model id) | `""` | `""` | Id of the model to treat as `primary`. Empty = let the runtime pick. Newly trained models are never auto-activated (PROJECT.md §21, §28.10); setting this is the explicit activation step once bundle loading exists. |

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
- `live.client_queue_size < 1`
- any unknown key is present in the file
