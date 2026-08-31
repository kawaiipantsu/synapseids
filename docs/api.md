# HTTP API

`synapsed` serves one versioned REST surface under `/api/v1` and one live
WebSocket channel at `/api/v1/stream` (PROJECT.md §18). All REST responses are
`application/json`, pretty-printed with two-space indent. There is **no auth** in
Phase 1: the listener binds `127.0.0.1:8080` by default, a non-loopback
`server.listen` only logs a warning, and remote access is expected to sit behind
an authenticating reverse proxy (PROJECT.md §21).

Routes come from `Server.Handler()` in `internal/api/api.go`. Field names below
are taken verbatim from the Go structs in `internal/storage/storage.go`,
`internal/inference/inference.go` and `api.go`.

## Conventions

- **`limit` query param** — accepted by the list endpoints. Missing, non-numeric
  or `< 1` → the endpoint default. `> max` → clamped to max.
- **Errors** — `text/plain` body, one line, via `http.Error`. Status codes are
  listed per route.
- **Not under `/api`** — `GET /` (and any unmatched path) serves the static web
  UI: the embedded `web/index.html`, or a directory when `server.web_root` /
  `SYNAPSE_WEB_ROOT` is set.

## Routes

### GET /api/v1/status

Daemon, storage, event-bus, live-channel and replay state. No params. Always
`200`.

```json
{
  "version": "synapsed v0.1.0-dev (unknown)",
  "commit": "unknown",
  "uptime_sec": 1234,
  "listen": "127.0.0.1:8080",
  "loopback": true,
  "storage": {
    "flows": 128,
    "classifications": 128,
    "flows_evicted": 0,
    "classifications_evicted": 0,
    "disagreements": 3,
    "driver": "memory"
  },
  "events": { "published": 542, "dropped": 0, "subscribers": 1 },
  "live": { "clients": 1, "accepted": 3, "frames_out": 210, "client_drops": 0 },
  "models": [
    { "id": "heuristic-v1", "family": "flow-classifier-v1", "role": "primary" }
  ],
  "replay": {
    "running": false,
    "started": "0001-01-01T00:00:00Z",
    "packets": 0,
    "flows": 0
  },
  "feature_schema": "flow-features-v1",
  "output_schema": "traffic-classes-v1"
}
```

`live.client_drops` is the count of WebSocket clients dropped for being too slow
(see [below](#backpressure)). When a replay is running, `replay` also carries
`id`, `source`, `speed` and (on failure) `last_error`.

`storage.disagreements` is the cumulative number of stored classifications whose
ensemble raised `result.disagreement` — every disagreeing verdict ever recorded,
not just those still in the ring (PROJECT.md §12, §24).

### GET /api/v1/flows

Recent stored flows, newest first. Query: `limit` (default `100`, max `2000`).
`200` → JSON array of `FlowRecord`:

```json
[
  {
    "id": 42,
    "proto": "TCP",
    "initiator_ip": "192.168.1.50",
    "initiator_port": 49712,
    "responder_ip": "93.184.216.34",
    "responder_port": 80,
    "first_seen": "2026-08-31T12:00:00Z",
    "last_seen": "2026-08-31T12:00:00.11Z",
    "duration_sec": 0.11,
    "fwd_packets": 6,
    "bwd_packets": 3,
    "fwd_bytes": 468,
    "bwd_bytes": 1310,
    "close_reason": "fin_rst",
    "snapshot_index": 0,
    "features": {
      "flow_id": 42,
      "schema": "flow-features-v1",
      "values": [0.11, 6, 3, 468, 1310, "…48 floats total…"]
    }
  }
]
```

`close_reason` is one of `snapshot`, `fin_rst`, `idle`, `max_lifetime`,
`capture_end`, `evicted` (see [architecture.md](architecture.md#flow-lifecycle)).
`features.values` is the frozen 48-element `flow-features-v1` vector
([features-v1.md](features-v1.md)).

### GET /api/v1/flows/{id}

One flow by numeric ID — the most recent stored version (a later snapshot or the
close record supersedes an earlier snapshot).

- `200` → a single `FlowRecord` (shape as above)
- `400` `bad flow id` — `{id}` is not a uint64
- `404` `flow not found` — no such ID in the ring (it may have been evicted)

### GET /api/v1/classifications

Recent ensemble verdicts, newest first — this is the rolling-log feed. `200` →
JSON array of `Classification`:

```json
[
  {
    "flow_id": 42,
    "ts": "2026-08-31T12:00:00.11Z",
    "sensor": "local",
    "proto": "TCP",
    "initiator_ip": "192.168.1.50",
    "initiator_port": 49712,
    "responder_ip": "93.184.216.34",
    "responder_port": 80,
    "result": {
      "flow_id": 42,
      "class": "normal",
      "class_id": 0,
      "score": 0.981,
      "disagreement": false,
      "models": [
        {
          "model_id": "heuristic-v1",
          "role": "primary",
          "class": "normal",
          "class_id": 0,
          "score": 0.981,
          "scores": [0.981, 0.004, 0.003, 0.004, 0.003, 0.002, 0.003]
        }
      ]
    }
  }
]
```

`result.class` / `class_id` / `score` are the verdict-driving model's top class —
the first `primary`-role model, or, absent any primary, the first
non-`experimental` model. `result.models[]` holds **every** model's full output —
`scores` is the 7-element `traffic-classes-v1` distribution (PROJECT.md §12: store
per-model outputs, not just the combined decision). `disagreement` is `true` when
the alert-driving models — every role **except `experimental` and `anomaly`** —
predict more than one distinct top class; the pipeline also emits a
`ModelDisagreementDetected` event in that case, carrying the same per-model
breakdown.

#### Query parameters

All optional and combinable. With none of them the response is the newest `limit`
verdicts unchanged. When any filter is present the endpoint scans the most recent
5000 stored verdicts, applies the predicates, and returns the newest `limit`
matches (the in-memory store has no indexes; a SQLite backend will push these
down).

| Param | Meaning |
|---|---|
| `limit` | Max rows returned. Default `100`, clamped to `5000`. Missing / non-numeric / `< 1` → default. |
| `disagreement` | `disagreement=true` returns only rows where `result.disagreement` is set. Any other value is ignored. |
| `class` | `class=<name>` returns only rows whose `result.class` equals `<name>`. `<name>` must be a `traffic-classes-v1` class (`normal`, `scan`, `dos_ddos`, `brute_force`, `botnet_c2`, `web_attack`, `suspicious`); anything else → `400 unknown class name`. |
| `model` | `model=<id>` returns only rows where some `result.models[].model_id` equals `<id>` (matches shadow/experimental models too, since their output is still recorded). |
| `min_confidence` | `min_confidence=<n>` returns only rows where `result.score >= n`. `n` in `0..1` is a fraction; `n > 1` is read as a `0..100` percentage (so `0.9` and `90` are equivalent, matching the web UI's slider). Negative or non-numeric → `400 bad min_confidence`. |

Examples:

```text
GET /api/v1/classifications?disagreement=true
GET /api/v1/classifications?class=scan&min_confidence=90
GET /api/v1/classifications?model=global-v1&limit=500
```

### GET /api/v1/models

Loaded classifiers. No params. `200`:

```json
[{ "id": "heuristic-v1", "family": "flow-classifier-v1", "role": "primary" }]
```

`role` is one of `primary`, `location`, `global`, `experimental`, `anomaly`.

### GET /api/v1/schemas/features

The frozen `flow-features-v1` document, served verbatim from the embedded
`schemas/features/flow-features-v1.json`. `200`, `application/json`.

### GET /api/v1/schemas/classes

The frozen `traffic-classes-v1` document, verbatim from
`schemas/outputs/traffic-classes-v1.json`. `200`, `application/json`.

### GET /api/v1/replay

Current replay state. `200` → the `replay` object from `/status`. `503`
`replay not available` if the server was built without a `ReplayController`
(`synapsed` always wires one; this only happens in embedded/test use).

### POST /api/v1/replay

Start a PCAP replay through the normal pipeline. Body (JSON, capped at 64 KiB):

```json
{ "path": "/abs/path/to/capture.pcap", "speed": "2" }
```

`speed` accepts `0.5`, `1`, `1x`, `2`, `10`, `max`, `0` (= max), or any positive
float; empty = `1`.

- `202` → `{ "id": "replay-1725105600000000000", "speed": "2x" }`
- `400` `bad request body` — unparseable JSON
- `400` `path is required` — empty `path`
- `400` `path does not name a readable file` — `stat` failed or it is a directory
- `400` `capture: invalid replay speed "…"` — bad `speed`
- `409` — `Start` refused: a replay is already running, or the file is not a
  classic pcap (pcapng, truncated header, unsupported link type)
- `503` `replay not available` — no controller

The daemon runs **one replay at a time**; stop the current one first. Replayed
traffic reaches the UI through the exact same flow/feature/inference path as live
traffic (PROJECT.md §6).

### POST /api/v1/replay/stop

Cancel the running replay. No body.

- `200` → `{ "stopped": "ok" }` (also when nothing was running — it is a no-op)
- `409` — `Stop` returned an error
- `503` `replay not available` — no controller

## WebSocket: GET /api/v1/stream

The single live channel (PROJECT.md §18). Server-to-client only in Phase 1.

### Handshake (RFC 6455)

Standard upgrade. The request must carry `Connection: Upgrade`,
`Upgrade: websocket`, `Sec-WebSocket-Version: 13` and a non-empty
`Sec-WebSocket-Key`. The server replies `101 Switching Protocols` with
`Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
A non-handshake request to this path gets `400 expected a websocket upgrade`.
Implemented from scratch in `internal/wshub` — no third-party dependency.

### Frames

Each frame is an **unmasked text frame whose payload is a JSON array of
event envelopes** (`event-envelope-v1`):

```json
[
  { "type": "FlowClosed",            "ts": "2026-08-31T12:00:00.11Z",  "seq": 5411, "data": { "…FlowRecord…" } },
  { "type": "FeaturesGenerated",     "ts": "2026-08-31T12:00:00.11Z",  "seq": 5412, "data": { "…Vector…" } },
  { "type": "ClassificationCreated", "ts": "2026-08-31T12:00:00.111Z", "seq": 5413, "data": { "…Classification…" } }
]
```

`data` is the same struct the matching REST endpoint returns. Event types are
listed in [architecture.md](architecture.md#event-bus-contract).

### Batching

The server's `pump` goroutine holds one bus subscription and flushes the
accumulated envelopes as one array either every `live.websocket_batch`
(config, default `100ms`) or immediately once a batch reaches 256 envelopes.
Empty intervals send nothing.

### Backpressure

Each client has a bounded send queue of `live.client_queue_size` payloads
(config, default `5000`). If that queue is full when a batch is broadcast, the
**client is dropped** — its connection is closed and the hub's drop counter
increments, visible at `/api/v1/status` as `live.client_drops` (PROJECT.md §22).
Reconnecting is the client's responsibility (the built-in page retries after
1.5s). Separately, if the pump's own bus subscription overflows (the pump itself
falling behind), those misses are counted in `events.dropped`.

Inbound frames from the client are drained and discarded (so a disconnect is
noticed promptly); `PING` is answered with `PONG`; an inbound frame larger than
1 MiB drops the connection; the read deadline is 120s.

## Raw packets are never sent to clients

The live channel only ever carries event envelopes whose `data` is a flow
record, a feature vector, a classification, or a replay-progress object —
**never packet bytes** (PROJECT.md §18: "Do not send every raw packet to every
browser"). `packet.Packet` is consumed inside the pipeline goroutine and has no
serialization path to the API; the decoder discards payload bytes entirely
(`packet.go` keeps only lengths). Aggregation and server-side filtering happen
before anything reaches a socket.

## Clients

Two clients consume this API in Phase 1, and only these are supported:

- **`synapse`** (`cmd/synapse`) — the admin CLI. Holds no logic of its own
  (PROJECT.md §5.2); every verb is an HTTP call: `status`, `models`,
  `flows [--limit N]`, `classifications [--limit N]` (rendered as a rolling-log
  table), `replay <file.pcap> [--speed S]`, `replay-stop`. Base URL from
  `--server` or `SYNAPSE_SERVER` (default `http://127.0.0.1:8080`).
- **`web/index.html`** — the embedded page served at `/`. Polls
  `/api/v1/status` every second, opens `/api/v1/stream`, renders
  `ClassificationCreated` events into the rolling log with client-side class and
  min-confidence filters, and drives replay via `POST /api/v1/replay[/stop]`.

---

⟦THUGS⟧ (c) 2026
