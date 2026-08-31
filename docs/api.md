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
  "live": {
    "ws_clients": 1, "ws_client_drops": 0, "ws_frames_batched": 87,
    "clients": 1, "accepted": 3, "frames_out": 210, "client_drops": 0
  },
  "flow": {
    "active": 128,
    "started": 4210,
    "closed": 4082,
    "snapshots": 17,
    "evicted": 0,
    "max": 200000
  },
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

`live` reports the WebSocket hub counters (PROJECT.md §24). The canonical keys
are `ws_clients` (connections currently registered), `ws_client_drops` (clients
dropped for being too slow — see [below](#backpressure)) and `ws_frames_batched`
(batched frames produced by the pump, one per flush, independent of the
client count). `clients`, `accepted`, `frames_out` and `client_drops` are kept
as pre-existing aliases (`frames_out` counts per-client frame writes). When a
replay is running, `replay` also carries `id`, `source`, `speed` and (on
failure) `last_error`.

`flow` is the running pipeline's flow table (`internal/api.FlowStats`): `active`
flows held right now, and lifetime `started` / `closed` / `snapshots` / `evicted`
counters, alongside the configured cap `max` (`capture.max_flows`, default
`200000`; override with `SYNAPSE_MAX_FLOWS`). A rising `evicted` means the table
is at capacity and shedding its least-recently-seen flows — raise `max` if that
is not expected (PROJECT.md §22, §24). The counters come from the replay
pipeline; between replays they hold the last run's final snapshot (`active` back
at `0`), and are all `0` before the first replay. The pipeline also writes a
throttled warning to the daemon log on the first eviction of a run and every
1000th after it.

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

### GET /api/v1/hosts

Observed host profiles (PROJECT.md §19.5, issue #39). Newest-active first by
default. Profiles are maintained incrementally by `internal/insight` from the
classified flow stream — see `docs/adr/0016-host-and-time-aggregation-for-investigation.md`.

| Param | Meaning |
|---|---|
| `limit` | Max profiles. Default `100`, clamped to `2000`. |
| `q` | Case-sensitive substring match on the address, e.g. `q=10.10.10.`. |
| `sort` | `last_seen` (default), `flows` or `bytes`. Anything else → `400 bad sort`. |

```json
[
  {
    "ip": "10.10.10.22",
    "first_seen": "2026-08-31T08:41:11.052640Z",
    "last_seen": "2026-08-31T08:43:45.874377Z",
    "flows": 1124,
    "flows_initiated": 864,
    "flows_responded": 260,
    "packets_in": 33880,
    "packets_out": 34202,
    "bytes_in": 15914440,
    "bytes_out": 10223125,
    "protocols": [{ "proto": "TCP", "flows": 923 }, { "proto": "UDP", "flows": 197 }],
    "top_ports": [{ "port": 3306, "flows": 400 }, { "port": 80, "flows": 248 }],
    "classifications": 1176,
    "classes": [
      { "class": "normal", "class_id": 0, "count": 868 },
      { "class": "brute_force", "class_id": 3, "count": 304 }
    ],
    "disagreements": 0,
    "baseline_available": false,
    "anomaly_available": false
  }
]
```

The list view is shallow: `top_ports` is capped at 5 and `top_peers` /
`recent_flows` are omitted. Fetch one host for the full lists.

`baseline_available` and `anomaly_available` are **always `false`**. Behavioural
baseline and anomaly trend (§19.5) need the Phase 7 anomaly work; the fields exist
so a client can label the gap rather than plot an invented number.

Counting rules worth knowing:

- `flows`, `packets_*` and `bytes_*` come only from **terminal** flow records. A
  long flow's periodic snapshot records carry cumulative counters, so including
  them would double-count.
- `classifications`, `classes[]` and `disagreements` count **every** verdict,
  snapshot verdicts included, which keeps a host's mix consistent with
  `/api/v1/classifications`.
- A flow updates **both** endpoints, so summing `flows` across hosts roughly
  doubles the flow count.
- `top_ports` is the conversation's **service** port (the responder side): for an
  initiator "a port I connected to", for a responder "a port I served".
- `top_ports` / `top_peers` are exact for heavy hitters but **approximate for long
  tails**: each host tracks at most 128 distinct keys and discards the
  lowest-count half on overflow (a 60000-port sweep evicts its own tail). The
  scalar totals are never pruned. Discards are counted in `status.insight.keys_pruned`.

Resource bounds are reported on `GET /api/v1/status` under `insight`:

```json
"insight": {
  "hosts": 84, "host_cap": 2048, "hosts_evicted": 0,
  "key_cap": 128, "keys_pruned": 0,
  "observed": 1176, "dropped": 0, "queue_size": 8192, "timeline_late": 0
}
```

At most 2048 hosts are tracked; on overflow the least-recently-active quarter is
dropped and counted in `hosts_evicted`. `dropped` counts observations the
aggregator's bounded ingest queue could not accept — the packet path never blocks
on it (PROJECT.md §21, §22).

### GET /api/v1/hosts/{ip}

One profile with its detail lists: `top_ports` up to 16, `top_peers` up to 16, and
`recent_flows` — up to 16 compact references (`flow_id`, `ts`, `proto`, `peer`,
`port`, `bytes`, `class`). Resolve a reference with `GET /api/v1/flows/{id}`; the
profile deliberately does not duplicate the 48-value feature vector.

`{ip}` must parse as an IPv4 or IPv6 literal (`net/netip`) or the response is
`400 bad host address`. The address is canonicalised, so `::ffff:10.0.0.1` and
`10.0.0.1` address the same profile. An unobserved but well-formed address is
`404 host not found`.

### GET /api/v1/hosts/{ip}/flows

That host's flow records, newest first, where it is either endpoint. Accepts the
**same** filter parameters as `/api/v1/classifications` (`class`, `model`,
`min_confidence`, `disagreement`) plus `from` / `to`, so there is one filter
dialect to learn. `limit` defaults to `100`, clamped to `2000`.

The classification predicates are applied by joining each flow to its verdict from
the recent classification window; a flow whose verdict has already aged out of the
ring is therefore not returned when such a filter is set.

### GET /api/v1/hosts/{ip}/classifications

That host's verdicts, newest first, with the same parameters as above.

| Param | Meaning |
|---|---|
| `from`, `to` | Inclusive RFC3339 bounds on the record timestamp. A malformed value → `400 bad from` / `400 bad to`; `to` before `from` → `400 bad range`. |

```text
GET /api/v1/hosts/10.10.10.21/classifications?class=brute_force&limit=50
GET /api/v1/hosts/10.10.10.22/flows?from=2026-08-31T08:42:00Z&to=2026-08-31T08:43:00Z
```

### GET /api/v1/timeline

Classification volume bucketed over time (PROJECT.md §19.6, issue #41).

| Param | Meaning |
|---|---|
| `bucket` | `1s` (default), `10s` or `1m` (`60s` is accepted as an alias). Anything else → `400 bad bucket`. |
| `from`, `to` | Inclusive RFC3339 bounds. Same validation as above. |
| `class` | Restrict to one `traffic-classes-v1` class; unknown → `400 unknown class name`. |
| `host` | Restrict to conversations involving this address; must be an IP literal → `400` otherwise. |

```json
{
  "bucket_sec": 1,
  "buckets": [
    { "ts": "2026-08-31T08:41:11Z", "total": 6, "by_class": { "normal": 4, "brute_force": 2 }, "disagreements": 0 },
    { "ts": "2026-08-31T08:41:12Z", "total": 3, "by_class": { "normal": 2, "brute_force": 1 }, "disagreements": 0 }
  ],
  "anomaly_available": false
}
```

The series is **dense**: a quiet interval is an explicit zero bucket, not a missing
`ts`, so a chart does not have to interpolate. With no `from`, it starts at the
oldest non-empty bucket still retained rather than at the start of the ring's
window.

Retention is per resolution: `1s` keeps 900 buckets (15 min), `10s` keeps 720
(2 h), `1m` keeps 1440 (24 h). A verdict older than a ring's whole window cannot be
placed and is counted in `status.insight.timeline_late`.

An unscoped query is answered from the incrementally maintained ring. A `class=` or
`host=` scoped query is bucketed on demand from the newest 5000 stored
classifications instead — a ring per host would be unbounded.

`anomaly_available` is **always `false`**: the anomaly-score series (§19.6) needs
the Phase 7 anomaly model, and the API reports its absence rather than returning a
fabricated zero series.

### GET /api/v1/models

The model registry view plus the classifiers currently loaded in the inference
runtime. No params. `200`:

```json
{
  "models": [
    {
      "model_id": "flow-classifier-v1-cph-0002",
      "name": "Copenhagen classifier",
      "version": "0.2.0",
      "family": "flow-classifier-v1",
      "feature_schema": "flow-features-v1",
      "input_size": 48,
      "output_schema": "traffic-classes-v1",
      "output_size": 7,
      "architecture": { "input_size": 48, "output_size": 7, "hidden": [ /* ... */ ] },
      "training_dataset_ids": ["cicids2017-v3"],
      "metrics": { "accuracy": 0.985 },
      "parameter_count": 5383,
      "artifact_bytes": 220114,
      "content_hash": "sha256:7aa0cf…",
      "created_at": "2026-08-31T12:00:00Z",
      "trainer_version": "synapse-trainer 0.2.0",
      "derived_from": "flow-classifier-v1-global-0001",
      "status": "active",
      "registered_at": "2026-08-31T12:05:00Z",
      "activated_at": "2026-08-31T12:07:11Z",
      "dir": "./data/models/cph-0002",
      "runtime": { "loaded": true, "role": "primary" }
    }
  ],
  "runtime": [
    { "id": "flow-classifier-v1-cph-0002", "family": "flow-classifier-v1", "role": "primary", "registered": true }
  ]
}
```

`models` is every registered bundle, newest registration first; `status` is one
of `registered`, `active`, `deactivated`. `runtime` is what is actually scoring
flows right now — the heuristic (`id: heuristic-v1`, `registered: false`) until a
model is activated, then the single activated model. `runtime` inside each
`models` entry says whether that entry is the one loaded and in what role.
Activation never survives a daemon restart: a `status: active` entry is
reconciled to `deactivated` on startup and must be re-activated explicitly
(PROJECT.md §28.10).

When the daemon runs without a registry (embedded/test), `models` is `[]` and
only `runtime` is populated.

### GET /api/v1/models/{id}

One registered model with its lineage. `200`:

```json
{
  "entry":   { /* one models[] element, incl. "runtime" */ },
  "lineage": [ /* root → id chain of entries via derived_from */ ],
  "children": [ /* entries whose derived_from == id, newest first */ ]
}
```

`404` if `id` is not a registered model.

### GET /api/v1/models/{id}/lineage

The lineage of one model plus the whole registry forest for context. `200`:

```json
{
  "lineage":  [ /* root → id chain */ ],
  "children": [ /* direct children */ ],
  "tree":     [ { "entry": { /* … */ }, "children": [ { "entry": …, "children": [] } ] } ]
}
```

`tree` is the forest of every registered model: one node per root (a model with
no `derived_from`, or one whose parent is not registered), children nested
recursively, each level newest registration first. `404` if `id` is unknown.

### POST /api/v1/models/{id}/activate

Explicitly make a registered model the live primary classifier (PROJECT.md §28.10,
§29 steps 16–18). No body. The daemon re-loads the bundle from disk, re-runs the
validation gate, compiles the ONNX graph, atomically swaps it into the inference
runtime, records the status change and writes a `ModelActivated` audit line. Any
previously active model is demoted to `deactivated`. `200` returns
`{ "entry": { /* … */ } }` with `status: active` and `runtime.loaded: true`.

- `404` — `id` is not a registered model.
- `409` — the bundle no longer loads, no longer passes the gate, or its
  `model.onnx` cannot be compiled by the Go inference runtime. The live runtime
  is left untouched.
- `503` — the daemon is running without a registry.

State-changing and unauthenticated for now — same posture as `POST
/api/v1/replay`, where loopback-by-default is the only control. RBAC is tracked
as issue #58.

### POST /api/v1/models/{id}/deactivate

Turn a model off and restore the heuristic as the live primary. No body. Records
the status change and writes a `ModelDeactivated` audit line. `200` returns
`{ "entry": { /* … */ } }` with `status: deactivated`.

- `404` — `id` is not a registered model.
- `503` — the daemon is running without a registry.

### GET /api/v1/datasets

Every dataset version's manifest, newest `created_at` first (PROJECT.md §14,
§19.10). No params. Always `200` — an empty `datasets` array when nothing has
been cut, never `503`.

```json
{
  "datasets": [
    {
      "id": "thugs/lab-attacks-2026-08",
      "version": "v1",
      "name": "Lab attacks, August 2026",
      "description": "portscan.pcap + a real nmap scan and MySQL brute-force run.",
      "location": "thugs-lab",
      "tags": ["lab", "phase4", "replay"],
      "created_at": "2026-08-31T11:52:39Z",
      "source_capture_ids": ["replay:testdata/pcap/portscan.pcap"],
      "time_range": { "from": "2026-08-31T08:41:11Z", "to": "2026-08-31T13:00:00Z" },
      "feature_schema": "flow-features-v1",
      "output_schema": "traffic-classes-v1",
      "flow_count": 1148,
      "label_counts": { "normal": 817, "brute_force": 304, "scan": 24, "web_attack": 2, "dos_ddos": 1 },
      "labeling_source": "model_prediction:heuristic-v1",
      "parent_datasets": [],
      "content_hash": "sha256:7bb0e46490e50e8c03fbbd68c19805e914c547ada62419e75a981af6ecf2ddff",
      "selection": {},
      "warnings": ["2 of 7 traffic-classes-v1 classes have no rows (botnet_c2, suspicious) — the model cannot learn them"],
      "csv_file": "dataset.csv",
      "csv_bytes": 426379,
      "feature_count": 48,
      "columns": ["flow_duration", "…", "snapshot_index", "label"],
      "dir": "/var/lib/synapseids/datasets/thugs/lab-attacks-2026-08/v1"
    }
  ],
  "columns": ["flow_duration", "…", "snapshot_index", "label"],
  "label_column": "label",
  "min_rows": 20
}
```

`labeling_source` is not decoration. Phase 4 has no human review loop
(issue #42), so every dataset built today is labelled by the daemon's **own
model predictions** and records `model_prediction:<sorted model ids>`. Nothing in
`internal/dataset` can write `human_review`; that value becomes possible only
once reviewed labels exist. Do not present these labels as ground truth.

`content_hash` is `sha256` over a domain separator, the two schema names and the
exact `dataset.csv` bytes. Two datasets built from the same rows and labels hash
identically regardless of id, version, name or creation time.

#### Addressing one dataset: the `{ref}` segment

A dataset id may contain one `/` (PROJECT.md §14 writes
`thugs/lab-attacks-2026-08`), so a single version is addressed by **one
url-escaped path segment** holding `<id>@<version>`:

```text
GET /api/v1/datasets/thugs%2Flab-attacks-2026-08%40v1
```

`net/http`'s `ServeMux` matches wildcards against the escaped path and unescapes
the segment for the handler, so `%2F` stays inside one segment and arrives
intact. **Deployment caveat:** a reverse proxy that normalises `%2F` into `/`
before forwarding will break these two routes (nginx needs no change; some
configurations of others do). That only arises off loopback, which these routes
are not ready for anyway — see issue #58.

A malformed ref → `400 … reference "…" must be "<id>@<version>"`.

### GET /api/v1/datasets/{ref}

One manifest plus every version of the same id, newest first.

```json
{ "dataset": { "…": "as above" }, "versions": [ { "…": "manifest" } ] }
```

- `400` — the ref is not `<id>@<version>`.
- `404` — unknown dataset version.
- `503` — the daemon is running without a dataset manager.

### POST /api/v1/datasets

Materialise a selection over the stored classifications into a new, immutable
dataset version on disk. Body is JSON, unknown fields rejected, 64 KiB cap.

```json
{
  "id": "thugs/lab-attacks-2026-08",
  "version": "v1",
  "name": "Lab attacks, August 2026",
  "description": "replayed lab corpus",
  "location": "thugs-lab",
  "tags": ["lab", "phase4"],
  "source_capture_ids": ["replay:/pcaps/nmap_scan.pcap"],
  "derive_from": "thugs/lab-attacks-2026-08@v1",
  "selection": {
    "from": "2026-08-31T00:00:00Z",
    "to": "2026-08-31T23:59:59Z",
    "class": "scan",
    "model": "heuristic-v1",
    "proto": "tcp",
    "initiator_ip": "10.0.0.5",
    "responder_ip": "10.0.0.9",
    "min_confidence": 0.8,
    "disagreement": false,
    "limit": 5000,
    "scan": 200000
  }
}
```

| Field | Meaning |
|---|---|
| `id` | Required. One or two `/`-separated lowercase slug segments of `[a-z0-9._-]`, each 1–64 chars, each starting and ending with a letter or digit. No `@`, no `..`, no traversal. |
| `version` | Optional. Same slug rules, no `/`. Omitted → `v1`, or `v<max+1>` if versions of this id already exist. |
| `name` | Optional; defaults to `id`. |
| `derive_from` | Optional `<id>@<version>`. Records that dataset (and its own ancestors) in `parent_datasets`. The rows still come from a fresh selection over the flow store — dataset-to-dataset merge with weighting is the training recipe, not this route. |
| `selection` | Optional; the zero value means "everything the store holds". |

**Selection fields.** `class`, `model`, `min_confidence` and `disagreement` mean
exactly what they mean on `GET /api/v1/classifications`, including
`min_confidence > 1` being read as a `0..100` percentage — so an operator can
preview a cut in the Flow Log and then build it with the same words. `from`/`to`
are inclusive RFC3339 bounds on the classification timestamp. `proto` matches
`TCP`/`UDP`/`ICMP`/`ICMPv6`/`IP` case-insensitively. `initiator_ip`/`responder_ip`
match the stored tuple exactly. `limit` caps the result at the newest N matching
flows. `scan` is how many recent verdicts to walk (default 200 000, capped at
2 000 000).

A flow contributes exactly **one row**; where it was classified more than once
(a long flow's periodic snapshots) the newest verdict wins. Rows are sorted by
flow id, which is what makes `content_hash` reproducible.

Responses:

- `201` — `{"dataset": {…manifest…}}`.
- `400` — bad body, bad `id`/`version`, bad `derive_from` ref, unknown `class` or
  `proto`, unparseable `from`/`to`, inverted time range, `min_confidence` outside
  `0..1`. The error text is the daemon's, verbatim.
- `404` — `derive_from` names a dataset that does not exist.
- `409` — `(id, version)` already exists. **A version is immutable**; create a new
  one and let `parent_datasets` record the lineage.
- `422` — the selection produced nothing a trainer could use: no rows, exactly
  one class, or fewer than `min_rows` (20) rows. The message says which.
- `503` — the daemon is running without a dataset manager.

A dataset that *is* built may still carry `warnings`: class imbalance above 90 %
for one class, classes with no rows, exact duplicate rows, verdicts whose flow
record had already been evicted from the bounded store, and non-finite feature
values replaced by the schema's `default_missing`.

### GET /api/v1/datasets/{ref}/download

The `dataset.csv` itself, so a trainer host can fetch a dataset over the API
instead of needing the daemon's filesystem.

```text
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="thugs_lab-attacks-2026-08-v1.csv"
X-Synapse-Dataset-Hash: sha256:7bb0e464…
X-Synapse-Feature-Schema: flow-features-v1
X-Content-Type-Options: nosniff
```

The header row is the 48 `flow-features-v1` column names in frozen schema order
followed by `label`; every data row is 48 floats and a `traffic-classes-v1` class
name. This is exactly what `trainer/synapse_trainer/dataset.py` `load_csv` reads,
with no adaptation. `400` / `404` / `503` as above.

### DELETE /api/v1/datasets/{ref}

Remove a dataset version. Immutability protects a version's contents, not its
existence — an operator who cut from the wrong window must be able to undo it.
Audited. `200 {"deleted": "<id>@<version>"}`, or `400` / `404` / `503` as above.

Any model trained on the deleted dataset keeps the `content_hash` in its
metadata, but the rows themselves are gone unless they are rebuilt.

### Dataset routes are state-changing and unauthenticated

`POST` and `DELETE /api/v1/datasets` inherit the repo's loopback-by-default
posture (PROJECT.md §21) and carry `TODO(#58): gate behind auth/RBAC`, the same
as `POST /api/v1/replay`, `POST /api/v1/captures` and model activation. Create,
derive and delete are written to `models.directory/audit.log` with
`subject_type: "dataset"`. There is deliberately no `DatasetCreated` event on the
live bus: `event-envelope-v1`'s type enum is frozen and has no `Dataset*` member
(see [ADR 0015](adr/0015-versioned-datasets-on-disk.md)).

### GET /api/v1/schemas/features

The frozen `flow-features-v1` document, served verbatim from the embedded
`schemas/features/flow-features-v1.json`. `200`, `application/json`.

### GET /api/v1/schemas/classes

The frozen `traffic-classes-v1` document, verbatim from
`schemas/outputs/traffic-classes-v1.json`. `200`, `application/json`.

### GET /api/v1/captures

Live capture sources managed by the `capture.Manager` (PROJECT.md §19.14). No
params. Always `200` — an empty array `[]` when no live capture is configured
(the daemon is replay-only), never `503`.

```json
[
  {
    "name": "lo",
    "kind": "nic",
    "state": "running",
    "packets": 6074,
    "decoded": 6074,
    "decode_errors": 0,
    "bytes": 4177656,
    "drops": 6,
    "pps": 3212.0,
    "bps": 1262408.6,
    "last_packet": "2026-08-31T09:15:25.737730002Z",
    "filter": "(all)",
    "error": "",
    "connection_latency_ms": 0,
    "origin": "config"
  }
]
```

- `kind` — `nic` (a local `AF_PACKET` interface), `tcpdump` (a local
  `tcpdump -U -w -` subprocess), `ssh` (an authorized remote
  `ssh <host> tcpdump -U -w -`), `pcap-over-ip` (a framed, authenticated TLS
  stream from a remote sensor **the daemon dialled**; see the config
  `capture.sources` entry and `internal/capture/pcapoverip/PROTOCOL.md`), or
  `pcap-over-ip-listen` (a sensor that **dialled the daemon** and was accepted by
  the collector — one row per connected peer, see `GET /api/v1/sensors`).
- `state` — `running`, `error` (see `error` for the message; other sources keep
  running), or `stopped` (the source was exhausted, the remote sensor sent a
  goodbye / end-of-capture, or the source was removed). A `tcpdump` / `ssh`
  source whose subprocess exits non-zero goes to `error` with
  `"<tool>: exit <code>: <stderr tail>"`. Nothing reconnects or restarts on its
  own yet — a dropped stream stays `error` / `stopped` until the daemon
  restarts.
- `pps` / `bps` — rolling packets- and bytes-per-second, sampled by the Manager
  once a second off the packet path.
- `drops` — kernel packet drops (`AF_PACKET` `PACKET_STATISTICS` `tp_drops`),
  accumulated. A non-zero, growing value means the sensor cannot keep up
  (PROJECT.md §22, §24). `tcpdump` / `ssh` sources leave it 0 (tcpdump reports
  drops only on stderr at exit); for `pcap-over-ip` it carries the
  sensor-reported drop counter from keepalive frames, or 0.
- `filter` — the source's current capture filter; `(all)` = everything. For
  `nic` it is a built-in cBPF preset name (`ip`, `ip6`, `ip-any`, `not-arp`);
  for `tcpdump` / `ssh` it is the raw tcpdump filter expression; for
  `pcap-over-ip` it is the filter string the sensor advertised in the handshake
  (blank until connected).
- `connection_latency_ms` — 0 for a local NIC or a local tcpdump; for
  `pcap-over-ip` the measured TLS dial + handshake time; the SSH dial time for
  an `ssh` source is a follow-up (currently 0).
- `origin` — `config` (opened at startup from `capture.sources[]`), `api` (added
  at runtime through `POST /api/v1/captures`) or `collector` (a sensor that
  dialled in — registered and removed by the collector, not by an operator).
  `config` and `api` sources are removable through `DELETE`; a `collector` row
  goes away when its sensor disconnects.

### POST /api/v1/captures

Start a capture source at runtime, without restarting the daemon (PROJECT.md
§19.14, issue #32). The body is exactly **one `capture.sources[]` entry** — the
same `config.CaptureSource` object the config file uses — and is validated by
the same `config.ValidateCaptureSource` the file loader runs, so a request that
would be rejected in the file is rejected here with the same sentence. Unknown
JSON fields are rejected; the body is capped at 64 KiB.

> **This is a powerful, currently unauthenticated endpoint.** It opens a raw
> socket, spawns a `tcpdump` subprocess, dials a remote sensor over TLS, or
> starts an SSH session. It relies on the daemon binding loopback by default
> (PROJECT.md §21). Do not expose the management API off loopback before issue
> **#58** (auth/RBAC) lands. `authorized: true` is an operator assertion
> (§28.18), not an access control.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/captures \
  -H 'content-type: application/json' \
  -d '{"name":"lo","kind":"tcpdump","interface":"lo","filter":"ip"}'
```

Per-kind bodies:

```jsonc
// nic — a local AF_PACKET interface (needs CAP_NET_RAW / CAP_NET_ADMIN)
{"name":"wan0","kind":"nic","interface":"eth0","promiscuous":true,
 "snaplen":65535,"filter":"ip-any"}          // filter: "" | ip | ip6 | ip-any | not-arp

// tcpdump — a local `tcpdump -U --immediate-mode -w -` subprocess
{"name":"span","kind":"tcpdump","interface":"eth0","filter":"tcp port 80 or udp",
 "snaplen":65535,"binary":"","extra_args":[]}   // filter: a raw tcpdump expression

// ssh — an authorized remote tcpdump; requires "authorized": true (§28.18)
{"name":"edge","kind":"ssh","destination":"sensor@10.0.0.9","interface":"eth1",
 "filter":"not port 22","port":22,"identity_file":"/keys/id","remote_binary":"tcpdump",
 "known_hosts":"strict","authorized":true}

// pcap-over-ip — a framed authenticated TLS stream from a remote sensor.
// An inline "token" is REFUSED (§23): use token_file or SYNAPSE_POIP_TOKEN.
{"name":"hq","kind":"pcap-over-ip","addr":"sensor.hq:4789",
 "token_file":"/etc/synapse/poip.tok","server_name":"sensor.hq","ca_file":"/etc/synapse/ca.pem",
 "client_cert_file":"","client_key_file":"","insecure_tls":false,"authorized":true}
```

`201 Created` returns the new source's `SourceStatus` (the same object
`GET /api/v1/captures` lists, with `"origin": "api"`):

```json
{
  "name": "lo", "kind": "tcpdump", "state": "running",
  "packets": 0, "decoded": 0, "decode_errors": 0, "bytes": 0, "drops": 0,
  "pps": 0, "bps": 0, "last_packet": "0001-01-01T00:00:00Z",
  "filter": "ip", "error": "", "connection_latency_ms": 0, "origin": "api"
}
```

| code | when |
| --- | --- |
| `201` | source built, registered and (if the pipeline is running) started |
| `400` | malformed / unknown-field body, an inline `token`, or a failed per-kind validation — the config error text verbatim (e.g. `capture source "edge": remote capture requires "authorized": true — you must be authorised to monitor sensor@10.0.0.9 (PROJECT.md §28.18)`) |
| `409` | a source with that `name` already exists |
| `422` | a **local** source (`nic`, `tcpdump`) could not be opened — missing capability, no such interface, binary not on `PATH`; the cause is in the body |
| `502` | a **remote** source (`ssh`, `pcap-over-ip`) could not be opened |
| `503` | no capture manager is wired into this daemon |

A source that fails to open is not registered and the daemon keeps serving
(PROJECT.md §21). The add is written to the daemon log and published as a
`CaptureSourceConnected` event with `"origin": "api"`.

### GET /api/v1/captures/{name}

One source, same object as above. `404` `capture source not found` if the name
is unknown or no live capture is configured.

### DELETE /api/v1/captures/{name}

Stop and deregister a source: it is cancelled, closed (raw socket closed /
subprocess killed / SSH session ended / TLS stream torn down) and its forwarder
goroutine is joined before the response is written. Sources with
`"origin": "config"` and `"origin": "api"` are **both** removable. Same
loopback-only / `#58` caveat as `POST`.

```bash
curl -sS -X DELETE http://127.0.0.1:8080/api/v1/captures/lo
```

```json
{ "removed": "lo" }
```

| code | when |
| --- | --- |
| `200` | removed; the row is dropped immediately, so a following `GET /api/v1/captures/{name}` is a `404` |
| `404` | unknown name, or no capture manager is wired |

The removal is written to the daemon log and published as a
`CaptureSourceDisconnected` event with `"origin": "api"`. Other sources and the
pipeline are unaffected.

### GET /api/v1/sensors

Reverse-connecting sensors currently attached to the daemon-side SYNPOIP
**collector** (PROJECT.md §5.3, §19.15; issues #43/#103,
[ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)). No
params, newest connection first. Always `200` — an empty array `[]` when no
collector is configured or no sensor is connected, never `503`.

This is the collector's view of its peers: the identity each sensor announced in
the handshake, joined with the live counters of its `capture.Manager` row. It is
**read-only** — a sensor appears by connecting and disappears by disconnecting,
so there is nothing here to `POST` or `DELETE`. It inherits the same
loopback-only posture as the rest of the state surface (PROJECT.md §21) and the
same `TODO(#58)` auth gate.

```bash
curl -sS http://127.0.0.1:8080/api/v1/sensors
```

```json
[
  {
    "sensor_id": "edge-1",
    "location": "wan",
    "remote_addr": "127.0.0.1:56982",
    "link_type": 1,
    "filter": "",
    "connected_at": "2026-08-31T14:52:51.539923103+02:00",
    "packets": 5054,
    "bytes": 1787170,
    "drops": 0,
    "pps": 340.0005015007397,
    "bps": 106962.15776918271,
    "last_packet": "2026-08-31T08:41:23.533764Z",
    "state": "running",
    "agent_version": "0.1.0-dev",
    "os_arch": "linux/amd64",
    "session_id": "edge-1|wan|0.1.0-dev|linux/amd64-b0dd699a577d5ccd",
    "source_name": "edge-1"
  }
]
```

- `sensor_id` / `location` — what the sensor announced (`--sensor-id` /
  `SYNAPSE_SENSOR_ID` / its hostname, and `--location` /
  `SYNAPSE_SENSOR_LOCATION`). Empty for a sensor that announced nothing.
- `remote_addr` — the peer address the collector accepted.
- `link_type` — the authoritative libpcap DLT the sensor negotiated: `1`
  `EN10MB`, `101` `RAW`.
- `filter` — the capture filter the sensor advertised in the handshake; `""` =
  everything.
- `connected_at` — when the collector accepted and registered this session. A
  reconnect is a new session with a new `connected_at`.
- `packets` / `bytes` / `drops` / `pps` / `bps` / `last_packet` / `state` — the
  same values, from the same place, as the sensor's `GET /api/v1/captures` row
  (`drops` is the sensor-reported kernel drop counter carried in keepalives).
- `agent_version` / `os_arch` — the sensor build and platform, for diagnostics.
- `session_id` — the SYNPOIP session id, which is also how the identity travelled
  (`<sensor_id>|<location>|<agent_version>|<os/arch>-<random>`; see
  `internal/capture/pcapoverip/PROTOCOL.md` §6). Useful for correlating the
  daemon and sensor logs.
- `source_name` — the name this peer is registered under in
  `GET /api/v1/captures`. Normally the `sensor_id`; a second sensor claiming the
  same id gets `edge-1#<short session>` so both still stream.

A sensor's capture row appears in `GET /api/v1/captures` with
`"kind": "pcap-over-ip-listen"` and `"origin": "collector"`, and is removed when
the connection drops.

### GET /api/v1/sensors/{id}

One sensor by `sensor_id` (or by `source_name`, for a sensor that announced no
id). Same object as above. `404` `sensor not found` if the id is unknown or no
collector is configured.

### Enabling the collector

The collector is **off by default** — a fresh install grows no extra listening
socket. It is its own config block rather than a `capture.sources[]` entry
because it is a listener that registers a source *per accepted peer*, not a
source that dials one target (ADR 0018):

```json
"capture": {
  "collector": {
    "listen": "0.0.0.0:4789",
    "cert_file": "/etc/synapseids/collector.crt",
    "key_file": "/etc/synapseids/collector.key",
    "token_file": "/etc/synapseids/collector.token",
    "client_ca_file": "/etc/synapseids/sensors-ca.pem",
    "max_sensors": 32,
    "authorized": true
  }
}
```

| field | meaning |
| --- | --- |
| `listen` | TLS listen address (`host:port`). **`""` (default) disables the collector.** |
| `cert_file` / `key_file` | the daemon's **server** certificate and key. Both required — in this direction the daemon is the TLS server. |
| `token_file` | file holding the bearer token the collector presents in its ClientHello; the sensor verifies it with `crypto/subtle`. An **inline `token` is refused** (PROJECT.md §23) — use this or `SYNAPSE_COLLECTOR_TOKEN`. |
| `client_ca_file` | optional PEM bundle. When set, mutual TLS is **required** and this is what authenticates the sensor. Strongly recommended for any non-loopback listener. |
| `max_sensors` | cap on concurrent **registered** sensors; `0` = 32. Past the cap a connection is refused before any handshake work (PROJECT.md §21). |
| `authorized` | must be `true` to enable the collector: you are asserting you are authorised to ingest traffic from the sensors that will connect (PROJECT.md §21, §28.18). |

`SYNAPSE_COLLECTOR_LISTEN` overrides `listen` and `SYNAPSE_COLLECTOR_TOKEN`
supplies the token, so neither has to live in the file.

**Who authenticates whom.** The SYNPOIP roles do not invert with the TCP
direction, so the bearer token still travels daemon → sensor: the daemon proves
itself with its server certificate *and* the token, and the sensor proves itself
with a client certificate (`client_ca_file`). Without `client_ca_file` the
collector accepts any peer that completes TLS — which is why `authorized: true`
is mandatory.

**Getting a certificate for testing.** Either use the bundled helper:

```bash
synapse-sensor gen-cert --host ids.example --cert collector.crt --key collector.key
```

which writes a self-signed ECDSA P-256 pair (cert `0644`, key `0600`) and prints
its SHA-256. The certificate is its own CA, so `collector.crt` doubles as the
`--ca` the sensor pins. Or do it by hand:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout collector.key -out collector.crt -days 365 \
  -subj '/CN=ids.example' -addext 'subjectAltName=DNS:ids.example,IP:127.0.0.1'
```

Production deployments provision from their own PKI; there is deliberately no
certificate-management subsystem in the daemon. A missing or unreadable
certificate logs one clear line and the daemon keeps serving the API without the
collector.

### POST /api/v1/architecture/estimate

Parameter, size and FLOP math for a candidate `flow-classifier-v1` hidden stack
— the compute behind the ML ▸ Architecture builder (PROJECT.md §10, §19.9). Pure
compute: no auth, no state.

Body (JSON, capped at 64 KiB) is a `schema.Architecture`. Only `hidden` is read;
`input_size` / `output_size` are **locked** to the frozen feature and output
schemas (48 / 7) and forced server-side regardless of what is sent.

```json
{
  "hidden": [
    { "width": 64, "activation": "relu", "dropout": 0.3, "batchnorm": true },
    { "width": 32, "activation": "relu" }
  ]
}
```

- `200` — always, when the body parses:

  ```json
  {
    "valid": true,
    "parameter_count": 5575,
    "approx_bytes": 22300,
    "rough_flops": 10688,
    "layers": [
      { "name": "hidden_1 (+bn)", "in": 48, "out": 64, "params": 3264 },
      { "name": "hidden_2", "in": 64, "out": 32, "params": 2080 },
      { "name": "output", "in": 32, "out": 7, "params": 231 }
    ]
  }
  ```

  When the hidden stack is not buildable — a width `<= 0`, a `dropout` outside
  `[0, 1)`, an `activation` other than `relu` / `leaky_relu` / `sigmoid` /
  `tanh`, or a `residual` layer whose previous width differs — `valid` is
  `false` and `error` carries the reason. The math fields are still returned as
  a best-effort estimate.
- `400` `bad request body: expected a schema.Architecture JSON object` —
  unparseable JSON.

The formulas match `internal/schema/architecture.go` and the trainer's
`trainer/synapse_trainer/architecture.py`: a Dense `prev -> w` layer is
`w*prev + w` parameters, an affine `BatchNorm1d(w)` adds `2*w`, `approx_bytes` is
`parameter_count * 4` (fp32), and `rough_flops` is `2*prev*w` summed over the
Dense layers.

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
  readable capture (not a classic pcap or minimal pcapng: truncated header,
  unsupported link type, multi-section pcapng)
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

A sensor coming and going on the collector shows up here as
`SensorConnected` / `SensorDisconnected` (both already in the frozen
`event-envelope-v1` enum):

```json
[
  { "type": "SensorConnected", "ts": "2026-08-31T12:55:11.965556298Z", "seq": 2466,
    "data": { "sensor_id": "edge-2", "location": "dmz", "remote_addr": "127.0.0.1:55204",
              "link_type": 1, "filter": "", "agent_version": "0.1.0-dev",
              "os_arch": "linux/amd64", "session_id": "edge-2|dmz|0.1.0-dev|linux/amd64-4313bfe…",
              "source_name": "edge-2" } }
]
```

### Batching

The server's `pump` goroutine holds one bus subscription and flushes the
accumulated envelopes as one array either every `live.websocket_batch`
(config, default `100ms`) or immediately once a batch reaches 256 envelopes.
Empty intervals send nothing.

### Backpressure

Each client has a bounded send queue of `live.client_queue_size` payloads
(config, default `5000`). If that queue is full when a batch is broadcast, the
**client is dropped** — its connection is closed and the hub's drop counter
increments, visible at `/api/v1/status` as `live.ws_client_drops` (and its
`live.client_drops` alias) (PROJECT.md §22).
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
