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
- **Downloads** — three routes are attachments rather than JSON documents:
  `GET /api/v1/datasets/{ref}/download`, and the two report routes with
  `format=html`, which return `text/html; charset=utf-8`. All three set
  `Content-Disposition: attachment`.
- **Not under `/api`** — `GET /` (and any unmatched path) serves the static web
  UI: the embedded `web/index.html`, or a directory when `server.web_root` /
  `SYNAPSE_WEB_ROOT` is set.

## Authentication (issue #58, PROJECT.md §21)

Disabled by default: with `auth.enabled` unset the API is open, and the daemon
relies on its loopback bind plus an authenticating reverse proxy in front. Set
`auth.enabled: true` and `auth.tokens_file` to require a bearer token for
**non-loopback** requests (all requests if `auth.allow_loopback: false`).

**Token file** — one `<role> <token> [label]` per line; `#` comments and blank
lines ignored; tokens are at least 8 characters and never inline in `synapse.json`
(§23). Keep it `0600`, owned by the daemon user.

```
# role      token                              label
admin       t0p-s3cr3t-admin-value             ops-oncall
operator    run-captures-and-replays-value     soc-analyst
viewer      read-only-dashboards-value         noc-wallboard
```

**Roles** cover, cumulatively:

| Role | Grants |
|---|---|
| `viewer` | every `GET`, and `GET /metrics` |
| `operator` | `viewer` + `POST/DELETE /api/v1/captures*`, `POST /api/v1/replay[/stop]` |
| `admin` | everything: model activate/deactivate, dataset create/delete, the trainer-facing `POST /api/v1/training*`, review writes |

`POST /api/v1/architecture/estimate` is a stateless calculator and needs only
`viewer`. `GET /` and `/assets/*` (the SPA shell) are never gated.

**Sending the token** — `Authorization: Bearer <token>` on every request. The
WebSocket route `GET /api/v1/stream` also accepts `?token=<token>` (a browser
cannot set the header on a `WebSocket`); no other route does.

**Responses** — `401` `{"error":"authentication required"}` (with
`WWW-Authenticate: Bearer`) or `{"error":"invalid token"}`; `403`
`{"error":"role \"admin\" required; this token is \"viewer\""}`.

**Clients** — `synapse --token <t>` / `SYNAPSE_TOKEN`. The SPA reads a token from
`localStorage` (`synapseids.api-token`); open it once as `…/?token=<t>#/dashboard`
to store it, or `window.__synapse.setToken('<t>')` from devtools. A full token UI
on the Settings page is a follow-up.

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
    "flow_versions_dropped": 0,
    "disagreements": 3,
    "flows_expired": 0,
    "classifications_expired": 0,
    "driver": "memory"
  },
  "events": { "published": 542, "dropped": 0, "subscribers": 1 },
  "capture": { "shutdown_drops": 0 },
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
  "inference": {
    "scored": 4082,
    "failures": 0,
    "latency_p50_ms": 0.031,
    "latency_p95_ms": 0.12,
    "latency_p99_ms": 0.44,
    "by_class": { "normal": 3200, "scan": 512, "brute_force": 304, "dos_ddos": 1,
                  "botnet_c2": 0, "web_attack": 0, "suspicious": 65 }
  },
  "alerts": {
    "enabled": true,
    "created": 6,
    "deduped": 302,
    "suppressed": 0,
    "evicted": 0,
    "retained": 6,
    "max_recent": 1000,
    "observed": 1176,
    "dropped": 0,
    "queue_size": 4096,
    "dedup_window_sec": 60
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
is not expected (PROJECT.md §22, §24). The counters are the **sum over every flow
table the daemon runs**: the capture pipeline's (live NICs and every `raw`-mode
SYNPOIP sensor) plus the replay pipeline's. Before issue #125 only the replay
table was reported, so a sensor-fed daemon showed `{"active":0,"started":0,…}`
while it was classifying hundreds of flows. Between replays the replay table
holds its last run's final snapshot (`active` back at `0`) and is cleared when a
new replay starts. `max` is the **per-table** cap as configured, not multiplied
by the number of tables, because that is the limit each one actually enforces.
The counters are refreshed on the flow table's tick cadence (about once a second
of capture time, and once more after a run's final flush) — never per packet. The
pipeline also writes a throttled warning to the daemon log on the first eviction
of a run and every 1000th after it.

`capture` carries `shutdown_drops`: the daemon-lifetime count of packets a
capture source had already handed to the fan-in that were discarded because the
daemon was shutting down or the source hit a terminal error — the point past
which no flow table can still be fed. Blocking shutdown on a slow consumer is the
worse choice, so those packets are dropped, but PROJECT.md §22 requires every
drop path to be counted: a non-zero value explains a gap between what a sensor
reports sending and what the daemon turned into flows. It also names the affected
source(s) in one line on the daemon log at exit. A finite source read to its end
(a PCAP replay, `synapse replay`) drains cleanly and contributes nothing here
unless shutdown races its last packets. The `capture` object is `{}` when no
capture manager is wired.

`storage.flow_versions_dropped` counts snapshot versions dropped because one flow
exceeded `storage.FlowHistoryCap` (64 versions per flow) — a long-lived flow
losing its *earliest* snapshots while keeping the most recent. It is distinct from
`flows_evicted`, which is the global ring overwriting its oldest slot. See
[`/api/v1/flows/{id}/snapshots`](#get-apiv1flowsidsnapshots).

`storage.flows_expired` / `classifications_expired` (and `alerts.expired`) count
records the **retention sweep** dropped for being older than their configured
window (`retention.flows` / `retention.classifications` / `retention.detections`,
issue #56, PROJECT.md §20) — as distinct from `*_evicted`, which is the ring
overflowing. A window of `0` disables the sweep for that category. The sweep runs
every `retention.sweep_interval` (default `5m`), off every hot path.

`storage.disagreements` is the cumulative number of stored classifications whose
ensemble raised `result.disagreement` — every disagreeing verdict ever recorded,
not just those still in the ring (PROJECT.md §12, §24).

`alerts` is the detection store (issue #117,
[ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)):

| Key | Meaning |
|---|---|
| `enabled` | `alerts.enabled` from config. When `false` nothing alerts, but the counters still report, so "alerting is off" is distinguishable from "nothing happened". |
| `created` | New detections opened. Exactly equal to the number of `AlertCreated` events published. |
| `deduped` | Verdicts folded into an existing detection. **No event was published for any of them** — this is the number the WebSocket was spared. |
| `suppressed` | Verdicts of an alertable class that did not clear their threshold. `normal` is not counted: it is not suppressed, it is not alertable. |
| `suppressed_by_rule` | Verdicts that **did** clear their threshold but matched an [`alerts.suppress`](#expected-behaviour-suppression) expected-behaviour rule, so no detection was opened. The classification is still recorded and visible in the flow log. |
| `suppress_rules` | Per-rule breakdown, in config order: `[{ "note": "...", "matched": N }]`. Omitted when no rules are configured. A rule with `matched: 0` has never fired and is probably stale. |
| `evicted` | Detections dropped by the `max_recent` bound, oldest first. Non-zero means `/api/v1/detections` is a recent window, not a full history. |
| `expired` | Detections dropped by the retention sweep for being older than `retention.detections` (issue #56). |
| `retained` | Detections currently held. |
| `max_recent` | The bound (`alerts.max_recent`, default `1000`). |
| `observed` | Verdicts the alert store evaluated. |
| `dropped` | Verdicts the ingest queue could not accept, so they were never evaluated. Non-zero means the alert goroutine fell behind the packet path (PROJECT.md §22, §24). |
| `queue_size` | Depth of that queue. |
| `dedup_window_sec` | `alerts.dedup_window_sec`, default `60`. |

`inference` is the scoring instrumentation (issue #55, PROJECT.md §24): `scored`
(runtime calls this lifetime), `failures`, `latency_p50_ms` / `latency_p95_ms` /
`latency_p99_ms` (approximate quantiles read off the histogram buckets — the raw
buckets are on [`GET /metrics`](#get-metrics)), and `by_class`, the per-class
verdict tally keyed by `traffic-classes-v1` class name.

### GET /metrics

Prometheus text exposition (version `0.0.4`), for a scraper. No params, always
`200`, `Content-Type: text/plain; version=0.0.4`. It is the same data
`/api/v1/status` carries plus the scoring and feature-extraction latency
**histograms** and the per-class verdict counter, rendered as metric families:

```text
# HELP synapseids_inference_latency_seconds Wall-clock cost of one runtime scoring call.
# TYPE synapseids_inference_latency_seconds histogram
synapseids_inference_latency_seconds_bucket{le="5e-06"} 41213
...
synapseids_inference_latency_seconds_bucket{le="+Inf"} 41902
synapseids_inference_latency_seconds_sum 0.2371
synapseids_inference_latency_seconds_count 41902
synapseids_classifications_total{class="scan"} 512
synapseids_capture_packets_total{source="wan"} 91771
synapseids_capture_packets_total{source="_all"} 91771
synapseids_flows_active 128
synapseids_detections_created_total 6
```

Every metric name is prefixed `synapseids_`; counters end `_total`; capture
counters carry a `source` label (plus a `source="_all"` aggregate). The endpoint
sits at `/metrics`, not under `/api/v1`, by Prometheus convention, and carries no
auth of its own — like the mutating routes it relies on the loopback bind and an
authenticating reverse proxy in front (issue #58, PROJECT.md §21).

`storage` latency (§24) is not instrumented: the Phase 1 store is an in-memory
ring where a put is a slice write. It gets a histogram when a durable backend
lands (#53).

### GET /api/v1/flows

Recent stored flows, newest first. Query: `limit` (default `100`, max `2000`),
plus the optional [`sensor=` / `location=` scope](#the-sensor-and-location-scope)
(issue #46). `200` → JSON array of `FlowRecord`:

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
    "sensor": "opnsense-wan",
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

`sensor` is the **observation point**: the id of the sensor that saw this
traffic, or `"local"` for the daemon's own capture and replay (issue #126;
[ADR 0030](adr/0030-flow-attribution-scoped-by-observation-point.md)). It always
equals the `sensor` on this flow's classification, and it is what `sensor=`
matches. Two sensors watching the same conversation produce **two** flows with
two ids, each with its own counters — the flow key is scoped by the observation
point, so their packet and byte counts are never summed together. The sensor id
is metadata on the record and is **not** part of the frozen 48-value feature
vector.
`sensor_mode` (`flow` / `feature`, absent for a flow built from packets) and
`sensor_flow_id` describe the *transport*, which is a separate question from
which sensor saw the traffic.

### GET /api/v1/flows/{id}

One flow by numeric ID — the most recent stored version (a later snapshot or the
close record supersedes an earlier snapshot). Earlier versions are available from
[`/snapshots`](#get-apiv1flowsidsnapshots) below.

- `200` → a single `FlowRecord` (shape as above)
- `400` `bad flow id` — `{id}` is not a uint64
- `404` `flow not found` — no such ID in the ring (it may have been evicted)

### GET /api/v1/flows/{id}/explain

Why this flow got the verdict it did, and what each model actually received
(PROJECT.md §19.3, issue #38,
[ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md)). A sibling of
the route above rather than part of it, so `FlowRecord`'s shape is unchanged.

`200`:

```json
{
  "flow_id": 1124,
  "snapshot_index": 0,
  "verdict_available": true,
  "verdict": {
    "ts": "2026-08-31T08:43:45.195387Z",
    "sensor": "local",
    "class": "brute_force",
    "class_id": 3,
    "score": 0.9217860648129587,
    "disagreement": false
  },
  "models": [
    {
      "model_id": "heuristic-v1",
      "role": "primary",
      "class": "brute_force",
      "class_id": 3,
      "score": 0.9217860648129587,
      "scores": ["…7 floats, traffic-classes-v1 order…"],
      "loaded": true,
      "input": {
        "kind": "raw",
        "note": "This model reads raw flow-features-v1 values — there is no transformation to show. …"
      },
      "explanation": {
        "model_id": "heuristic-v1",
        "role": "primary",
        "kind": "rules",
        "rules": [
          {
            "rule": "brute_force.auth_port_rounds",
            "class": "brute_force",
            "class_id": 3,
            "detail": "repeated short small-packet request/response rounds against an authentication port",
            "features": [
              { "name": "destination_port", "value": 3306, "unit": "port" },
              { "name": "packets_forward", "value": 7, "unit": "count" },
              { "name": "packets_backward", "value": 6, "unit": "count" },
              { "name": "tcp_fin_count", "value": 2, "unit": "count" },
              { "name": "tcp_rst_count", "value": 0, "unit": "count" },
              { "name": "flow_duration", "value": 0.000861, "unit": "seconds" },
              { "name": "packet_size_mean", "value": 76.53846153846153, "unit": "bytes" }
            ]
          }
        ],
        "class_weights": [
          { "class": "brute_force", "class_id": 3, "weight": 4.5 },
          { "class": "normal", "class_id": 0, "weight": 3 }
        ],
        "normal_prior": 3,
        "note": "Every rule listed is an exact account of the decision: …"
      }
    }
  ],
  "anomaly": {
    "available": true,
    "model_id": "flow-anomaly-v1-…",
    "score": 0.83, "recon_error": 0.21, "threshold": 0.18, "exceeds": true,
    "top_deltas": [ { "index": 12, "name": "bytes_per_second", "input": …, "output": …, "delta": … } ],
    "note": "Reconstruction error and the largest per-feature gaps …"
  },
  "baseline": { "available": false, "note": "Not available in this build. …" }
}
```

- `400` `bad flow id` · `404` `flow not found`

**`models[]` comes from the stored verdict**, not from whatever is loaded now —
these are the models that actually scored this flow. `verdict_available` is
`false` (and `models` empty) when the classification has aged out of the bounded
ring; `notes[]` then says so. A model named in the verdict but no longer in the
runtime gets `loaded: false`, and its inputs and rationale are not reconstructed.

#### `input.kind` — normalized model inputs

Normalization is a **per-model** concern (§8): the pipeline scores the *raw*
vector, the heuristic reads it raw, and a trained model applies its own bundle's
`normalizer.json`. There is no daemon-wide normalized vector, so this is reported
per model:

| `kind` | meaning |
|:--|:--|
| `raw` | the model scores raw values. `features` is **absent** — there is no transformation, and an identity table would imply a step that does not happen. |
| `normalized` | `normalizer_id` (`standard` / `minmax` / `identity`) plus `features[]` of `{index, name, unit, raw, normalized}` for all 48, resolved from the **active** registry entry's bundle. |
| `unknown` | the normalizer could not be resolved — no registry, nothing active, the model is unloaded, or the bundle is gone. Nothing is shown and `note` says why. |

Resolved normalizers are cached per `<model id>@<content hash>` for the process
lifetime, since `model.Load` reads and hashes `model.onnx`.

#### `explanation.kind` — what the panel claims

| `kind` | claim |
|:--|:--|
| `rules` | **exact.** Those rules, on those feature values, produced `class_weights`, which were soft-maxed into `scores`. `rules` and `class_weights` come from the same evaluation that produced the verdict, so they cannot drift from it. |
| `unavailable` | **nothing**, beyond `note`. `rules` is `[]`. |

`rules: []` with `kind: "rules"` is meaningful, not a loading state: no rule
fired, and `normal_prior` is what decided the verdict. The note spells out that
"nothing was detected" is *not* "checked against a baseline and found normal".

There is deliberately **no per-rule contribution percentage**: several rules can
feed one class and rule→probability runs through a softmax over class weights, so
a per-rule share would be invented. Read `class_weights` for the real arithmetic.

**A trained ONNX model always reports `unavailable`.** Exact attribution needs
gradients or SHAP, and `internal/nn` exposes no weights; no linear proxy is
offered, because a proxy drawn in an explanation panel reads as an explanation.
The full `scores` vector is that model's complete output.

#### `anomaly` and the (still-absent) baseline column

`baseline` is always `{available: false, note: …}` — behavioural baselines are
still Phase 7 (§19.4), so there is no "Current vs Baseline" table.

`anomaly` is populated when a `flow-anomaly-v1` autoencoder scored the flow (ADR
0037): `model_id`, the bounded `score` (0..1), the raw `recon_error`, the
calibrated `threshold` and whether it `exceeds` it — all from the stored verdict
— plus `top_deltas`, the largest per-feature reconstruction gaps, recomputed on
demand **only while that model is still loaded**. With no anomaly model it is
`{available: false, note: …}` with no value fields: a labelled gap, never a
fabricated number, so "never scored" cannot read as "scored and clean".

### GET /api/v1/flows/{id}/snapshots

The retained version history of one flow: the periodic `snapshot` records a
long-lived flow emits, then its terminal record, oldest first, each paired with
the verdict computed from it (§19.3).

`200`:

```json
{
  "flow_id": 5,
  "retained": 3,
  "cap": 64,
  "truncated": false,
  "snapshotting": true,
  "versions": [
    {
      "snapshot_index": 1,
      "close_reason": "snapshot",
      "terminal": false,
      "first_seen": "2026-08-31T08:41:17.657338Z",
      "last_seen": "2026-08-31T08:42:18.225Z",
      "duration_sec": 60.568,
      "fwd_packets": 1934,
      "bwd_packets": 1473,
      "fwd_bytes": 1996456,
      "bwd_bytes": 956500,
      "verdict": { "class": "normal", "class_id": 0, "score": 0.9611, "disagreement": false }
    }
  ],
  "notes": ["Counters are cumulative, not per-interval: …"]
}
```

- `400` `bad flow id` · `404` `flow not found`

Counters are **cumulative**, not per-interval: each version reports the flow's
totals as of its own `last_seen`.

`snapshotting: false` means the flow closed inside one `snapshot_interval` and
produced a single record — the common case, and not a gap.

`verdict: null` means that version's classification aged out of the bounded ring.
It never means "was not classified", and the response says so in `notes[]`.

History is bounded twice. Globally by the flow ring, since every retained version
occupies exactly one ring slot. Per flow by `storage.FlowHistoryCap` (**64**
versions, reported as `cap`), oldest dropped first and counted in
`status.storage.flow_versions_dropped`. `truncated: true` means the per-flow cap
dropped this flow's earliest versions — detected exactly, since a flow's first
snapshot carries `snapshot_index` 1.

Note that `flow.Table` increments `snapshot_index` on the live flow, so a long
flow's **terminal record inherits the last snapshot's index** and the final two
rows may share one. `notes[]` mentions it; see
[ADR 0025](adr/0025-flow-inspector-explanation-and-snapshots.md).

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

### GET /api/v1/detections

The detection feed (issue #117, PROJECT.md §17; see
[ADR 0027](adr/0027-detection-dedup-and-derived-severity.md)). A *detection* is a
**deduplicated** finding, not a verdict: every classification that clears its
confidence threshold is folded into one detection per
`(src_ip, dst_ip, class)` inside a dedup window, so a 1000-port sweep is one row
with `count: 1000` rather than 1000 rows. Most recently active first (`last_ts`
descending, ties by descending `id`). Always `200` on a valid query.

```json
{
  "detections": [
    {
      "id": 12,
      "ts": "2026-08-31T18:04:11.123456789Z",
      "last_ts": "2026-08-31T18:05:02.000000000Z",
      "count": 7,
      "class": "brute_force",
      "severity": "high",
      "confidence": 0.983,
      "flow_id": 4231,
      "flow_ids": [4231, 4232],
      "src_ip": "10.0.0.5",
      "dst_ip": "10.10.10.21",
      "src_port": 51234,
      "dst_port": 3306,
      "protocol": "tcp",
      "disagreement": false,
      "reason": "brute_force at 98.3% >= 70% threshold",
      "models": [
        { "model_id": "heuristic-v1", "role": "primary", "class": "brute_force", "confidence": 0.983 }
      ]
    }
  ],
  "total": 12,
  "returned": 12,
  "evicted": 0
}
```

`total` is how many retained detections matched the filter **before** `limit`;
`returned` is `detections.length`. `evicted` is the store's lifetime eviction
count — non-zero means you are looking at a recent window, not a history.
`detections` is always an array, never `null`.

#### Which occurrence each field describes

The dedup key is `(src_ip, dst_ip, class)` and deliberately excludes the ports —
that is what collapses a port sweep. So the fields do **not** all describe the
same packet, and which occurrence each comes from is part of the contract:

| Fields | Occurrence |
|---|---|
| `ts`, `flow_id`, `src_port`, `dst_port`, `protocol` | the **first**. On a scan, `dst_port` is the first port seen, not "the" port. |
| `last_ts`, `flow_ids` | the most recent. `flow_ids` holds the 20 most recent **distinct** flow ids, oldest dropped; `flow_id` stays the first one even after the list has rolled. |
| `confidence`, `reason`, `models` | the **highest-confidence** one. `reason` quotes `confidence`, so the two must agree. |
| `count` | every occurrence. One long-lived flow can contribute several (a periodic snapshot verdict plus a terminal one), which is why `count` can exceed `flow_ids.length`. |
| `disagreement` | `true` if **any** occurrence disagreed. |

`severity` is **derived from `class`**, not predicted by a model and not part of
the frozen `traffic-classes-v1` schema:

| class | severity |
|---|---|
| `normal` | *never alerts — no detection is ever created* |
| `suspicious` | `low` |
| `scan` | `medium` |
| `brute_force`, `web_attack` | `high` |
| `dos_ddos`, `botnet_c2` | `critical` |

The mapping is code, not config, and covering every class in the frozen schema is
a startup gate: a class with no severity panics `synapsed` at start rather than
serving `"severity": ""`. See ADR 0027 for why.

#### What creates a detection

The policy is the `alerts` block in `synapse.json` (see
[the annotated config](../contrib/config/synapse.annotated.md)). A verdict
becomes a detection when its class is not `normal` **and** either:

- `result.score >= ` the threshold for its class — `alerts.per_class_min_confidence[class]`
  if present, else `alerts.min_confidence` (default `0.70`; `suspicious` defaults
  to `0.85`); or
- `alerts.alert_on_disagreement` is `true` (the default) and the ensemble
  disagreed, even below the threshold — a disagreement is a finding in its own
  right (PROJECT.md §12).

`reason` states which of the two fired, in measured values only.

#### Expected-behaviour suppression

Some hosts are *supposed* to look like an attack: a DarkWeb monitor makes
outbound connections to known-malicious infrastructure all day, a vulnerability
scanner probes ports for a living, backup replication and CDN health-checks are
one-directional floods by design. Those verdicts are not misclassifications —
the traffic genuinely has the shape the rules describe — so the fix is not to
weaken the model but to state, declaratively, that this traffic is expected.

`alerts.suppress` is a list of rules, each matching on **stable** attributes
only (never an ephemeral port):

| Field | Meaning |
|---|---|
| `src` / `dst` | An IP or CIDR the flow's initiator / responder must fall within. `""` = any. A bare address is a single host. Pin `src` to your edge address to suppress *outbound*, `dst` to suppress *inbound*. |
| `dst_port` | The responder port. `0` = any. |
| `class` | A `traffic-classes-v1` class name. `""` = any alertable class. `normal` is rejected (it never alerts). |
| `note` | **Required** free-text reason, echoed in `status.alerts.suppress_rules`. |

A verdict that clears its threshold but matches a rule is **still scored and
still stored as a classification** — it stays visible in `/api/v1/flows` and
`/api/v1/classifications` and in the flow log, so an operator never loses the
ability to audit what was hidden. What suppression skips is only the *detection*:
no row in `/api/v1/detections`, no `AlertCreated`. It is counted
(`status.alerts.suppressed_by_rule`, and per rule in `suppress_rules`) so the
decision is auditable and a rule that has matched nothing is visible.

Rules are validated at load: a rule with no matchers (it would suppress
everything), an unparseable address, an unknown or `normal` class, a port out of
range, or a missing note is a **config error**, not a silent no-op. Rules are
evaluated in file order and the first match wins.

Suppression is a reporting decision, not a modelling one: the classifier keeps
scoring honestly, and "expected" is never fed back into the model. Learning what
is normal per host is a different feature (a behavioural baseline, #47/#63).

#### `AlertCreated` fires once per *new* detection

A dedup increment publishes **nothing** on the live channel. That is the point: a
sweep produces one WebSocket event, not a thousand (PROJECT.md §22). The event's
`data` is the `Detection` object above, so a client needs no follow-up request.
`status.alerts.created` equals the number of `AlertCreated` events published, and
`status.alerts.deduped` is the number the channel was spared.

#### Query parameters

All optional and combinable. **This route is stricter than the other collection
routes**: an unknown parameter name or an unparseable value is a `400`, because on
a route whose job is "show me what matters", a typo that silently widens the
result to everything is worse than an error.

| Param | Meaning |
|---|---|
| `limit` | Max detections. Default `100`, clamped to `1000`. Non-numeric or `< 1` → `400 bad limit: want a positive integer`. A value above the cap is clamped, not rejected — the cap is server policy, not a client mistake. |
| `class` | A `traffic-classes-v1` class name. Anything else → `400 unknown class name`. `class=normal` is accepted and always matches nothing. |
| `severity` | `low` \| `medium` \| `high` \| `critical`. Anything else, including a different case → `400 bad severity: want low, medium, high or critical`. |
| `min_confidence` | Keeps detections with `confidence >= n`. `n` in `0..1` is a fraction; `n > 1` is read as a `0..100` percentage (so `0.9` and `90` are equivalent), matching `/api/v1/classifications`. Outside `[0,100]` or non-numeric → `400`. |
| `since` | RFC3339. Keeps detections **active** at or after it (`last_ts >= since`), not "first seen after it" — an ongoing detection that started earlier is still reported. Unparseable → `400 bad since: want an RFC3339 timestamp`. |

Examples:

```text
GET /api/v1/detections?severity=critical
GET /api/v1/detections?class=brute_force&limit=20
GET /api/v1/detections?min_confidence=90&since=2026-08-31T18:00:00Z
```

A daemon running without an alert store answers `200` with an empty page rather
than `503`.

### GET /api/v1/detections/{id}

One detection, in the same shape as an element of `detections[]` above. `404
detection not found` for an unknown or evicted id, `400 bad detection id` for a
non-numeric one — the same contract as
[`/api/v1/flows/{id}`](#get-apiv1flowsid). Ids are per-process and start at `1`;
they do not survive a restart.

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

`baseline_available` is **always `false`** — behavioural baselines (§19.5) are
still Phase 7. `anomaly_available` is `true` when a `flow-anomaly-v1` model
scored any of this host's flows, and then `anomaly_flows` / `anomaly_mean` /
`anomaly_max` / `anomaly_exceeded` summarise those reconstruction-error scores
(ADR 0037); it is `false` with those fields zeroed otherwise.

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
  "hosts": 85, "host_cap": 2048, "hosts_evicted": 0,
  "key_cap": 128, "keys_pruned": 32,
  "observed": 1358, "dropped": 0, "queue_size": 8192, "timeline_late": 0,
  "pairs": 91, "pair_cap": 4096, "pairs_evicted": 0
}
```

`pairs` / `pair_cap` / `pairs_evicted` are the traffic matrix's bound (issue #68):
at most 4096 `(initiator, responder)` pairs are tracked, and on overflow the
lighter half by `(flows, bytes)` is discarded and counted. A non-zero
`pairs_evicted` is why `GET /api/v1/matrix` reports `partial: true`.

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

### GET /api/v1/hosts/{ip}/similar

The host's **behavioural fingerprint** and the other observed hosts whose
fingerprint is cosine-nearest to it — a lateral-movement / botnet-peer lead, not
a verdict (issue #63, [ADR 0039](adr/0039-per-host-behavioural-fingerprint.md)).

```json
{
  "ip": "10.10.10.22",
  "fingerprint": {
    "ip": "10.10.10.22",
    "flow_count": 1124,
    "vector": [0.61, 0.98, …],
    "dims": [ { "name": "flow_volume", "value": 0.61 }, { "name": "initiator_bias", "value": 0.98 }, … ]
  },
  "dims": ["flow_volume", "initiator_bias", "upload_bias", …],
  "min_flows": 5,
  "similar": [
    { "ip": "10.10.10.23", "cosine": 0.981, "flow_count": 940 },
    { "ip": "10.10.10.24", "cosine": 0.902, "flow_count": 512 }
  ],
  "method": "hand-crafted behavioural fingerprint (bounded per-host aggregates), cosine similarity. Not a learned embedding and not a verdict (issue #63, ADR 0039)."
}
```

The fingerprint is a fixed, ordered vector of scale-free ratios — flow
direction, volume asymmetry, peer/port fan-out and Shannon entropy, protocol
mix, the seven `traffic-classes-v1` shares, and the disagreement / anomaly
rates. It is **hand-crafted, not trained**; a learned embedding is a future
upgrade behind this same shape. `dims` (top level) is the frozen name list; a
new dimension is a `fingerprint-v2`, not an edit.

| Param | Meaning |
|---|---|
| `limit` | Neighbours to return, `1`–`100` (default `10`). |
| `min_flows` | A candidate host needs at least this many terminal flows to be compared (default `5`) — below that a fingerprint is mostly noise. |

`{ip}` validation is the same as `GET /api/v1/hosts/{ip}`: `400` for a
non-literal address, `404` when the host has never been observed.

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
    { "ts": "2026-08-31T08:41:11Z", "total": 6, "by_class": { "normal": 4, "brute_force": 2 }, "disagreements": 0,
      "anomaly_n": 0, "anomaly_mean": 0, "anomaly_max": 0, "anomaly_exceeds": 0 }
  ],
  "anomaly_available": false
}
```

Each bucket carries `anomaly_n` (flows an anomaly model scored), `anomaly_mean` /
`anomaly_max` (over their bounded 0..1 reconstruction scores) and
`anomaly_exceeds` (how many crossed the model's threshold).

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

`anomaly_available` is `true` when a `flow-anomaly-v1` model scored flows in the
window (ADR 0037); otherwise it is `false` and the per-bucket `anomaly_*` fields
are zero rather than a fabricated series.

### GET /api/v1/drift

The current `flow-features-v1` distribution compared against the **active model's
training distribution**, per feature and overall (issue #49, PROJECT.md §19.13).

The reference is the active bundle's `normalizer.json`. A `standard` normalizer
carries the per-feature training `mean` and `std` directly; that is the
comparison. Without an active model — or when its normalizer is `identity` /
`minmax`, which carry no mean+std pair — there is no training distribution to
compare against: `state` is `no_baseline`, `baseline.source` is `none`, and a
`baseline_note` says why. The per-feature `current_mean` / `current_std` are
still returned so a distribution view has data.

It is a read-side fold of the newest 5000 stored flow vectors, like
`GET /api/v1/matrix` — no packet-path work, no new storage.

| Param | Meaning |
|---|---|
| `from`, `to` | Inclusive RFC3339 bounds on a flow version's `last_seen`. A bad value → `400`. |
| `sensor`, `location` | The scope shared with the flow and classification lists. |

`200`:

```json
{
  "state": "warn",
  "baseline": { "source": "model_normalizer",
                "model_id": "flow-classifier-v1-cph-0002", "method": "standard" },
  "window": { "flows": 4213, "scanned": 4213, "truncated": false,
              "first_seen": "2026-09-01T08:00:00Z", "last_seen": "2026-09-01T09:10:00Z" },
  "thresholds": { "warn": 2.0, "drift": 4.0, "retrain_suggest_z": 6.0, "retrain_suggest_features": 3 },
  "overall": { "max_z": 3.1, "mean_z": 0.7, "features_warn": 3, "features_drift": 0 },
  "features": [
    { "index": 12, "name": "bytes_per_second",
      "baseline_mean": 1234.5, "baseline_std": 456.7,
      "current_mean": 2510.2, "current_std": 690.1,
      "z": 2.79, "std_ratio": 1.51, "state": "warn" }
  ],
  "suggestion": {
    "retrain_suggested": false,
    "reason": "drift is within tolerance (max z 3.1 < 6.0, 0/3 feature(s) in the drift band)",
    "advisory": "Suggestion only. Retraining and activation are always an explicit operator decision (PROJECT.md §19.13, §28.10)."
  },
  "advisory": "Drift is informational. The daemon never retrains or activates a model automatically (PROJECT.md §19.13, §28.10)."
}
```

- `z` — the standardized mean shift `|current_mean − training_mean| / training_std`.
  `state` per feature is `stable` (`z < warn_z`), `warn` (`warn_z ≤ z < drift_z`)
  or `drift` (`z ≥ drift_z`). The bands are the `drift.warn_z` / `drift.drift_z`
  config values (defaults `2.0` / `4.0`).
- `suggestion` (only when a training baseline exists, issue #65 / ADR 0038) is an
  **advisory** retraining hint. `retrain_suggested` is `true` when
  `overall.max_z ≥ drift.retrain_suggest_z` (default `6.0`) **or** at least
  `drift.retrain_suggest_features` features (default `3`) are in the drift band;
  `reason` explains which trip fired (or why none did). It never retrains,
  deploys or activates anything — that is always an explicit operator step.
- `std_ratio` — `current_std / training_std`, so a feature whose spread changed
  without its mean moving is still visible.
- `features` is sorted worst-`z` first when a baseline exists, schema order
  otherwise.
- `state` (top level) is the worst per-feature band: `drift` if any feature is
  `drift`, else `warn` if any is `warn`, else `stable`; `no_baseline` when there
  is no training distribution or no flows in the window.
- `window.truncated` is `true` once the 5000-record scan is full — older traffic
  is not covered.

**Drift never triggers an action.** The daemon does not retrain, deploy or
activate a model on its own — not even when `suggestion.retrain_suggested` is
`true`; this route is a signal for an operator (PROJECT.md §19.13, §28.10). See
[ADR 0036](adr/0036-feature-drift-monitoring.md) and
[ADR 0038](adr/0038-drift-config-and-retraining-suggestion.md).

### GET /api/v1/reports/host/{ip}

A **downloadable host investigation report** (PROJECT.md §19.3, §19.4; issue #66,
[ADR 0023](adr/0023-downloadable-investigation-reports.md)): one self-contained
artefact an operator can attach to a ticket or mail to a peer team.

| Param | Meaning |
|---|---|
| `format` | `json` (default) or `html`. Anything else → `400 bad format`. |
| `from`, `to` | Inclusive RFC3339 window bounds. `to` before `from` → `400`. Omit both for "whatever is retained". |
| `bucket` | Timeline resolution: `1s`, `10s` (default) or `1m`. Anything else → `400 bad bucket`. |
| `limit` | Notable-flow cap. Default **500**, clamped at **2000**. Non-positive → `400 bad limit`. |
| `class`, `model`, `min_confidence`, `disagreement` | Exactly the `GET /api/v1/classifications` filter dialect, applied to the verdicts the report covers. The applied predicates are echoed back in `scope.filter`. |

`{ip}` is re-parsed and canonicalised with `net/netip`: a non-literal is
`400 bad host address`, and an address the aggregation index has never observed is
`404 host not found`. `::ffff:10.0.0.1` and `10.0.0.1` address the same report.

Both formats are served as a download:

```
Content-Type: application/json                 (format=json)
Content-Type: text/html; charset=utf-8         (format=html)
Content-Disposition: attachment; filename="synapseids-host-10.10.10.22-20260831T131500Z.json"
Cache-Control: no-store
X-Content-Type-Options: nosniff
```

The filename's scope segment is reduced to `[a-z0-9._-]`, so a packet-derived
address can neither break out of the quoted header parameter nor produce a
traversal when the browser writes the file (§28.11).

**`format=json`** is the `report.Report` struct verbatim:

```json
{
  "schema": "investigation-report-v1",
  "generated_at": "2026-08-31T13:15:00Z",
  "generator": {
    "product": "synapseids",
    "version": "0.1.0-dev",
    "commit": "6afcf43",
    "built_at": "2026-08-31T12:58:04Z",
    "dirty": false,
    "feature_schema": "flow-features-v1",
    "output_schema": "traffic-classes-v1"
  },
  "scope": { "kind": "host", "host": "10.10.10.22", "unbounded": true },
  "coverage": {
    "partial": true,
    "store_driver": "memory",
    "flows_retained": 5000, "flows_evicted": 0,
    "classifications_retained": 5000, "classifications_evicted": 1240,
    "scan_limit": 5000, "scan_scanned": 5000, "scan_exhausted": true,
    "oldest_retained": "2026-08-31T13:02:11Z",
    "range_starts_before_retention": false,
    "hosts_tracked": 27, "host_cap": 2048, "hosts_evicted": 0,
    "key_cap": 128, "keys_pruned": 3072,
    "observations_dropped": 0, "timeline_late": 0,
    "notable_flow_cap": 500, "notable_candidates": 1041,
    "notable_flows_truncated": true, "flow_records_missing": 0,
    "baseline_available": false,
    "anomaly_available": false
  },
  "notes": [
    { "code": "baseline_unavailable", "level": "warning",
      "text": "Behavioural baseline comparison is not available in this build (Phase 7, …)." },
    { "code": "anomaly_unavailable", "level": "warning",
      "text": "No anomaly model scored this traffic. … the absence of an anomaly finding here does NOT mean the traffic was checked for novelty and found normal." },
    { "code": "partial_topn_pruned", "level": "warning",
      "text": "PARTIAL VIEW: per-host top-N lists are capped at 128 distinct ports and peers and 3072 low-count keys have been pruned. …" }
  ],
  "summary": {
    "classifications": 1124, "disagreements": 0, "non_normal": 1041,
    "distinct_flows": 1124, "distinct_hosts": 6,
    "first_verdict": "2026-08-31T13:02:11Z", "last_verdict": "2026-08-31T13:04:52Z"
  },
  "host": { "…": "the insight.Profile from GET /api/v1/hosts/{ip}" },
  "classes":   [ { "class": "scan", "class_id": 1, "count": 1035, "share": 0.9209 } ],
  "timeline":  { "source": "retained-classifications", "bucket_sec": 10, "buckets": [], "anomaly_available": false },
  "top_peers": [ { "ip": "10.10.10.21", "flows": 1024 } ],
  "top_ports": [ { "port": 3306, "flows": 61 } ],
  "protocols": [ { "proto": "tcp", "flows": 1124 } ],
  "models":    [ { "id": "heuristic-v1", "family": "flow-classifier-v1", "role": "primary" } ],
  "notable_flows": [
    {
      "flow_id": 8123,
      "reasons": ["non_normal_verdict"],
      "ts": "2026-08-31T13:04:52Z",
      "proto": "tcp",
      "initiator_ip": "10.10.10.22", "initiator_port": 45122,
      "responder_ip": "10.10.10.21", "responder_port": 3306,
      "class": "brute_force", "class_id": 3, "score": 0.918,
      "disagreement": false,
      "models": [ { "model_id": "heuristic-v1", "role": "primary", "class": "brute_force", "score": 0.918 } ],
      "record_available": true,
      "duration_sec": 0.41, "fwd_packets": 8, "bwd_packets": 6,
      "fwd_bytes": 612, "bwd_bytes": 430, "close_reason": "fin",
      "features": [ { "name": "flow_duration", "value": 0.41, "unit": "seconds" } ]
    }
  ],
  "feature_legend": [ { "name": "flow_duration", "unit": "seconds", "calc": "last_seen - first_seen" } ]
}
```

**Honesty contract.** `coverage` and `notes` come *before* the findings on
purpose — the caveats are part of the finding.

- `baseline_available` is **always `false`** (Phase 7), and the
  `baseline_unavailable` note is unconditional. `anomaly_available` is `true`
  when a `flow-anomaly-v1` model scored any verdict in scope; when it is
  `false` the `anomaly_unavailable` note fires so an empty anomaly result can
  never read as "checked for novelty and clean" (ADR 0037).
- `coverage.partial` is `true` whenever any bound bit: the record ring evicted,
  the 5000-verdict scan budget filled, the requested `from` predates the oldest
  retained verdict, the host map evicted, a per-host top-N list was pruned,
  observations were dropped, verdicts missed their timeline bucket, the
  notable-flow list truncated, or a listed verdict outlived its flow record. Each
  gets its own `notes[]` entry naming the limit and the counters.
- A notable flow whose `FlowRecord` has been evicted carries
  `record_available: false` and an **empty** `features` array — never a row of
  zeroes.

**Notable-flow selection** is every in-scope verdict that either disagreed across
models or landed on a class other than `normal`, ranked disagreements-first, then
by descending confidence, then newest, then flow ID. `feature_legend` documents
the fixed named subset carried per flow — the raw values this build's classifier
reads, **not** a ranked per-flow attribution (that is Phase 7).

**`format=html`** returns one standalone document: a single inline `<style>` in
the project's dark palette with a `@media print` block, tables for the flows,
ports and peers, and CSS/inline-SVG bars for the class mix and the timeline.
There is **no** external stylesheet, no CDN, no `<script>`, no `<img>` and no
webfont, so it opens correctly from `file://` with no network access. It renders
through Go's `html/template`, whose contextual escaping is what stops a crafted
hostname, sensor name or filter string from injecting markup into a document an
operator opens in a browser (§21, §28.11).

### GET /api/v1/reports/range

The same artefact for a time window rather than one host. Identical parameters
minus the path address; `scope.kind` is `"range"`, there is no `host` block, and
`top_peers` / `top_ports` / `protocols` are the busiest addresses, service ports
and protocols in the window rather than one host's profile lists.

```
GET /api/v1/reports/range?from=2026-08-31T13:00:00Z&to=2026-08-31T13:10:00Z&class=scan&format=html
Content-Disposition: attachment; filename="synapseids-range-20260831T131500Z.html"
```

An unfiltered range report's `timeline.source` is `insight-ring` — the
incrementally maintained ring, exact within its own (wider) window. Any
classification filter switches it to `retained-classifications`, bucketed on
demand from the scanned verdicts, exactly like `GET /api/v1/timeline`.

### Report routes are read-only but concentrate sensitive telemetry

Both routes are read-only, so unlike model activation they carry no
explicit-action gate. But a report is a **concentrated** dump: one request yields
every observed peer of a host, its service ports, its volume, its verdicts and
the raw feature values behind them, packaged as a file designed to be forwarded
and re-opened elsewhere. They inherit the daemon's loopback-only default and the
standing requirement for an authenticating proxy on any non-loopback listener
(PROJECT.md §21) — and unlike a live API response, a leaked artefact cannot be
un-shared. `TODO(#58)`.

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
    { "id": "heuristic-v1", "family": "flow-classifier-v1", "role": "primary",
      "registered": false, "unsupported_classes": ["web_attack"] }
  ]
}
```

`models` is every registered bundle, newest registration first; `status` is one
of `registered`, `active`, `deactivated`. `runtime` is what is actually scoring
flows right now — the heuristic (`id: heuristic-v1`, `registered: false`) until a
model is activated, then the single activated model. `runtime` inside each
`models` entry says whether that entry is the one loaded and in what role.

`unsupported_classes` (present only when non-empty) lists `traffic-classes-v1`
classes the runtime model never emits, so a client shows a labelled gap rather
than implying full coverage. The Phase 1 heuristic reports `["web_attack"]`: its
byte-asymmetry rule fired only on ordinary uploads and was removed (#135), and
whether the class is reachable from `flow-features-v1` at all — without payload
inspection — is open (#134). The class stays index 5 of the frozen output vector
regardless; a trained model may still learn it.
Activation never survives a daemon restart: a `status: active` entry is
reconciled to `deactivated` on startup and must be re-activated explicitly
(PROJECT.md §28.10).

When the daemon runs without a registry (embedded/test), `models` is `[]` and
only `runtime` is populated.

### GET /api/v1/models/comparison

Side-by-side agreement of every model that scored the same flows (PROJECT.md
§12, §19.7). The inference runtime records each model's individual output on
every `Classification` (`result.models[]`), so this route is a read-side fold of
the newest window of stored verdicts — no packet-path work, no new storage, the
same on-demand scan `GET /api/v1/matrix` does for a filtered query.

Query parameters are the shared class filters and time range (see
[`GET /api/v1/classifications`](#query-parameters) and the `from` / `to` bounds):
`class`, `model`, `min_confidence`, `disagreement`, `sensor`, `location`,
`from`, `to`. `model=` narrows the window to rows that model scored; the
comparison is then within that subset. A bad `from` / `to` / `min_confidence` /
`class` is a `400`.

`200`:

```json
{
  "window": { "scanned": 4213, "matched": 4213, "truncated": false,
              "from": null, "to": null },
  "classes": ["normal","scan","dos_ddos","brute_force","botnet_c2","web_attack","suspicious"],
  "flows_compared": 4000,
  "single_model_rows": 213,
  "disagreement_rate": 0.021,
  "models": [
    { "model_id": "flow-classifier-v1-cph-0002", "role": "primary", "rows": 4213,
      "mean_confidence": 0.883,
      "class_distribution": { "normal": 3800, "scan": 210, "brute_force": 203 } },
    { "model_id": "heuristic-v1", "role": "experimental", "rows": 4213,
      "mean_confidence": 0.71,
      "class_distribution": { "normal": 3900, "scan": 150, "brute_force": 163 },
      "unsupported_classes": ["web_attack"] }
  ],
  "pairs": [
    { "a": "flow-classifier-v1-cph-0002", "b": "heuristic-v1",
      "both_scored": 4000, "agree": 3860, "disagree": 140,
      "agreement_rate": 0.965, "mean_abs_confidence_delta": 0.071,
      "class_matrix": [[3780, 5, 0, 3, 0, 0, 2], /* ... 7×7 ... */] }
  ],
  "notes": [ /* what this view does and does not claim */ ]
}
```

- `window.matched` — verdicts in scope after filters and time range;
  `window.truncated` is `true` once the 5000-record scan window is full, meaning
  older traffic is not covered.
- `flows_compared` — rows carrying **≥ 2** model outputs; `single_model_rows`
  cannot be compared (only one model scored them — the usual case until a second
  model is loaded or run as a shadow).
- `disagreement_rate` — matched rows whose ensemble `result.disagreement` was
  set, over `matched` (the alert-driving models predicted more than one top
  class; experimental and anomaly roles are excluded from that flag by the
  runtime).
- `models[]` — one entry per model id seen, primary role first: how many rows it
  scored, its mean verdict confidence, its class distribution, and
  `unsupported_classes` when the loaded model declares a coverage gap (#134).
- `pairs[]` — one entry per unordered model-id pair that scored a common flow.
  `agree` counts equal top class; `class_matrix[i][j]` counts flows where model
  `a` said `classes[i]` and model `b` said `classes[j]` (rows = `a`, columns =
  `b`, in the `classes` order). `mean_abs_confidence_delta` is the mean
  `|score_a − score_b|` over the common flows.

**What it does not do.** Accuracy / F1 / precision / recall need ground-truth
labels, which live in the review store and the datasets, not on a live verdict —
that comparison is an offline evaluation run against a labelled dataset or a
replay, and is out of scope here. Per-model inference latency is not recorded
per verdict; `GET /metrics` carries the aggregate scoring-latency histogram.

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

Explicitly make a registered model live (PROJECT.md §28.10, §29 steps 16–18). No
body. The daemon re-loads the bundle from disk, re-runs the validation gate,
compiles the ONNX graph, atomically swaps it into the inference runtime, records
the status change and writes a `ModelActivated` audit line.

Activation is **role-aware**: the role is derived from the bundle family —
`flow-classifier-v1` → `primary`, `flow-anomaly-v1` → `anomaly` (ADR 0037),
`flow-sequence-v1` → `sequence` (ADR 0040) — and activating a model only demotes
the previously-active model **in the same role**. A primary classifier, an
anomaly autoencoder and a temporal sequence peer can all be Active at once. The
`sequence` peer's verdict joins `models[]` and the disagreement flag but never
drives `class`/`score`; the `anomaly` model stays out of both.

`200` returns `{ "entry": { /* … */ } }` with `status: active` and
`runtime.loaded: true`.

- `404` — `id` is not a registered model.
- `409` — the bundle no longer loads, no longer passes the gate, or its
  `model.onnx` cannot be compiled by the Go inference runtime. The live runtime
  is left untouched.
- `503` — the daemon is running without a registry.

State-changing and unauthenticated for now — same posture as `POST
/api/v1/replay`, where loopback-by-default is the only control. RBAC is tracked
as issue #58.

### POST /api/v1/models/{id}/deactivate

Turn a model off. No body. The role is taken from the registry entry: a
`primary` deactivation restores the heuristic; an `anomaly` or `sequence`
deactivation drops that peer (the other roles are untouched). Records the status
change and writes a `ModelDeactivated` audit line. `200` returns
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
    "scan": 200000,
    "reviewed": false,
    "include_ignored": false
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

**`selection.reviewed` — a curated, human-labelled cut** (PROJECT.md §16, issue
#42; ADR 0021). With `"reviewed": true` the rows come from the human review store
instead of the classification ring, and the CSV `label` column carries the
**operator's** label rather than the model's prediction. This is the only way
`labeling_source` can become `human_review`; there is no request field that could
assert it directly.

Eligibility by review state:

| state | included | label |
|---|---|---|
| `correct` | yes | the prediction the human confirmed |
| `incorrect` | yes | the human's correction |
| `ignored_pattern` | only with `"include_ignored": true` | the model's *unconfirmed* prediction |
| `unsure` | no | — |
| `unreviewed` | no | — |

`labeling_source` is therefore `human_review` when every row's label was asserted
by a person, and `human_review+model_prediction:<ids>` for a mixed cut (which
also carries a `warnings` entry naming how many rows are unconfirmed). Every
other guarantee is unchanged: immutability, `content_hash` over the CSV bytes,
sort by flow id, `parent_datasets` lineage, and the zero-rows / one-class /
`min_rows` refusals.

In a reviewed cut the remaining predicates read differently, because there is no
classification to match against: `class` filters on the **human** label, `model`
and `min_confidence` on the *captured* prediction, `from`/`to` on the flow's
last-seen time, and `proto`/`initiator_ip`/`responder_ip` on the stored flow
record. `scan` is ignored (reviews are not a ring). `disagreement` combined with
`reviewed` is a `400`: a review record keeps the model's class, score and id, not
the ensemble's disagreement flag, so there is nothing to filter on.
`include_ignored` without `reviewed` is also a `400`.

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

### GET /api/v1/datasets/{ref}/stats

The **Dataset Explorer** bundle (PROJECT.md §19.11; issues #37 and #67). Every
value is derived server-side from the immutable `dataset.csv` and cached by the
version's `content_hash`, so repeated calls are cheap and byte-for-byte
identical. Read-only, unauthenticated. `400` bad ref · `404` unknown version ·
`500` the CSV on disk is unreadable/malformed · `503` no dataset manager wired.

```jsonc
{
  "ref": "thugs/lab-attacks-2026-08@v1",
  "content_hash": "sha256:7bb0e464…",
  "row_count": 1124,
  "feature_count": 48,

  "feature_stats": [               // one entry per flow-features-v1 feature, schema order
    {
      "index": 3, "name": "bytes_forward", "unit": "bytes", "norm": "log1p",
      "min": 0, "max": 4.1e6, "mean": 5123.4, "stddev": 90211.7,
      "p25": 40, "p50": 220, "p75": 1460,
      "degenerate": false,         // true ⇒ every row equal; bin_* are null
      "log_scale": true,           // histogram edges are log1p-spaced
      "bin_edges": [ /* 25 */ ], "bin_counts": [ /* 24 */ ]
    }
  ],

  "label_distribution": {
    "classes": [ /* 7 traffic-classes-v1 names */ ],
    "counts": [817,304,1,0,0,2,0], "fractions": [0.727, …],
    "total": 1124,
    "unknown": {},                 // labels in the CSV that are not schema classes
    "manifest_mismatch": false     // CSV counts vs the manifest's label_counts
  },

  "correlation": {                 // 48×48 Pearson, row-major flattened
    "names": [ /* 48 feature names */ ],
    "size": 48,
    "matrix": [ /* size*size floats; matrix[i*size+j] = corr(i,j) */ ]
  },

  "ports": {                       // from the source_port / destination_port features
    "top_destination": [ { "port": 3306, "count": 400 }, … ],  // ≤ 20, count desc
    "top_source": [ … ],
    "distinct_destination": 214, "distinct_source": 968
  },
  "protocols": { "tcp": 923, "udp": 197, "icmp": 4, "other": 0 },

  "outliers": {
    "rule": "row's max |z-score| over the 48 features exceeds the threshold; …",
    "threshold": 6, "cap": 100,
    "count": 81,                   // total that exceed the threshold
    "rows": [                      // ≤ cap, worst first
      { "row": 4, "label": "normal", "max_z": 31.1,
        "features": [ { "index": 3, "name": "bytes_forward", "value": 4.1e6, "z": 31.1 }, … ] }
    ]
  },

  "pca": {                         // top 3 components of the standardised matrix
    "components": 3,
    "loadings": [ [ /* 48 */ ], [ /* 48 */ ], [ /* 48 */ ] ],  // eigenvectors, sign-fixed
    "explained_variance": [0.174, 0.146, 0.110],               // eigenvalue_k / trace
    "eigenvalues_total": 46,       // trace = count of non-degenerate features
    "jacobi_sweeps": 11,
    "projection": [ { "pc1": …, "pc2": …, "pc3": …, "label": "scan", "row": 12 }, … ],
    "projection_sampled": false,   // true ⇒ a fixed-stride sample was taken
    "projection_cap": 5000         // …because row_count exceeded this
  }
}
```

`row` in `outliers` and `pca.projection` is the 0-based index into `dataset.csv`
(the CSV carries no flow-id column); rows are ordered by flow id. The PCA is a
stdlib-only cyclic Jacobi eigensolve of the correlation matrix — see
[ADR 0020](adr/0020-dataset-explorer-and-in-tree-pca.md); UMAP is deferred.

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

### GET /api/v1/review/queue

The flows that still need a human, ranked (PROJECT.md §16; issues #42, #64. See
[ADR 0021](adr/0021-human-review-loop-and-curated-datasets.md)).

Query parameters:

| Param | Meaning |
|---|---|
| `sort` | `uncertainty` \| `recent` (default) \| `disagreement`. An unknown value is a `400` echoing the valid set. |
| `limit` | Page size, default 100, max 2000. Applied **after** ranking. |
| `class`, `model`, `min_confidence`, `disagreement` | The shared classification filters — identical meaning to `GET /api/v1/classifications`, including `min_confidence > 1` read as a percentage. |

```json
{
  "queue": [
    {
      "flow_id": 15,
      "ts": "2026-08-31T08:41:39Z",
      "sensor": "local",
      "proto": "TCP",
      "initiator_ip": "10.10.10.22", "initiator_port": 36862,
      "responder_ip": "160.79.104.10", "responder_port": 443,
      "predicted_class": "web_attack",
      "predicted_score": 0.8366529128376532,
      "model_id": "heuristic-v1",
      "disagreement": false,
      "scores": [0.1580, 0.0, 0.0, 0.0, 0.0, 0.8366, 0.0053],
      "top1": "web_attack", "top2": "normal",
      "margin": 0.6786, "uncertainty": 0.3214, "entropy": 0.245,
      "scores_available": true,
      "review_state": "unreviewed"
    }
  ],
  "sort": "uncertainty",
  "scanned": 1176,
  "vocabulary": { "states": [ … ], "classes": [ … ], "sorts": [ … ] },
  "ranking": {
    "uncertainty": "1 - (p_top1 - p_top2) over the authoritative model's 7-class probability vector; larger = review sooner",
    "entropy": "normalised Shannon entropy over the 7 classes, 0 (certain) .. 1 (uniform)"
  }
}
```

**The ranking.** `sort=uncertainty` is the active-learning order issue #64 asks
for: **smallest margin first**, where `margin = p_top1 - p_top2` over the
authoritative model's 7-class vector (normalised by its sum first, so an
unnormalised vector cannot skew it). `uncertainty` is reported as `1 - margin` so
bigger always means "review sooner". Normalised entropy is reported alongside.
A uniform vector gives margin 0 / entropy 1 and ranks first; a one-hot vector
gives margin 1 / entropy 0 and ranks last; a verdict with no usable vector
reports `scores_available: false` and is treated as maximally uncertain rather
than hidden. `top1`/`top2` name the two classes the margin is between, so the UI
can show *why* a row is near the top. Ties break by newest first, then flow id.

`sort=disagreement` puts `disagreement` flows first and falls back to the margin
order inside each group. `sort=recent` is newest verdict first.

**Membership.** A flow leaves the queue once its review state is terminal —
`correct`, `incorrect` or `ignored_pattern`. **`unsure` stays in the queue** by
design: "I don't know" is a request to come back to it, not an answer, and the
note is carried forward on the queue item so the next reviewer sees it. One entry
per flow; the newest verdict wins.

- `400` — unknown `sort`, unknown `class`, bad `min_confidence`.
- `503` — the daemon is running without a review store.

### GET /api/v1/review

Every stored review decision, most recently updated first.

| Param | Meaning |
|---|---|
| `state` | Keep only this §16 state. An unknown value is a `400`. |
| `limit` | Default 100, max 5000. |

```json
{
  "reviews": [
    {
      "flow_id": 15,
      "state": "incorrect",
      "human_label": "scan",
      "effective_label": "scan",
      "predicted_class": "web_attack",
      "predicted_score": 0.8366529128376532,
      "model_id": "heuristic-v1",
      "reviewer": "local",
      "note": "nmap probe, not a web attack",
      "created_at": "2026-08-31T13:32:52Z",
      "updated_at": "2026-08-31T13:33:53Z",
      "history": [
        { "ts": "2026-08-31T13:32:52Z", "state": "correct", "reviewer": "local" }
      ]
    }
  ],
  "stats": { … },
  "vocabulary": { … }
}
```

`predicted_class`, `predicted_score` and `model_id` are the model's **original**
claim, captured when the flow was first reviewed and never overwritten
(PROJECT.md §16). `effective_label` is derived on every read: the confirmed
prediction for `correct`, the correction for `incorrect`, `""` otherwise.
`history` holds the superseded decisions, oldest first.

### GET /api/v1/review/stats

Counts per §16 state. Every one of the five keys is always present, zero
included, so a UI strip does not change shape.

```json
{
  "stats": {
    "total": 40,
    "by_state": { "unreviewed": 0, "correct": 36, "incorrect": 2, "unsure": 1, "ignored_pattern": 1 },
    "terminal": 39,
    "open": 1,
    "labelled": 38,
    "directory": "/var/lib/synapseids/review"
  },
  "vocabulary": { … }
}
```

`terminal` is `correct + incorrect + ignored_pattern` (out of the queue), `open`
is `unreviewed + unsure` (still in it), and `labelled` is
`correct + incorrect` — the rows a curated dataset can use.

### GET /api/v1/review/{flow_id}

One review record, `{"review": {…}, "vocabulary": {…}}`.

- `400` — the path segment is not a positive integer.
- `404` — the flow has never been reviewed.
- `503` — no review store wired.

### PUT /api/v1/review/{flow_id}

Record a decision, or correct an earlier one. `POST` is accepted identically.
Body is JSON, unknown fields rejected, 16 KiB cap.

```json
{ "state": "incorrect", "human_label": "scan", "note": "nmap probe, not a web attack" }
```

| Field | Meaning |
|---|---|
| `state` | Required. One of `unreviewed`, `correct`, `incorrect`, `unsure`, `ignored_pattern`. |
| `human_label` | A `traffic-classes-v1` class. **Required** for `incorrect`; optional for `correct` (and then must equal the prediction); must be empty for every other state. |
| `note` | Optional free text, 4096 bytes max. |

There is deliberately **no** `predicted_class`, `predicted_score` or `model_id`
field, and there never will be. The daemon captures the model's prediction itself
on the first review of a flow and copies it forward untouched on every later one;
sending one of those keys is a `400 unknown field`. This is PROJECT.md §16's
"always retain the original model prediction separately from the human-reviewed
label", enforced structurally — see ADR 0021.

Rules, and why:

- `correct` means *the prediction is the label*, so the label is derived from the
  prediction. Supplying one that differs is a `400` pointing at `incorrect`.
- `incorrect` requires a label, and it must **differ** from the prediction —
  saying the model was both wrong and right is a `400` pointing at `correct`.
- `unsure`, `ignored_pattern` and `unreviewed` assert no class, so a label is a
  `400`. `ignored_pattern` means "stop showing me this", not "this is class X".
- Writing `unreviewed` is how an operator un-reviews a flow: the decision is
  cleared and the flow returns to the queue, with the previous state preserved in
  `history`.

Responses:

- `201` — first review of this flow; `{"review": {…}, "vocabulary": {…}}`.
- `200` — a correction to an existing review. The previous decision is appended
  to `history` and `updated_at` moves; `created_at` and the three `predicted_*`
  values do not.
- `400` — bad body, unknown field, unknown `state`, a `human_label` that is not a
  `traffic-classes-v1` class (the error echoes the valid set), or a state/label
  combination that contradicts itself.
- `404` — the flow has no stored classification: it was never classified, or its
  verdict has already been evicted from the bounded ring, so there is no
  prediction to review against. You cannot review a flow the store has forgotten.
- `503` — no review store wired.

### Review write routes are state-changing and unauthenticated

`PUT`/`POST /api/v1/review/{flow_id}` inherit the repo's loopback-by-default
posture (PROJECT.md §21) and carry `TODO(#58): gate behind auth/RBAC`, the same as
the dataset, replay, capture and model-activation routes. Every write appends a
line to `models.directory/audit.log` with `subject_type: "review"` and the flow
id as the subject, carrying both the human label and the prediction — this is the
"human label changes" audit §21 asks for. Each write also publishes a
`ReviewUpdated` envelope on the live bus with
`{flow_id, state, human_label, predicted_class}`; `ReviewUpdated` was already a
member of the frozen `event-envelope-v1` enum, so nothing about the event schema
changed.

### GET /api/v1/training

Every training run the daemon is mirroring, newest first. `?limit` caps the list
(default 100, max 500).

```json
{
  "runs": [ { "id": "20260831T123737Z-75549ac4", "name": "nightly", "status": "completed", "epoch": 3, "epochs_total": 3, "history": [ … ], "final": { … } } ],
  "history_cap": 1000,
  "stale_after_seconds": 900
}
```

`status` is `running` | `completed` | `failed` | `stale`. A `running` run whose
last progress update is older than `stale_after_seconds` reads back as `stale` —
computed on read, never persisted; a later update clears it. With no training
store wired this returns `{"runs": []}` rather than `503`.

### GET /api/v1/training/{id}

One run with its full `history` (per-epoch progress dicts, capped at
`history_cap`, oldest dropped) and `final` (the trainer's terminal `done`
metrics: accuracy, macro precision/recall/F1, per-class table, confusion matrix,
held-out `test` block). **This is the endpoint the SPA polls**, every ~1.5 s
while the run is `running`. `404` unknown id, `503` no training store wired.

### POST /api/v1/training

`synapse-trainer` registers a run. The Go daemon never launches training
(PROJECT.md §5.4); the trainer runs elsewhere and reports here over HTTP
([ADR 0019](adr/0019-external-training-runs-reported-over-http.md)).

```json
{ "name": "nightly", "recipe": { … }, "epochs_total": 50, "trainer_version": "0.1.0" }
```

`201 {"id": "…", "progress_url": "http://…/api/v1/training/{id}/progress"}`.
`400` bad body, `503` no training store wired.

### POST /api/v1/training/{id}/progress

**One JSON object per request** (a single trailing newline is tolerated, so the
trainer's JSON-line writer works unchanged). An epoch dict is appended to the
run's `history`; a dict whose `"event"` is `"done"` finishes the run and stores
its `"metrics"` object as `final`.

`202`. `400` body is not a JSON object, `404` unknown id, `409` the run has
already finished, `503` no training store wired.

### POST /api/v1/training/{id}/fail

`{ "reason": "cuda oom" }` → `202`, marks the run `failed`. `404` / `409` / `503`
as above.

### Training routes are state-changing and unauthenticated

The three `POST /api/v1/training*` routes inherit the repo's loopback-by-default
posture (PROJECT.md §21) and carry `TODO(#58): gate behind auth/RBAC`, the same
as `POST /api/v1/datasets` and model activation — a trainer on another host would
need a bearer token or mTLS. `TrainingStarted` / `TrainingCompleted` /
`TrainingFailed` are written to `models.directory/audit.log` with
`subject_type: "training"`. There is deliberately no `Training*` event on the
live bus: `event-envelope-v1`'s type enum is frozen and has no such member (see
[ADR 0019](adr/0019-external-training-runs-reported-over-http.md)); the dashboard
updates by polling `GET /api/v1/training/{id}` instead.

### GET /api/v1/audit

The tail of the append-only audit log (`models.directory/audit.log`), **newest
record first** (PROJECT.md §21; issue #36,
[ADR 0022](adr/0022-auditable-model-activation-workflow.md)). This is where an
operator sees who activated which model and when, plus dataset edits and training
history.

| Param | Meaning |
|---|---|
| `limit` | Records to return. Default `100`, clamped to `1000` (`max_limit`). Missing, non-numeric or `< 1` → the default. |
| `subject_type` | Exact match on the subject kind: `model`, `dataset`, `training`, or any type added later. Not validated against a fixed set, so a new subject type is filterable as soon as it is first written. |
| `subject` | Exact match on the subject id — a `model_id`, a `<id>@<version>` dataset ref, or a training-run id. |
| `event` | Exact match on the event name, e.g. `ModelActivated`. |
| `from`, `to` | Inclusive RFC3339 bounds on the record timestamp. A malformed value → `400 bad from` / `400 bad to`; `to` before `from` → `400 bad range`. |

```json
{
  "records": [
    { "ts": "2026-08-31T13:26:25Z", "event": "ModelDeactivated", "actor": "local", "subject_type": "model", "subject": "flow-classifier-v1-demo-0001", "model_id": "flow-classifier-v1-demo-0001", "detail": "restored heuristic as primary" },
    { "ts": "2026-08-31T13:25:56Z", "event": "ModelActivated", "actor": "local", "subject_type": "model", "subject": "flow-classifier-v1-demo-0001", "model_id": "flow-classifier-v1-demo-0001", "detail": "hash=sha256:d8d3e137…" },
    { "ts": "2026-08-31T13:25:35Z", "event": "ModelRegistered", "actor": "local", "subject_type": "model", "subject": "flow-classifier-v1-demo-0001", "model_id": "flow-classifier-v1-demo-0001", "detail": "hash=sha256:d8d3e137… status=registered" }
  ],
  "count": 3,
  "limit": 100,
  "max_limit": 1000,
  "scan_bytes_cap": 8388608
}
```

`model_id` is populated on `subject_type: "model"` lines and empty on every other
subject type; `actor` is `"local"` until RBAC (issue #58). Events written today:
`ModelRegistered` / `ModelActivated` / `ModelDeactivated`, `DatasetCreated` /
`DatasetDerived` / `DatasetDeleted`, `TrainingStarted` / `TrainingCompleted` /
`TrainingFailed`. Human label changes (§21's fourth category) arrive with the
review loop, issue #42, as a new subject type — no change to this route.

**The read is bounded twice.** `limit` caps the records returned, and the reader
seeks backwards from the end of the file and never scans further back than
`scan_bytes_cap` (8 MiB), so the cost of a request does not grow with the log. A
record older than that window stays on disk but is not served here. A torn
trailing line — a crash mid-append — is skipped, not fatal, and a log file that
does not exist yet returns `{"records": []}`.

- `200` — always, including an empty log.
- `400` — a malformed `from` / `to`, or `to` before `from`.
- `503` — no audit logger is wired (distinct from "nothing has happened yet").

### The audit log is append-only, forever

`GET` is the only method routed at `/api/v1/audit`; `POST`, `PATCH` and `DELETE`
return `404` and always will. There is deliberately no way to edit or delete a
record through the API, because an audit trail an operator can curate after the
fact records nothing worth reading (PROJECT.md §21). The only writers are
`internal/audit`'s appenders, driven by a state change that actually happened.
Rotation, if it becomes necessary, is an operator-and-filesystem concern outside
this API and should archive rather than truncate.

Note that the trail is **more** sensitive than most of this API — it is a
timeline of every model that went live and every dataset built or deleted — and
it inherits the same loopback-by-default, unauthenticated posture as the rest of
`/api/v1` until issue #58. Do not expose it beyond localhost before then.

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
- `mode` / `records` / `record_bytes` — for a remote SYNPOIP peer, the sensor mode
  it negotiated (`raw`, `flow`, `feature`) and its record throughput. Omitted for
  a local source, which is always equivalent to `raw`. See
  `GET /api/v1/sensors` for what the modes mean and why `packets` is `0` in the
  record modes (issue #45).
- `sensor_id` / `location` — the **observation point** this source speaks for,
  when it speaks for one. `sensor_id` is exactly the value stamped on every flow
  this source produces, and therefore the value to pass as `sensor=`. Both are
  omitted for a local NIC or a replay, whose flows are attributed to the daemon's
  own name (`local`) — issue #126.

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
    "source_name": "edge-1",
    "mode": "raw",
    "protocol_version": 2,
    "records": 0,
    "record_bytes": 0
  }
]
```

A `feature`-mode sensor looks like this instead — note that every packet counter
is `0`, because no frame crossed the wire at all:

```json
[
  {
    "sensor_id": "edge-fw",
    "location": "wan",
    "mode": "feature",
    "protocol_version": 2,
    "payload_schema": "flow-features-v1",
    "packets": 0,
    "bytes": 0,
    "pps": 0,
    "bps": 0,
    "records": 1176,
    "record_bytes": 508032,
    "state": "running"
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
- `mode` — what this sensor is shipping (issue #45, PROJECT.md §5.3;
  [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md)):
  - `raw` — every captured frame. The default, and the only thing SYNPOIP v1 can
    carry.
  - `flow` — flows aggregated on the sensor, shipped as `flow-record-v1` records.
    The daemon extracts features from them and classifies; it does not rebuild
    the flows.
  - `feature` — only the 48 computed `flow-features-v1` values plus the flow's
    endpoints and timing. **No packet content crosses the wire.** The daemon only
    classifies and stores.
- `protocol_version` — the SYNPOIP version in force: `1` for a v1 sensor, `2` for
  one that negotiated the record frames. `raw` sensors may be either.
- `payload_schema` — the frozen schema id the sensor's record frames conform to
  (`flow-record-v1` / `flow-features-v1`); absent in `raw` mode. The daemon
  refuses a session whose schema it does not implement, so a value here is one it
  has validated.
- `records` / `record_bytes` — flow or feature records received, and the encoded
  payload bytes they arrived as. Both `0` in `raw` mode.

> **Reading the counters in a record mode.** A `flow`- or `feature`-mode sensor
> transfers no packets, so `packets`, `bytes`, `pps`, `bps` and `last_packet`
> stay `0`. That is an accurate statement about the wire, not a missing
> measurement — `mode` is what explains it, and `records` / `record_bytes` are
> the throughput to watch. Health checks that key off `pps` need to consider
> `records` too.

The same `mode`, `records` and `record_bytes` fields appear on the sensor's
`GET /api/v1/captures` row.

A sensor's capture row appears in `GET /api/v1/captures` with
`"kind": "pcap-over-ip-listen"` and `"origin": "collector"`, and is removed when
the connection drops.

### GET /api/v1/sensors/{id}

One sensor by `sensor_id` (or by `source_name`, for a sensor that announced no
id). Same object as above. `404` `sensor not found` if the id is unknown or no
collector is configured.

> A sensor whose id is literally `topology` is shadowed by the route below —
> Go's `ServeMux` prefers the more specific literal pattern. Read it from
> `GET /api/v1/sensors` instead.

### GET /api/v1/sensors/topology

The same sensors, **grouped by the location each one reported** (PROJECT.md
§19.15, issue #46;
[ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)). No params. Always
`200`: with no collector wired it returns an empty grouping with
`"collector": false`, which is deliberately distinguishable from a collector that
simply has nobody connected.

This is a sibling of `GET /api/v1/sensors`, not a replacement — that route is a
flat list several views consume, and grouping is a different question asked of the
same facts. Each sensor row is the **entire** `/api/v1/sensors` object plus one
extra field, `flow_attribution`.

```bash
curl -sS http://127.0.0.1:8080/api/v1/sensors/topology
```

```json
{
  "locations": [
    {
      "location": "dmz",
      "unassigned": false,
      "sensor_count": 1,
      "running": 1,
      "health": "ok",
      "modes": ["raw"],
      "packets": 904156,
      "bytes": 425463469,
      "drops": 0,
      "records": 0,
      "record_bytes": 0,
      "pps": 145730.58,
      "bps": 69424771.67,
      "last_packet": "2026-08-31T15:20:07.613208863Z",
      "attributable_sensors": 1,
      "sensors": [
        {
          "sensor_id": "edge-dmz-1",
          "location": "dmz",
          "mode": "raw",
          "state": "running",
          "flow_attribution": "packets",
          "…": "every other GET /api/v1/sensors field"
        }
      ]
    },
    {
      "location": "wan",
      "unassigned": false,
      "sensor_count": 1,
      "running": 1,
      "health": "degraded",
      "modes": ["flow"],
      "packets": 0,
      "drops": 390655,
      "records": 19,
      "record_bytes": 5510,
      "attributable_sensors": 1,
      "sensors": [
        {
          "sensor_id": "edge-wan-1",
          "location": "wan",
          "mode": "flow",
          "state": "running",
          "flow_attribution": "records",
          "…": "…"
        }
      ]
    }
  ],
  "sensors": 2,
  "location_count": 2,
  "unassigned_sensors": 0,
  "attributable_sensors": 2,
  "packets": 904156,
  "drops": 390655,
  "records": 19,
  "collector": true,
  "scope_sensor_param": "sensor",
  "scope_location_param": "location",
  "local_sensor_label": "local",
  "scope_note": "sensor= and location= match the sensor id stored on every flow and classification. …"
}
```

Per location:

- `location` — **exactly what the sensors reported**, trimmed, or `"unassigned"`
  for the empty bucket. This is the string to send back as `location=`, so a
  client never guesses a spelling. Two locations differing only in case stay
  distinct groups: merging them would mean choosing a spelling no sensor sent.
- `unassigned` — `true` for the bucket holding sensors that reported no location.
  The sensors in it keep their own empty `location`; **no location is invented for
  them**. Named groups come first (sensor count, then name); this bucket is always
  last.
- `sensor_count` / `running` — how many sensors are here, and how many are in
  `state: "running"`.
- `health` — `down` when nothing is running, `degraded` when some sensor is not
  running **or any sensor is dropping**, `ok` otherwise. Drops count because a
  running sensor that is shedding packets is not healthy (§19.14).
- `modes` — the distinct sensor modes in use here, sorted.
- `packets` / `bytes` / `drops` / `records` / `record_bytes` / `pps` / `bps` — sums
  across the group. Remember that a `flow`/`feature`-mode sensor transfers no
  packets, so a group of them reports `0` packets and non-zero `records`.
- `last_packet` — the newest across the group; absent when nothing has arrived.
- `attributable_sensors` — how many of these sensors a `location=` scope can
  actually select. **When this is `0`, `location=<this group>` matches nothing.**

#### `flow_attribution` — read this before offering a scope

The whole point of §19.15 is that clicking a sensor or location scopes the other
views. Every sensor that reports an id is scopeable since issue #126; this field
says by which mechanism, and names the one case that still is not:

| value | meaning |
|---|---|
| `records` | A `flow`- or `feature`-mode sensor. The collector tags its records with the sensor id and the pipeline stores it, so `sensor=`/`location=` filter its flows and classifications. |
| `packets` | A `raw`-mode sensor. Its packets are stamped with its id as they are decoded, and the daemon's flow table is keyed by the observation point, so the flows it builds are attributed to that sensor — and are never merged with another sensor's identical 5-tuple. |
| `none` | The peer reported **no sensor id**. Its rows are indistinguishable from the daemon's own capture and land in `"local"`, so a `sensor=` scope on it would match **nothing**. |

`packets` replaced `none` for raw-mode sensors in #126
([ADR 0030](adr/0030-flow-attribution-scoped-by-observation-point.md)); a client
should treat *anything but `none`* as scopeable rather than testing for
`records`. `attributable_sensors` counts exactly that.

### The `sensor=` and `location=` scope

Two additions to the shared filter vocabulary (issue #46), accepted anywhere the
`class` / `model` / `min_confidence` / `disagreement` dialect is accepted —
`/api/v1/classifications`, `/api/v1/flows`, `/api/v1/hosts/{ip}/flows`,
`/api/v1/hosts/{ip}/classifications`, `/api/v1/review/queue`,
`/api/v1/reports/*` and `/api/v1/matrix`.

- **`sensor=<id>`** — matches the `sensor` stored on a flow and its classification,
  verbatim. Not validated against the connected set, on purpose: a sensor that has
  disconnected still owns its stored rows, and **`sensor=local` is a legitimate
  scope** — since #126 it covers exactly the daemon's own capture (local NIC, PCAP
  replay, and any peer that reported no id), no longer raw-mode sensors.
- **`location=<name>`** — resolved through the *currently connected* sensors,
  because a location lives on the live SYNPOIP session and is not stored on a row.
  Matched exactly as `GET /api/v1/sensors/topology` spelled it.
  **A location no connected sensor reports is a `400`**, not an empty `200` — an
  empty result would be indistinguishable from "that location is quiet".
- Given both, they **intersect**: `sensor=` narrows within `location=`.

```bash
# real scoping — a flow-mode sensor's own traffic
curl -sS 'http://127.0.0.1:8080/api/v1/matrix?sensor=edge-wan-1'
curl -sS 'http://127.0.0.1:8080/api/v1/flows?limit=500&location=wan'
# every locally-captured row, including raw-mode sensors
curl -sS 'http://127.0.0.1:8080/api/v1/classifications?sensor=local&class=brute_force'
# 400 unknown location: no connected sensor reports it
curl -sS 'http://127.0.0.1:8080/api/v1/matrix?location=atlantis'
```

`GET /api/v1/flows` answers the scope from the flow's own `sensor` field (#126).
A row that carries none — written by an embedder, or stored by an older build —
still falls back to a join against the newest 5000 classifications and therefore
drops out of a *scoped* list once its verdict ages out of that window. An
unscoped `GET /api/v1/flows` is unchanged.

### GET /api/v1/matrix

The **traffic matrix**: who talks to whom over the observed hosts (issue #68,
PROJECT.md §19.4-5; [ADR 0026](adr/0026-traffic-matrix-and-sensor-topology.md)).
One entry per ordered `(initiator, responder)` pair, with its flow count, byte
volume and class mix.

> **This is not a full hosts × hosts grid, and it never claims to be.** The host
> map is capped at 2048, which permits ~4.2 million pairs; the daemon tracks at
> most **4096**, discarding the lighter half by `(flows, bytes)` when it overflows.
> What you get is a bounded top-N of the heaviest conversations. `partial`,
> `truncated` and `pairs_evicted` tell you when that bound has bitten.

```bash
curl -sS 'http://127.0.0.1:8080/api/v1/matrix?limit=5&sort=flows'
```

```json
{
  "pairs": [
    {
      "initiator": "10.10.10.22",
      "responder": "10.10.10.21",
      "flows": 426,
      "bytes": 9868837,
      "bytes_fwd": 3409192,
      "bytes_bwd": 6459645,
      "packets": 43191,
      "first_seen": "2026-08-31T08:41:11.068824Z",
      "last_seen": "2026-08-31T08:43:45.850959Z",
      "classifications": 455,
      "classes": [
        { "class": "brute_force", "class_id": 3, "count": 304 },
        { "class": "normal", "class_id": 0, "count": 151 }
      ],
      "dominant_class": "brute_force",
      "threat_class": "brute_force",
      "threat_count": 304,
      "disagreements": 0
    }
  ],
  "initiators": [{ "ip": "10.10.10.22", "flows": 659, "bytes": 10184458, "pairs": 7 }],
  "responders": [{ "ip": "10.10.10.21", "flows": 426, "bytes": 9868837, "pairs": 1 }],
  "sort": "flows",
  "source": "incremental",
  "tracked_pairs": 90,
  "returned_pairs": 5,
  "pair_cap": 4096,
  "pairs_evicted": 0,
  "partial": false,
  "truncated": true,
  "total_flows": 1124,
  "total_bytes": 26137565,
  "max_flows": 426,
  "max_bytes": 9868837
}
```

#### Query parameters

| param | meaning |
|---|---|
| `limit` | Maximum pairs returned. Default `100`, clamped to `2000`. A bad or absent value falls back to the default; there is no "all". |
| `sort` | `flows` (default) \| `bytes` \| `last_seen`. Case-sensitive; anything else is a `400`. Every ordering breaks ties on `(flows, bytes, addresses)`, so repeated reads of unchanged state are identical. |
| `from`, `to` | RFC3339 inclusive bounds on the flow's `last_seen`. Either one forces the scan source. `to` before `from` is a `400`. |
| `class` | One `traffic-classes-v1` class. Unknown name → `400`. |
| `model` | A model id that scored the flow. |
| `min_confidence` | `0..1`, or `0..100` as a percentage. Negative or unparseable → `400`. |
| `disagreement` | `true` for model-disagreement pairs only. |
| `sensor`, `location` | The sensor scope above. |

#### Per pair

- `initiator` / `responder` — the ordered pair. `flow.Key` is direction-normalized,
  so the initiator is the side that **opened** the conversation, and `A→B` and
  `B→A` are **separate cells that are never merged**.
- `flows` / `bytes` / `bytes_fwd` / `bytes_bwd` / `packets` — volume, from
  **terminal records only**. A long flow's periodic snapshots carry cumulative
  counters, so adding them would double-count the same bytes (the rule host
  profiles follow, ADR 0016).
- `classifications` / `classes` / `disagreements` — from **every** record,
  snapshot verdicts included, which keeps the mix consistent with
  `GET /api/v1/classifications`. `classes` is ordered by count.
- `dominant_class` — the highest-count class on the pair.
- `threat_class` / `threat_count` — the highest-count class that is **not**
  `normal`, and its count. This is the field to colour a grid by: a pair with 400
  `normal` and 3 `brute_force` verdicts is *dominated* by `normal` but is the cell
  an operator wants to see. Absent when the pair is benign-only.
- A cell is a **host pair, not a host:port pair.** Traffic to `:3306` and `:443`
  between the same two hosts is one cell with a mixed `classes` bar. Use
  `GET /api/v1/hosts/{ip}` or the flow list for the port dimension.

#### Axes and totals

- `initiators` / `responders` — the grid axes, covering **exactly the returned
  pairs** (so a rendered grid has no all-zero row or column), each with its own
  totals within that selection and ordered by them.
- `total_flows` / `total_bytes` — across **every tracked pair**, not just the
  returned ones, so a client can state what share the visible cells cover.
- `max_flows` / `max_bytes` — the largest values among the **returned** pairs: the
  heat scale.

#### Honesty flags — render these

- `source` — `incremental` when the query was unfiltered and answered from the
  bounded table `internal/insight` maintains off the packet path (O(1) per record,
  exact for every pair it still holds). `scan` when any filter was given, in which
  case the matrix is folded on demand from the newest window of stored records —
  the same split `GET /api/v1/timeline` makes, because a table per filter
  combination would be unbounded.
- `scanned` — rows walked by a `scan` query. Absent on `incremental`.
- `partial` — **the answer is incomplete.** Either the pair cap evicted pairs
  (`pairs_evicted > 0`) or a `scan` walked its full 5000-record window, so older
  traffic is not covered. `false` means these pairs are everything in scope.
- `truncated` — `limit=` cut the list. **Independent of `partial`:** a limited view
  of a complete table is truncated but not partial.
- `tracked_pairs` / `returned_pairs` / `pair_cap` / `pairs_evicted` — the raw
  numbers behind those flags. `pairs`, `pair_cap` and `pairs_evicted` also appear
  on `GET /api/v1/status` under `insight`.

A pair evicted by the cap and later seen again **restarts from zero**, so a light
pair's counters can undercount. Heavy hitters are never evicted while they stay
heavy, and the flow log and host profiles remain the systems of record for
anything this derived view drops.

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

A new detection arrives as `AlertCreated`, carrying the whole `Detection` object
so a client needs no follow-up request. It is published **once per new
detection** — a dedup increment sends nothing, which is what keeps the channel
quiet under a scan (issue #117, PROJECT.md §22; see
[`/api/v1/detections`](#get-apiv1detections)):

```json
[
  { "type": "AlertCreated", "ts": "2026-08-31T18:04:11.130Z", "seq": 8812,
    "data": { "id": 12, "ts": "2026-08-31T18:04:11.123456789Z", "last_ts": "2026-08-31T18:04:11.123456789Z",
              "count": 1, "class": "brute_force", "severity": "high", "confidence": 0.983,
              "flow_id": 4231, "flow_ids": [4231], "src_ip": "10.0.0.5", "dst_ip": "10.10.10.21",
              "src_port": 51234, "dst_port": 3306, "protocol": "tcp", "disagreement": false,
              "reason": "brute_force at 98.3% >= 70% threshold",
              "models": [{ "model_id": "heuristic-v1", "role": "primary",
                           "class": "brute_force", "confidence": 0.983 }] } }
]
```

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
