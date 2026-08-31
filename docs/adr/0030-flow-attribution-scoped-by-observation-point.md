# 0030 — Flow attribution: the observation point is part of the flow key

- **Status:** Accepted
- **Date:** 2026-08-31
- **Issues:** #126 (classifications from a remote sensor attributed to `local`),
  #125 (flow-table counters read zero on a sensor-fed daemon)
- **Supersedes the deferral in:** [ADR 0026](0026-traffic-matrix-and-sensor-topology.md)
  ("real sensor attribution for raw mode needs sensor identity on `packet.Packet`
  **and** in `flow.Key` … deliberately deferred")

## Context

The first live-hardware run put an OPNsense sensor (`opnsense-wan`, location
`cph-valby-gw01`) in front of a real WAN link, streaming `raw`-mode packets over
SYNPOIP. Every classification came back labelled with the *pipeline's* configured
sensor name:

```json
{"flow_id":111,"sensor":"local","proto":"TCP","initiator_ip":"87.54.62.131", ...}
```

`GET /api/v1/sensors` knew the sensor perfectly well. The data plane did not.
`GET /api/v1/sensors/topology` reported `attributable_sensors: 0` — honest, but
it meant the `sensor=` / `location=` scoping that §19.15 is built on could never
select a raw-mode sensor's traffic.

Record modes (`flow`, `feature`) were already fine: the collector tags each
record frame with the session's sensor id and the pipeline copies it onto the
classification. Raw mode was not, because raw packets merge into
`capture.Manager`'s single output channel, and neither `packet.Packet` nor
`flow.Key` had anywhere to put the origin. By the time a flow record existed the
provenance was gone.

There is a second, larger problem hiding behind the first, and it is why this is
a data-plane change and not a labelling change. `flow.Key` is the
direction-normalised 5-tuple, and `flow.Table` is keyed on it. **Two sensors
observing the same 5-tuple merge into one flow.** That is latent with one sensor
and immediate with four: the deployment this was found on is about to run WAN,
IoT, DMZ and MGMT sensors on one gateway, where a packet routed between two
monitored segments is *genuinely seen twice*. Merging those two observations
produces one flow with doubled packet counts, doubled byte counts, and a
corrupted inter-arrival distribution — and every feature derived from those
counters is then wrong, silently, with no signal that anything happened.

## Decision

**Sensor identity is part of the flow key. One flow table, keyed by
(observation point, 5-tuple).**

Concretely:

1. `packet.Packet` gains a `Sensor string` field. `packet.Decode` never sets it —
   nothing inside a frame may be trusted to say where it was observed (§28.11).
2. The two SYNPOIP sources stamp it as they decode, where the identity is known
   first hand: the collector-accepted `sessionSource` from the sensor id in the
   accept, the dialled `PCAPOverIP` client from its configured `sensor_id`.
   `capture.Manager` resolves a source's identity once at registration through a
   new `sensorReporter` interface — the same shape as the existing
   `latencyReporter` / `filterReporter` / `modeReporter` — publishes it on the
   source's status row, and stamps any source that reports an identity without
   applying it itself. A local NIC or a replay reports none and stays unstamped.
3. `flow.Key` gains `Sensor string`, set by `KeyOf` from the packet. The
   normalisation rule itself is untouched: `KeyOfEndpoints` still answers the
   5-tuple alone, so a record rebuilt from the wire is byte-identical to what the
   sensor derived.
4. `storage.FlowRecord` gains `Sensor`, alongside the `SensorMode` it already
   had. The pipeline resolves one sensor id per record — the packet's observation
   point, or the record frame's sensor, or this pipeline's configured name — and
   stamps *both* the flow and its classification with it, so the two can never
   disagree.

`flow-features-v1` is untouched. Provenance is metadata on the record, never
input to the model: the vector stays 48 values and the golden test passes with no
`-update`. Putting identity in the feature vector would also be exactly the
host-memorisation §8 forbids.

### Why not one table with provenance only on the record

This was the cheap option: keep one flow per 5-tuple and write the sensor id onto
whichever record comes out. It answers "which sensor saw this" with a coin flip
whenever two sensors see the same conversation, and — much worse — it keeps the
merged counters. A flow whose `fwd_packets` is the sum of two observation points
is not a flow; it is an artefact. Every rate, ratio and inter-arrival feature
computed from it is wrong, and nothing in the output says so. Rejected.

### Why not one flow table per sensor

Also viable, and it gives better isolation: each sensor's evictions are its own.
Rejected on three counts.

- **The cap stops meaning anything.** `capture.max_flows` is a memory bound. Per
  table, N sensors means N × the bound — the daemon's footprint grows with who
  connects. Dividing the cap by the sensor count instead makes an existing
  sensor's capacity shrink when an unrelated one connects, which is worse.
- **The counters fragment.** `/api/v1/status` would have to aggregate N tables,
  and `active` against `max` — the number an operator actually watches — would
  no longer be comparable to anything.
- **More moving parts for the same invariant.** Per-table `Tick` sweeps, per-table
  grace windows, and a map of tables to keep the single-goroutine rule over.
  The key scoping gets the same separation with one map lookup.

### The trade-off this accepts

**Eviction fairness is global, not per sensor.** One table with one cap means a
sensor under a flood can evict another sensor's flows. The eviction rule is
*oldest-idle*, so an actively-updating flow is rarely the victim, and the
`evicted` counter plus the throttled log line make the pressure visible (#69).
But it is a real cross-sensor coupling and it is not solved here. If a
measurement ever shows one sensor starving another, the answer is a per-sensor
reservation inside the one table — not N tables.

**Cost on the packet path.** One string field on `packet.Packet` (a header copy,
no allocation — every packet from a source shares one string) and one extra field
in the map key's hash. Both are constant and neither allocates. `flow.Table`
stays single-goroutine and stays fed from one place: the Manager still merges
into one channel; only the packets are labelled.

**Location is not stored on a row.** `location=` still resolves through the
*currently connected* sensors, as before. A location that no connected sensor
reports is a 400 rather than a silently empty 200. Storing location per row would
make historical location scoping work after a sensor disconnects; that is a
follow-up, not this change.

**An anonymous peer is still unattributable.** A sensor that reports no id has no
value for `sensor=` to match, so its flows fall in with the daemon's own capture
under `local`. The topology response says so: `flow_attribution: "none"`.

## Consequences

- `GET /api/v1/sensors/topology` gains a third `flow_attribution` value,
  `"packets"` — a raw-mode sensor is attributable, but by the packet path rather
  than by tagged records. `"records"` keeps its meaning, `"none"` now means only
  "this peer reported no id". `attributable_sensors` counts everything that is
  not `"none"`, so it is non-zero for the deployment that reported #126.
- `sensor=` / `location=` select real rows for every sensor mode, on
  `/api/v1/flows` as well as `/api/v1/classifications` — `/flows` answers from
  the row's own `sensor` now, falling back to the old verdict join only for a row
  that carries none.
- `"local"` narrows to what it says: this daemon's own capture (NIC, replay, or an
  anonymous peer). It is still a legitimate scope.
- **#125, the same plumbing:** the daemon runs two pipelines with two flow tables,
  and `/api/v1/status` was reading only the replay controller's — a table that
  never runs on a sensor-fed daemon. A `flowStatsHub` now collects both (the
  capture pipeline reports through `pipeline.Options.OnStats`, which was simply
  never wired) and reports their sum. `max` stays the per-table configured cap,
  because that is the limit that is actually enforced.
- A future `flow-features-v2` is free to add sensor-derived *behavioural* context
  if it is ever justified. It must not add identity.
