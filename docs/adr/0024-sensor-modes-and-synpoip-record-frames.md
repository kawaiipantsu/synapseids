# 0024 — Sensor modes (`raw`/`flow`/`feature`) and the SYNPOIP v2 record frames

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §5.3 specifies three modes for `synapse-sensor`:

- `raw`: stream packet/capture records;
- `flow`: aggregate into flows remotely;
- `feature`: send only calculated feature vectors.

Only `raw` existed. SYNPOIP v1 (ADR 0012, ADR 0018) carries a `0x01` packet
frame, a `0x02` keepalive and a `0x03` goodbye, and the daemon's data plane
*starts* at packets: `capture.Source` yields `packet.Packet` and `pipeline.Run`
builds flows from them.

Two problems motivate the other two modes, and they are different problems.

**Bandwidth.** A sensor on a constrained WAN link should not ship every frame
when the daemon only needs flow records. On the capture used to validate this
work — 68 814 packets, 1 176 flows — `raw` costs 39 MB on the wire and `flow`
costs 600 KB. Shipping frames to rebuild flows the sensor already built is 65×
more traffic for an identical result.

**Privacy.** A `feature` sensor ships *no packet content at all* — only the 48
derived `flow-features-v1` numbers plus the flow's endpoints and timing. That is
a meaningful, statable property: it is the mode for a link whose traffic is
sensitive, or a site that will permit flow telemetry off-box but not payloads.
It is worth having even where bandwidth is free.

The design questions were: where does each mode join the pipeline; how do new
frame types coexist with v1 peers; how are the payloads bound to their schemas;
and how do remote flow ids become globally unique.

## Decision

### 1. Where each mode joins the pipeline

The data plane stays strictly one-way; the modes differ only in **how far along**
a record enters it.

```
raw      packets ─▶ flow.Table ─▶ features.Extract ─▶ inference ─▶ store + events
flow                             features.Extract ─▶ inference ─▶ store + events
feature                                              inference ─▶ store + events
```

- **`raw`** is unchanged and remains the default. Packets from a
  collector-accepted session join the one merged `capture.Manager` channel that
  the single pipeline goroutine drains.
- **`flow`** joins at feature extraction. The daemon **does not** re-run its flow
  table over an arriving `flow.Record`; doing so would double-count and would
  build flows-of-flows. It extracts features from the record and classifies.
- **`feature`** joins at inference. The daemon runs neither the flow table nor
  feature extraction; it scores the vector the sensor computed and stores the row.

Mechanically, `pipeline.Options.Records` is a second input channel, and
`pipeline.Run` drains it **in the same `select`, on the same goroutine** as the
packet channel. This was chosen over a separate sink goroutine with its own
locking because it preserves the single-goroutine `flow.Table` invariant
(PROJECT.md §22, CLAUDE.md) for free and adds nothing new that has to be made
concurrency-safe. A record's work is the work one local flow closure already
does, so it does not endanger the packet path; and a record arrives once per
flow, not once per packet.

The classify/store/publish tail was factored into one `publish` closure shared by
all three entry points, so there is exactly one place where a verdict is produced
and announced.

Backpressure is deliberate: the collector's send onto the record channel
**blocks** (bounded by context) rather than dropping. Records are precious and
rare; stalling the TLS read applies TCP backpressure to the sensor, which is the
correct way to shed record load. This is the opposite of the event bus, where
dropping is correct because a slow UI must never stall ingestion (§17, §22).

### 2. SYNPOIP v2, negotiated by a capability in the hello metadata

New frame types `0x04` (flow record) and `0x05` (feature record) are a wire-format
change, so this is **v2**, not a v1 capability bolt-on. But the *negotiation*
rides in the ClientHello's JSON metadata, and the fixed `version` field stays at
`1` forever.

The reason is concrete. A v1 server rejects any `version > 1` with
`0x01 unsupported-version` and then closes the connection; there is no in-session
retry. In the reverse-connect posture the sensor is the reconnecting party, so a
v2 daemon that kept proposing `2` would loop against a v1 sensor indefinitely.
Carrying the ceiling as `meta.max_version` turns that failure into a success: a
v1 server decodes the metadata into a struct without the field, drops the unknown
key, and accepts at v1. The fixed field keeps its v1 meaning ("the version I
insist you support") and gains a companion the old code never has to understand.

So: the client sends baseline `1` plus `max_version`; the server answers with
`version = min(ceiling, server_max)`; the accept grows a **mode + payload-schema
tail only when `version >= 2`**, because a v1 client reads a frame header
immediately after `session_id` and would misparse appended bytes.

The rejected alternative was "no version bump, self-describing frames only" —
let the daemon route on the frame type as it arrives. It was rejected because the
daemon must know a session's mode at handshake time to route and display it, and
because the schema binding must be validated once up front rather than inferred
from whichever record happens to arrive first.

A sensor in `flow`/`feature` mode talking to a v1 client is refused with a new
typed reject `0x06 mode-unsupported`, naming the mode. It is **never** silently
downgraded to `raw`: a `feature`-mode sensor quietly shipping packet content
would destroy the exact property the operator selected the mode for. Symmetrically,
a *new* daemon with no record channel wired advertises `max_version: 1`, so it
behaves exactly like an old one.

Compatibility matrix (identical in both postures of PROTOCOL.md §6, which share
`ServeConn`):

| | old sensor (raw only) | new sensor `--mode raw` | new sensor `--mode flow`/`feature` |
|---|---|---|---|
| **old daemon** | v1, raw, byte for byte | v1, raw; no v2 tail | reject `0x06` |
| **new daemon** | v1, raw; capability key ignored | v2, `mode=raw`; same `0x01` frames | v2, mode set, schema-bound |

### 3. The payloads are schema-bound twice

A record must never be misread as a different schema (§28.5-6 — the discipline
`schema.ValidateBundle` already applies to model bundles).

- **Per session:** the v2 accept carries `payload_schema` —
  `"flow-record-v1"` for `flow`, `"flow-features-v1"` for `feature`, `""` for
  `raw`. `pcapoverip.ValidateAccept` checks it before a single frame is consumed
  and **refuses the session** on anything this build does not implement. A future
  `flow-features-v2` sensor is rejected with a clear error, not silently
  misinterpreted.
- **Per frame:** every `0x04`/`0x05` payload opens with a one-byte layout version.
  A mismatch is counted and skipped.

The schema string is *not* repeated in every frame. It is a per-session property,
and ~20 bytes per record of restated constant is precisely the bandwidth these
modes exist to save. The ids themselves are owned by `internal/flow` and
`internal/features`; the transport aliases them (`FlowRecordSchema =
flow.RecordSchemaV1`) and a test asserts it never invents its own.

`flow-record-v1` is a new frozen contract in its own right, and is treated like
one: `internal/flow/wire.go` is the only sanctioned way to read or restore a
`Record`'s private accumulators, and its field order must never be reordered or
re-meant.

### 4. Reuse, not reimplementation

`pcapoverip.Aggregate` runs `internal/flow` and `internal/features` **unchanged**
on the sensor. Two small changes made that possible cleanly:

- `internal/flow/wire.go` exposes `Accumulators` / `WithAccumulators` and
  `WithDerivedKey`. The private accumulators (`pktSizeSum`, `iatSumSq`, …) must
  cross the wire, or `features.Extract` on the daemon would compute different
  means and standard deviations than the sensor did. The normalized `Key` is
  *not* sent — it is recomputed from the endpoints by the same rule
  (`flow.KeyOfEndpoints`), which saves ~40 bytes and cannot disagree.
- `flow.Pacer` extracts the `Table.Tick` cadence (512 packets, or one second of
  capture time) that was previously inline in `pipeline.Run`. The sensor and the
  daemon must expire flows at the same points, or the same capture would draw
  different flow boundaries per mode. Sharing the policy makes drift impossible
  rather than merely unlikely.

`pcapoverip` therefore imports `internal/flow` and `internal/features`. This is a
deliberate, justified crossing of §28.4: SYNPOIP v2 carries *domain records*, and
their byte layout and schema binding are exactly the transport's business. Both
are leaf packages (`flow` → `packet`; `features` → `flow`, `packet`, `schema`), so
the import graph stays a DAG and nothing inverts.

### 5. Flow-id remapping

A sensor's flow ids come from its own per-process counter; they collide across
sensors and across restarts. The daemon remaps **every** arriving record through
its shared `IDGen` and keeps the original as provenance:

- `storage.FlowRecord.sensor_flow_id` — the sensor's id, `0` for local records;
- `storage.FlowRecord.sensor_mode` — `""` local, `"flow"`, `"feature"`.

The vector's `flow_id` is restamped to match the daemon's id. `flow_id` is not a
feature value, so the 48 numbers are never touched.

`sensor_mode` is provenance with teeth: a `feature`-mode row carries no
packet-level detail beyond what `flow-features-v1` encodes, and this field is how
a consumer knows that before reading the counters. The counters themselves are
read back out of the vector (`features.Vector.Counts`, values 0..4) rather than
defaulted to zero, so the row never implies a measurement that did not cross the
wire.

### 6. Operator visibility

`capture.SourceMeta.Mode`, `SourceStatus.mode/records/record_bytes` and
`SensorStatus.mode/protocol_version/payload_schema/records/record_bytes` surface
the mode on `GET /api/v1/captures` and `GET /api/v1/sensors`. In a record mode
`packets`, `bytes`, `pps` and `bps` stay `0` — no frames crossed the wire, which
is a fact, not a gap — and `records`/`record_bytes` are the throughput to watch.
`mode` is what explains it.

## Consequences

**The modes are interchangeable, and that is tested.** `TestSensorModesAgree`
runs a local replay plus all three modes over a real loopback TLS collector and
requires an identical, ordered set of verdicts (tuple, close reason, class,
counters). The manual two-process run agrees: 1 176 flows and 1 176
classifications in every mode, from `raw`, `flow` and `feature` sensors.

**`feature` mode costs more bytes than `flow` mode.** 48 `float64` values are
larger than the accumulators they were derived from: 432 vs 290 payload bytes per
record. `flow` is the bandwidth mode; `feature` is the privacy-and-daemon-CPU
mode. Documenting this honestly matters more than a tidy story where the later
mode wins on every axis.

**Record modes can lose to `raw` on pathological traffic.** The cost is per flow,
so a scan of one-packet flows with minimum-size frames is the worst case — the
break-even is 4-5 packets/flow for `flow` and 6-7 for `feature`. On the committed
`portscan.pcap` fixture (29 packets, 24 flows) the record modes are genuinely
*more* expensive, which is why the unit test asserts the per-record cost the
design controls rather than a total that depends on the fixture.

**Per-record framing is not free.** On the wire each record is its own TLS record
and TCP segment: 511/632 measured bytes against a 295/437-byte payload. Batching
several records per frame is a tracked follow-up.

**A record-mode sensor produces no packet counters.** Anything reading
`packets`/`pps` to decide whether a sensor is healthy needs to consider `records`
too. The `mode` field makes that decidable.

**The dialled (`--listen`) posture does not accept records yet.** The wire format
is posture-independent and `capture.PCAPOverIP` implements the receiving half,
but no config surface wires its record channel, so it advertises `max_version: 1`
and a record-mode sensor it dials is cleanly rejected with `0x06`. Left for #46.

**`flow-record-v1` is now a frozen contract.** Adding a field to `flow.Record`
that the feature layer consumes means adding it to `flow.Accumulators` and the
`0x04` layout — which is a `flow-record-v2`, not an edit.

## References

- PROJECT.md §5.3 (sensor modes), §7 (flow engine), §8 (feature schema),
  §21, §22, §28.4-6, §28.11
- `internal/capture/pcapoverip/PROTOCOL.md` §2.2-2.4, §3.4-3.6, §7, §8
- ADR 0012 (PCAP-over-IP transport), ADR 0014 (reverse connect), ADR 0018
  (daemon-side collector and sensor identity)
- Issue #45, EPIC #6; follow-up #46
