# SYNPOIP — the SynapseIDS PCAP-over-IP transport (v1, v2)

A small framed, authenticated, versioned protocol for streaming capture records
from a remote sensor to `synapsed`. It runs over **one TLS connection**
(`crypto/tls`, TLS 1.2 minimum, 1.3 preferred). The daemon is the **client**: it
dials the sensor, authenticates, and reads frames. This document is the
authoritative byte layout; `protocol.go` and `records.go` are the only
implementation.

**Versions.** v1 carries raw packet frames only. **v2** adds the three sensor
modes of PROJECT.md §5.3 — `raw`, `flow`, `feature` — with two new frame types
(`0x04`, `0x05`), a mode + payload-schema tail on the accept, and a capability
negotiation designed so a v1 peer keeps working byte for byte. See §2.3, §3.4-5
and §8.

All integers are **big-endian**. All strings are UTF-8. There is no compression
and no chunk-level checksum — TLS already provides confidentiality and integrity.

## 1. Connection lifecycle

```
client                                   server (sensor)
  │ tls.Dial ───────────────────────────▶ │
  │ ClientHello ────────────────────────▶ │
  │ ◀──────────── ServerResponse (accept) │   or (reject → close)
  │ ◀──────────── frame (0x01 packet) ─── │
  │ ◀──────────── frame (0x02 keepalive)  │
  │ …                                     │
  │ ◀──────────── frame (0x03 goodbye) ── │   (end of capture / shutdown)
  │ frame (0x03 goodbye) ───────────────▶ │   (client Close / ctx cancel)
  │ tls close_notify ◀─────────────────▶  │
```

## 2. Handshake

### 2.1 ClientHello (client → server), variable length

| field        | type       | notes                                                        |
|--------------|------------|-------------------------------------------------------------|
| `magic`      | `[8]byte`  | `"SYNPOIP\0"` (`0x53 59 4E 50 4F 49 50 00`)                 |
| `version`    | `uint16`   | protocol version the client proposes; **1**                 |
| `link_type`  | `uint32`   | preferred libpcap DLT (`1` EN10MB, `101` RAW); `0` = any    |
| `token_len`  | `uint16`   | bearer-token length, `≤ 512`                                |
| `token`      | `token_len` bytes | bearer secret; carried only inside TLS, never logged |
| `meta_len`   | `uint32`   | metadata JSON length, `≤ 65536`; `0` allowed                |
| `meta`       | `meta_len` bytes  | JSON: `{"sensor_id","filter","location","max_version"}`, all optional |

`meta` is advisory with **one** exception: `max_version` (added in v2) is the
client's capability advertisement and does change what the server may send. The
rest is echoed into the capture-sources view and never changes what the server
streams. An unknown key is ignored by both ends, which is what makes `meta` a
usable extension point at all.

`version` in the fixed header stays at **1** forever. See §2.3 for why.

### 2.2 ServerResponse (server → client)

Fixed prefix:

| field    | type      | notes                                    |
|----------|-----------|------------------------------------------|
| `magic`  | `[8]byte` | `"SYNPOIP\0"`                            |
| `status` | `uint8`   | `0x00` = accept; non-zero = reject code  |

**On accept (`status == 0x00`):**

| field         | type              | notes                                          |
|---------------|-------------------|-----------------------------------------------|
| `version`     | `uint16`          | negotiated version, `≤` the client's proposal |
| `link_type`   | `uint32`          | **authoritative** DLT for every packet frame  |
| `filter_len`  | `uint16`          | advertised filter length, `≤ 1024`            |
| `filter`      | `filter_len` bytes| human-readable capture filter, `""` = all     |
| `session_len` | `uint16`          | session-id length, `≤ 128`                    |
| `session_id`  | `session_len` bytes | server-assigned id, for log correlation     |

**v2 tail — present if and only if `version >= 2`:**

| field         | type              | notes                                          |
|---------------|-------------------|-----------------------------------------------|
| `mode`        | `uint8`           | `0x00` raw, `0x01` flow, `0x02` feature       |
| `schema_len`  | `uint16`          | payload schema id length, `≤ 128`             |
| `payload_schema` | `schema_len` bytes | `""` for raw, `"flow-record-v1"` for flow, `"flow-features-v1"` for feature |

A v1 client reads frames immediately after `session_id`, so these three fields
would be misparsed as a frame header. They are therefore written **only** when
the client asked to be upgraded and the server answered with `version = 2` — the
negotiation in §2.3 guarantees that never happens to a v1 client.

The receiver validates the tail before consuming a single frame
(`ValidateAccept`): an unknown `mode`, a mode below its minimum version, or a
`payload_schema` this build does not implement is a **hard refusal**, not a
best-effort read. A future `flow-features-v2` sensor is rejected with a clear
error rather than silently misinterpreted (PROJECT.md §28.5-6 — the same
discipline `schema.ValidateBundle` applies to a model bundle).

**On reject (`status != 0x00`):**

| field        | type              | notes                        |
|--------------|-------------------|------------------------------|
| `reason_len` | `uint16`          | reason length, `≤ 1024`      |
| `reason`     | `reason_len` bytes| human-readable, may be empty |

The server closes the connection immediately after a reject.

Reject codes:

| code   | name                    | meaning                                            |
|--------|-------------------------|---------------------------------------------------|
| `0x01` | `unsupported-version`   | client proposed a version the server cannot speak |
| `0x02` | `unauthorized`          | missing or wrong bearer token                     |
| `0x03` | `bad-request`           | malformed or oversized handshake                  |
| `0x04` | `unavailable`           | server shutting down / at capacity                |
| `0x05` | `link-type-unsupported` | client demanded a DLT the sensor cannot provide   |
| `0x06` | `mode-unsupported`      | sensor is in `flow`/`feature` mode and the client offered only v1 |

### 2.3 Version negotiation

The client declares a **baseline** and a **ceiling**:

- the baseline is the fixed `version` field of the ClientHello, and is always
  `1`;
- the ceiling is `meta.max_version`, omitted when the client speaks only v1.

The server picks `version = min(max(baseline, ceiling), server_max)` and puts it
in the accept. That version is in force for the whole session and decides
whether the accept carries the §2.2 v2 tail and whether `0x04`/`0x05` may appear.

Rejections:

- a **baseline** above the server's maximum → reject `0x01`
  (`unsupported-version`). The server never invents a version above its own max;
- a baseline below the server's minimum supported → reject `0x01`;
- a sensor configured for `flow`/`feature` mode whose negotiated version is
  below `2` → reject `0x06` (`mode-unsupported`), with a reason naming the mode.
  It is **never** silently downgraded to `raw`: a `feature`-mode sensor quietly
  shipping packet content would destroy the exact property the operator chose
  the mode for.

#### Why the ceiling rides in the metadata

The obvious design — bump the fixed `version` field to `2` — does not work. A v1
server rejects any `version > 1` outright (`0x01`), and after a reject the
connection is closed, so there is no way to retry at a lower version inside the
same session. In the reverse-connect posture (§6) the sensor is the one that
reconnects, so a v2 daemon that kept offering `2` would loop against a v1 sensor
forever.

Carrying the ceiling in the hello metadata inverts that failure into a success:
a v1 server decodes the metadata JSON into a struct without the field, drops the
unknown key, accepts at version 1, and streams raw frames exactly as before. The
fixed `version` field keeps its v1 meaning — "the version I insist you support"
— and gains a companion meaning nothing older has to understand.

This is a version bump *of the wire format* with a capability flag *as the
negotiation carrier*. The alternative — no version bump, self-describing frames
only — was rejected because the daemon must know a session's mode at handshake
time to route it and to display it, and because the schema binding has to be
validated once up front rather than inferred from the first record that arrives.

### 2.4 Compatibility matrix

"old" is a SYNPOIP v1 build; "new" is this one. The matrix is identical in both
postures of §6, because both run the same `ServeConn` / client-handshake code.

| | old sensor (raw only) | new sensor, `--mode raw` | new sensor, `--mode flow`/`feature` |
|---|---|---|---|
| **old daemon** (no `max_version`) | v1, raw. Byte for byte unchanged. | v1, raw. No upgrade is forced; the accept has no v2 tail. | **reject `0x06`**, reason names the mode. Operator upgrades the daemon or the sensor's mode. |
| **new daemon** (`max_version: 2`) | v1, raw. The capability key is ignored, the v1 accept is returned, the daemon reads `0x01` frames. | v2, `mode = raw`, `payload_schema = ""`. Same `0x01` frames as v1. | v2, `mode = flow`/`feature`, schema-bound. `0x04`/`0x05` frames. |

Two further guarantees:

- a **v1 daemon that somehow receives `0x04`/`0x05`** behaves as it always did
  for an unrecognised type: the frame is read, its length respected, and it falls
  through the type switch without effect. Only a mode it negotiated can produce
  those frames, so this is a belt-and-braces property, not a path;
- a **new daemon with nowhere to put records** (no record channel wired) offers
  `max_version: 1`, which makes it behave exactly like an old daemon — a
  record-mode sensor gets the clean `0x06` reject instead of streaming into a
  void.

## 3. Record frames

After an accept, every message in either direction is a frame:

| field    | type      | notes                                             |
|----------|-----------|--------------------------------------------------|
| `type`   | `uint8`   | `0x01` packet, `0x02` keepalive, `0x03` goodbye, `0x04` flow record, `0x05` feature record |
| `length` | `uint32`  | payload length, `≤ 262208` (`262144 + 64`)       |
| `payload`| `length` bytes | see below                                   |

A frame that declares `length > 262208` is a **protocol error**: the receiver
drops the connection and never allocates the claimed size (crafted-input
defence, PROJECT.md §21, §28.11). `262144` is the same snaplen ceiling the pcap
file readers enforce; the `+64` is slack for the timestamp prefix.

### 3.1 `0x01` packet

| field       | type     | notes                                   |
|-------------|----------|-----------------------------------------|
| `ts_unixns` | `uint64` | capture timestamp, nanoseconds since epoch |
| `frame`     | rest     | raw link-layer bytes for `link_type`    |

The client decodes `frame` with `packet.Decode(link_type, ts, frame)`. A decode
failure is counted (`decode_errors`) and skipped, never fatal.

### 3.2 `0x02` keepalive

Payload is **empty**, or exactly **16 bytes**:

| field     | type     | notes                                    |
|-----------|----------|------------------------------------------|
| `packets` | `uint64` | records the sender has produced so far   |
| `drops`   | `uint64` | sender-side kernel drop counter (may be 0) |

Sent by the server every `keepalive_interval` (default 15 s) when no packet has
gone out; the client may send empty keepalives at the same cadence. Any received
frame — keepalive included — resets the peer's read-idle timer.

### 3.3 `0x03` goodbye

Payload is an optional UTF-8 reason. Either peer may send it to end the stream
cleanly:

- server → client: `"end of capture"`, `"server closing"`, `"source error: …"`.
- client → server: `"client closing"` on `Close()` / context cancellation.

A goodbye (or a plain EOF / `close_notify`) is a **clean** end — the client
reports no terminal error, and the capture-sources row goes to `stopped`.

### 3.4 `0x04` flow record (v2, `mode = flow`)

One remotely-aggregated flow, emitted as it snapshots or closes. Schema
`flow-record-v1`, owned by `internal/flow`. Fixed layout, big-endian; **290
bytes** for an IPv4 flow, 314 for IPv6.

The payload carries the flow's *private accumulators* as well as its counters, so
`features.Extract` on the daemon yields bit-identical values to what the sensor
would have computed. That is what makes `flow` mode a transport optimisation
rather than a behaviour change.

| field | type | notes |
|---|---|---|
| `layout_version` | `uint8` | `1`. A mismatch is counted and skipped. |
| `proto` | `uint8` | IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6) |
| `reason` | `uint8` | `1` snapshot, `2` fin_rst, `3` idle, `4` max_lifetime, `5` capture_end, `6` evicted. Never renumbered. |
| `reserved` | `uint8` | must be `0`; a non-zero value is refused |
| `snapshot_index` | `uint32` | |
| `sensor_flow_id` | `uint64` | the **sensor's** id; the daemon remaps it (§8) |
| `first_seen` | `int64` | Unix nanoseconds |
| `last_seen` | `int64` | Unix nanoseconds |
| `init_addr_len` | `uint8` | `0` (unset), `4` or `16`; anything else is refused |
| `init_addr` | `init_addr_len` bytes | initiator address |
| `init_port` | `uint16` | |
| `resp_addr_len` | `uint8` | `0`, `4` or `16` |
| `resp_addr` | `resp_addr_len` bytes | responder address |
| `resp_port` | `uint16` | |
| `fwd_packets`, `bwd_packets` | `uint64` × 2 | |
| `fwd_bytes`, `bwd_bytes` | `uint64` × 2 | IP total length |
| `fwd_payload`, `bwd_payload` | `uint64` × 2 | L4 payload length |
| `pkt_size_min`, `pkt_size_max` | `int32` × 2 | |
| `small_pkts`, `large_pkts` | `uint64` × 2 | |
| `syn`, `ack`, `fin`, `rst`, `psh`, `urg` | `uint64` × 6 | TCP flag counts |
| `initial_window` | `uint32` | |
| `window_count`, `iat_count`, `fwd_iat_count`, `bwd_iat_count` | `uint64` × 4 | accumulator denominators |
| `pkt_size_sum`, `pkt_size_sum_sq` | `float64` × 2 | IEEE-754 bits, big-endian |
| `fwd_size_sum`, `bwd_size_sum` | `float64` × 2 | |
| `window_sum` | `float64` | |
| `iat_sum`, `iat_sum_sq`, `iat_min`, `iat_max` | `float64` × 4 | seconds |
| `fwd_iat_sum`, `bwd_iat_sum` | `float64` × 2 | seconds |

The normalized 5-tuple `Key` is **not** sent: it is recomputed on the daemon from
the initiator/responder endpoints by the same rule (`flow.KeyOfEndpoints`) the
local table applies to a packet, which saves ~40 bytes per record and cannot
disagree.

### 3.5 `0x05` feature record (v2, `mode = feature`)

One `flow-features-v1` vector plus the minimum flow identity needed to store and
render a row. **No packet content whatsoever.** Fixed layout, big-endian; **432
bytes** for an IPv4 flow, 456 for IPv6.

| field | type | notes |
|---|---|---|
| `layout_version` | `uint8` | `1` |
| `proto` | `uint8` | IP protocol number |
| `reason` | `uint8` | as §3.4 |
| `reserved` | `uint8` | must be `0` |
| `snapshot_index` | `uint32` | |
| `sensor_flow_id` | `uint64` | the sensor's id; remapped by the daemon |
| `first_seen` | `int64` | Unix nanoseconds |
| `last_seen` | `int64` | Unix nanoseconds |
| `init_addr_len` / `init_addr` / `init_port` | as §3.4 | |
| `resp_addr_len` / `resp_addr` / `resp_port` | as §3.4 | |
| `value_count` | `uint16` | must equal `48`; checked **before** the `8n`-byte read |
| `values` | `float64` × 48 | the frozen `flow-features-v1` order, IEEE-754 bits |

**Why exactly this identity and no more.** Duration and the forward/backward
packet and byte counts are already feature values 0..4, and both ports are 21 and
22, so re-sending them would be pure waste — the daemon reads them back from the
vector (`features.Vector.Counts`). What is *not* in the vector has to travel
beside it: PROJECT.md §8 deliberately keeps IP addresses out of the feature set,
the vector holds a duration but no wall clock, and features 23..25 collapse ICMP
and ICMPv6 into one indicator. Everything listed above is therefore load-bearing.

A `feature`-mode row is honest about this. `storage.FlowRecord.sensor_mode` is
set to `"feature"`, and the row's counters are exactly the vector's — nothing is
defaulted to zero to imply a measurement that never crossed the wire.

### 3.6 Frame-type / mode matrix

| mode | frames the sensor sends | schema id |
|---|---|---|
| `raw` | `0x01`, `0x02`, `0x03` | — (`link_type` describes the payload) |
| `flow` | `0x04`, `0x02`, `0x03` | `flow-record-v1` |
| `feature` | `0x05`, `0x02`, `0x03` | `flow-features-v1` |

A record frame whose type does not match the negotiated mode is counted as a
decode error and skipped. `link_type` is meaningless in the record modes and is
not used to gate the session.

## 4. Timeouts

| name                | default | effect                                                  |
|---------------------|---------|--------------------------------------------------------|
| dial timeout        | 10 s    | `tls.Dial` deadline                                     |
| handshake timeout   | 10 s    | ClientHello send + ServerResponse read                  |
| keepalive interval  | 15 s    | cadence of `0x02` frames                                |
| read-idle timeout   | 60 s    | no frame of any type within the window → terminal error |
| write timeout       | 10 s    | a single frame write deadline                           |

All are configurable on both ends.

## 5. Security model

- **Transport:** TLS ≥ 1.2 (1.3 preferred). The client verifies the sensor
  certificate against `ca_file` (a pinned PEM) or the host's system roots.
  `InsecureSkipVerify` is available for a self-signed lab sensor but logs a loud
  warning and requires an explicit `authorized` acknowledgement.
- **Client → server auth:** a bearer token in the ClientHello, compared with
  `crypto/subtle.ConstantTimeCompare`. It travels only inside the TLS tunnel and
  is never written to a log.
- **Optional mutual TLS:** the server may set
  `RequireAndVerifyClientCert` with its own client-CA pool; the client presents
  `client_cert_file` / `client_key_file`. Defence in depth on top of the token.
- **Resource caps:** token ≤ 512 B, metadata ≤ 64 KiB, filter/reason ≤ 1 KiB,
  session id ≤ 128 B, frame payload ≤ 262208 B, handshake must complete inside
  the handshake deadline. Every over-cap value is a hard error before the
  oversized read.
- **Untrusted bytes:** frame contents are never trusted; `packet.Decode` is
  bounds-checked and a malformed frame is counted, not a panic (§28.11).
- **Observe only:** the transport streams records one way. It never modifies
  traffic and carries no control channel back to the sensor beyond keepalive and
  goodbye (§28.17).
- **Authorization:** a non-loopback sensor address requires `authorized: true`
  in the daemon config — the operator asserting they are authorized to monitor
  that host (PROJECT.md §21).

## 6. Transport-direction inversion (reverse connect)

§1 draws the daemon as the TCP/TLS dialer. That is a deployment choice, not
part of the wire format. A sensor on a firewall is usually behind NAT, and
opening an inbound hole in the box you are trying to monitor is the wrong
instinct — so `synapse-sensor pcap-over-ip --connect <daemon>` **dials out**
instead.

**The SYNPOIP roles do not invert with the TCP direction.** On the established
TLS connection:

```
sensor (TCP client)                        daemon collector (TCP server)
  │ tls.Dial ────────────────────────────▶ │
  │ ◀──────────────────────── ClientHello  │   the ACCEPTING side still speaks first
  │ ServerResponse (accept) ─────────────▶ │
  │ frame (0x01 packet) ─────────────────▶ │
  │ …                                      │
```

Everything in §2–§4 applies byte for byte. There is no role flag, no extra
handshake field and **no version bump**: v1 clients and v1 servers are the same
code on both sides (`pcapoverip.ServeConn` is the identical per-connection
handler `Serve` runs). The only thing that changed is who opened the socket.

Consequences, all deliberate:

| concern | `--listen` (daemon dials) | `--connect` (sensor dials) |
|---------|---------------------------|-----------------------------|
| TLS server cert | sensor presents | **daemon** presents |
| TLS client cert (mTLS) | daemon presents | **sensor** presents |
| bearer token in ClientHello | daemon presents, sensor verifies | unchanged — daemon presents, sensor verifies |
| sensor identity | `sensor_id` in the hello metadata | the accept's `session_id`, prefixed with the sensor id |
| firewall rule needed | inbound, on the sensor | outbound, on the sensor |

So both ends still authenticate each other: the daemon proves itself with the
bearer token (and its server certificate), the sensor with its client
certificate. `sensor_id` moves from the hello metadata to the `session_id`
field of the accept, because in this direction the sensor is the one answering.

**The daemon side is wired.** A `capture.collector` block in `synapsed`'s config
stands up `capture.Collector`: a TLS listener that accepts sensor connections and,
per accepted connection, runs the **client** half of §2–§4 (it sends the
ClientHello, reads the ServerAccept, then consumes frames) and registers that
peer as its own `capture.Manager` source, removing it when the stream ends. The
peer shows up on `GET /api/v1/captures` with `kind: "pcap-over-ip-listen"` and on
`GET /api/v1/sensors`.

Sensor identity travels in the accept's `session_id`, which `synapse-sensor`
formats as `<sensor_id>|<location>|<agent_version>|<os/arch>` before the
server-appended random suffix — see `pcapoverip.FormatSessionPrefix` /
`ParseSensorIdentity`. That is **not** a wire change: `session_id` is already a
free-form string capped at `MaxSessionIDLen`, every field is sanitised of the
separator and of control bytes, and a prefix with no separator still parses as a
bare sensor id, so the plain `<sensor-id>-<hex>` form older sensors sent keeps
working.

The accept path is bounded (`max_sensors`, default 32, plus a looser cap on
connections still handshaking) and refuses an over-cap peer **before** any TLS or
SYNPOIP work. Note that a typed `ServerReject` is not available to the collector
in this direction — reject codes are a server→client message and here the daemon
is the client — so capacity is signalled by closing the connection; the sensor's
reconnect loop backs off. See ADR 0014 and ADR 0018.

## 7. Sensor modes (v2)

`raw`, `flow` and `feature` are the three modes of PROJECT.md §5.3. They are a
**bandwidth and privacy** choice, not a behaviour change: the same capture must
classify identically whichever mode carried it, and
`TestSensorModesAgree` asserts exactly that against a committed fixture.

| mode | runs on the sensor | crosses the wire | joins the daemon's pipeline at |
|---|---|---|---|
| `raw` | nothing | every captured frame | the flow table (unchanged; the default) |
| `flow` | packet decode + flow engine | one `flow-record-v1` per closed/snapshotted flow | feature extraction — the daemon does **not** re-run its flow table |
| `feature` | packet decode + flow engine + feature extraction | one `flow-features-v1` vector + flow identity | inference — the daemon skips flow *and* feature work |

Both record modes reuse `internal/flow` and `internal/features` unchanged
(`pcapoverip.Aggregate`), with the same `flow.Options` lifecycle and the same
`flow.Pacer` tick cadence the daemon uses. If those diverged, flow boundaries
would diverge and the modes would legitimately disagree.

**The `feature` mode's privacy property.** A `feature`-mode sensor never puts a
byte of packet content on the wire. Frames are decoded, folded into counters,
reduced to the 48 derived `flow-features-v1` numbers and discarded — inside the
sensor process, before the encoder is reached. What leaves the host is the 48
values plus the flow's endpoints, ports, timing and close reason. That is
enforced by construction: `Aggregate` in `ModeFeature` hands the encoder a
`FeatureRecord`, which has no field a frame could occupy. It is the right mode
for a link where the traffic itself is sensitive, or where an operator will
permit flow telemetry off-box but not payloads.

**Bandwidth.** `raw` costs bytes per *packet*; the record modes cost a fixed 295
(flow) / 437 (feature) bytes per *flow*, SYNPOIP framing included. Which is
cheaper is a property of the traffic, not of the protocol.

Measured end to end at the loopback interface — so including TLS and TCP
overhead — for a 68 814-packet, 1 176-flow nmap capture:

| mode | bytes on the wire | per unit | share of `raw` |
|---|---|---|---|
| `raw` | 39 343 501 | 572 B/packet | 100 % |
| `flow` | 600 510 | 511 B/record | **1.53 %** (65× less) |
| `feature` | 743 609 | 632 B/record | **1.89 %** (53× less) |

A repeat run gave 1.37 % and 1.80 %. The interface counter also sees unrelated
loopback traffic, so treat the percentages as ±10 %; the per-record SYNPOIP
payload (295 / 437 B) is exact and fixed by the layout.

The break-even is around 4-5 packets per flow for `flow` mode and 6-7 for
`feature` mode with minimum-size frames, and well under one packet per flow with
full-size ones. A SYN scan of one-packet flows is the worst case for the record
modes and they can lose there; ordinary traffic is the table above.

Two things worth knowing. First, `feature` records are *larger* than `flow`
records — 48 `float64` values cost more than the accumulators they were derived
from — so `feature` is chosen for privacy and daemon CPU, `flow` for bandwidth.
Second, the per-record cost on the wire (511/632 B) exceeds the SYNPOIP payload
(295/437 B) because each record is written as its own TLS record and TCP segment;
batching several records per frame is a listed follow-up in §8.

**Flow ids.** A sensor's flow ids come from its own per-process counter and would
collide across sensors and restarts. The daemon remaps every arriving record
through its shared `IDGen` and keeps the original in
`storage.FlowRecord.sensor_flow_id` (CLAUDE.md: flow ids must be globally unique
across the daemon's lifetime). The vector's `flow_id` is restamped to match;
`flow_id` is not a feature value, and the 48 values are never touched.

## 8. Not yet (tracked follow-ups)

- **Client reconnect / backoff** for the dialled posture. A dropped stream is
  terminal; the capture-sources row shows `error` and an operator restarts it.
- **QUIC transport.** TLS-over-TCP now; QUIC later (PROJECT.md §6).
- **Record modes on the dialled (`--listen`) posture.** The wire format is
  posture-independent and `capture.PCAPOverIP` implements the receiving half, but
  no config surface wires its record channel yet, so a dialled source advertises
  `max_version: 1` and a record-mode sensor it dials is cleanly rejected with
  `0x06`. Issue #46.
- **Record batching.** One record per frame today. Coalescing several flow
  records into one frame would amortise the 5-byte header and compress better.
- **`flow-features-v2` / `flow-record-v2`.** New schema ids, negotiated by the
  same `payload_schema` field; the current one is refused rather than reused.
- **Server-side fan-out of one capture to many clients** with shared paging —
  today each client gets an independent replay/stream.
- Switching the client decode loop to the shared
  `capture.decodePCAPStream` helper once the tcpdump/SSH branch lands it.
