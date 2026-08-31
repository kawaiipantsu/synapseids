# SYNPOIP — the SynapseIDS PCAP-over-IP transport (v1)

A small framed, authenticated, versioned protocol for streaming raw capture
records from a remote sensor to `synapsed`. It runs over **one TLS connection**
(`crypto/tls`, TLS 1.2 minimum, 1.3 preferred). The daemon is the **client**: it
dials the sensor, authenticates, and reads packet frames. This document is the
authoritative byte layout; `protocol.go` is the only implementation.

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
| `meta`       | `meta_len` bytes  | JSON: `{"sensor_id","filter","location"}`, all optional |

`meta` is advisory: it is echoed into the capture-sources view and never changes
what the server streams.

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

### 2.3 Version negotiation

- The client sends the highest version it supports (`1`).
- The server replies with `min(client_version, server_max)` **if** that is a
  version it still supports, and streams at that version.
- A client version **higher** than the server's maximum → reject `0x01`
  (unknown-higher-version is never silently downgraded past what the client
  asked, but the server also never invents a version above its own max).
- A client version **below** the server's minimum supported → reject `0x01`.

With only v1 defined, the server accepts exactly `version == 1` and rejects
everything else with `0x01`.

## 3. Record frames

After an accept, every message in either direction is a frame:

| field    | type      | notes                                             |
|----------|-----------|--------------------------------------------------|
| `type`   | `uint8`   | `0x01` packet, `0x02` keepalive, `0x03` goodbye  |
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

## 7. Not in v1 (tracked follow-ups)

- **Client reconnect / backoff.** A dropped stream is terminal; the
  capture-sources row shows `error` and an operator restarts it. Phase 6.
- **QUIC transport.** TLS-over-TCP now; QUIC later (PROJECT.md §6).
- **Sensor `flow` / `feature` modes** (PROJECT.md §5.3). v1 is `raw` records
  only.
- **Server-side fan-out of one capture to many clients** with shared paging —
  today each client gets an independent replay/stream.
- Switching the client decode loop to the shared
  `capture.decodePCAPStream` helper once the tcpdump/SSH branch lands it.
