# 0018 — The daemon-side SYNPOIP collector, and real sensor identity

**Status:** Accepted, 2026-08-31

## Context

ADR 0012 built the SYNPOIP transport with the **daemon as the dialer**: a
`capture.sources[]` entry of `kind: "pcap-over-ip"` opens a TLS connection to a
sensor that is listening. ADR 0014 added the opposite deployment posture —
`synapse-sensor pcap-over-ip --connect <daemon>` — because a firewall sensor is
usually behind NAT and punching an inbound hole in the box you are monitoring is
the wrong instinct. It shipped the complete sensor half, exercised against a
**stand-in** collector in `cmd/synapse-sensor/connect_test.go`, and said so
plainly: *"`--connect` has no daemon to connect to yet."*

That is this ADR. GitHub issues **#43** (`synapse-sensor` implementation) and
**#103** (daemon-side collector) are the two halves of one feature — a sensor
that dials out and a daemon that accepts it — so they land together.

Three things were missing:

1. **`synapsed` has no inbound socket for capture.** All four capture kinds
   (`nic`, `tcpdump`, `ssh`, `pcap-over-ip`) open outward or locally; the only
   listener is the HTTP API.
2. **No sensor identity worth the name.** `--sensor-id` existed as a flag and
   became a session-id prefix, but there was no location, no environment
   fallback, no host-derived default, and nothing on the daemon parsed it back.
3. **The daemon has no TLS certificate of its own.** In the reverse direction the
   daemon is the TLS *server*, so it must present one.

The usual hard constraints apply (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0`, **zero third-party Go dependencies**, clean cross-build to
`linux/{amd64,386,arm64,arm}` and `freebsd/{amd64,arm64}`.

## Decision

### 1. The collector is a *listener-shaped* thing, so it gets its own config block

A `capture.sources[]` entry models **one** source that dials one target or opens
one device. A collector is not that: it is a long-lived listener that spawns *N*
sources, one per peer, whose names and count are not known until sensors connect.

Forcing it into `sources[]` as `kind: "pcap-over-ip-listen"` would also have made
`CaptureSource`'s TLS fields mean two opposite things depending on kind —
`ca_file` / `client_cert_file` are *client* material for the dialled
`pcap-over-ip` kind, while a collector needs a *server* certificate and a
*client*-CA pool. Overloading them is exactly the "special case throughout the
codebase" PROJECT.md §2.10 warns about.

So the collector is a distinct `capture.collector` block, and every existing
kind is untouched:

```json
"capture": {
  "collector": {
    "listen": "0.0.0.0:4789",
    "cert_file": "/etc/synapseids/collector.crt",
    "key_file":  "/etc/synapseids/collector.key",
    "token_file": "/etc/synapseids/collector.token",
    "client_ca_file": "/etc/synapseids/sensors-ca.pem",
    "max_sensors": 32,
    "authorized": true
  }
}
```

`listen: ""` (the default) means **disabled** — a fresh install grows no new
listening socket. `config.ValidateCollector` enforces the rest: `host:port`,
`cert_file` **and** `key_file` required, an **inline `token` refused** with the
same sentence the `pcap-over-ip` kind uses (§23 — use `token_file` or
`SYNAPSE_COLLECTOR_TOKEN`), `max_sensors >= 0`, and `authorized: true` required
to enable the collector at all (§28.18: the operator asserts they are authorised
to ingest traffic from the sensors that will connect). `SYNAPSE_COLLECTOR_LISTEN`
overrides the address for deployments that keep it out of the file.

### 2. No wire change. The collector runs the SYNPOIP **client** role.

This is the part most likely to be got backwards, so it is worth stating flatly.

PROTOCOL.md §6 fixes the roles: **on a reverse connection the accepting daemon
still sends the ClientHello**, and the sensor answers with a ServerAccept and
streams packet frames. Only the TCP/TLS dial direction inverts. That is what
makes `--connect` free of a version bump, and it keeps the *data* direction
correct — flipping the SYNPOIP roles too would make the ClientHello sender the
producer, which is the opposite of what every v1 peer means by it.

Consequently the collector is **not** `pcapoverip.ServeConn` (that is the sensor
side, and the sensor keeps running it unchanged). The collector, per accepted
connection, does exactly what `capture.PCAPOverIP` does minus the dial:

```
tls.Listener.Accept  →  tls handshake  →  pcapoverip.ClientHandshake(hello)
                     →  read 0x01/0x02/0x03 frames  →  packet.Decode
```

Not one byte of `protocol.go` changed.

### 3. A peer becomes a `capture.Manager` source

`capture.Collector.serve` wraps the live `*pcapoverip.Session` in a
`sessionSource` — a plain `capture.Source` that streams the frames it is already
handshaken for — and calls `Manager.Add(name, src, SourceMeta{...})`. `Add` and
`Remove` have worked dynamically after `Packets()` since issue #32, so the seam
already existed.

- **Kind** is `pcap-over-ip-listen`, **origin** is `collector`, so
  `GET /api/v1/captures` distinguishes a dialled sensor from one that dialled in.
- **Name** is the sensor id from the handshake, falling back to the remote
  address for an anonymous sensor. Two sensors sharing an id are de-duplicated
  with a short session suffix (`edge-1#a1b2c3d4`) rather than one of them being
  refused — a fleet built from one image should still work.
- Packets flow into the **one merged Manager channel** the single pipeline
  goroutine drains, so the single-goroutine `flow.Table` is still fed from
  exactly one place (§22, CLAUDE.md).
- `sessionSource` exposes `Done()`, closed when its streaming goroutine exits
  (goodbye / EOF / read-idle / cancel). The collector waits on it and then calls
  `Manager.Remove`, so a dropped sensor's row **disappears** rather than
  lingering as `stopped`. It also implements `DynamicFilter()` and
  `ConnLatencyMS()`, so the advertised filter and the accept-time handshake cost
  show up in the existing capture row without the Manager knowing what a sensor
  is.

### 4. Authentication: who proves what to whom

Because the roles do not invert, the bearer token travels **daemon → sensor**.
The issue text asked the collector to "compare the received token with
`crypto/subtle`"; that describes a daemon-as-server design the wire format does
not have, so it is implemented the way the protocol actually works — and the
resulting model is mutual either way:

| direction | mechanism | who verifies |
|---|---|---|
| daemon proves itself to the sensor | TLS **server** certificate + the bearer token in the ClientHello | the sensor, with `crypto/subtle.ConstantTimeCompare` in `pcapoverip.negotiate` |
| sensor proves itself to the daemon | TLS **client** certificate (mTLS) | the collector, via `client_ca_file` → `RequireAndVerifyClientCert` |

So a sensor will not stream to a collector that cannot present the shared token,
and — when `client_ca_file` is set — a collector will not accept a sensor that
cannot present a certificate its CA signed. A wrong token surfaces on the
collector as a typed `*pcapoverip.RejectError` with code `unauthorized`, counted
and dropped without registering anything.

`client_ca_file` is optional but strongly recommended, and it is the *only* thing
authenticating the sensor: without it the collector accepts any peer that
completes TLS. That is why enabling the collector requires `authorized: true`,
and why the startup line prints `mtls=` and `token=` plainly.

### 5. Bounded accept

An unauthenticated remote opening connections is a resource-exhaustion vector
(§21), so the accept path is capped in two tiers:

- **`max_sensors`** (default 32) caps **registered** sensors. The check is on
  `len(peers)`, deliberately *not* on connections in flight — otherwise a stream
  of probes or failed handshakes would starve legitimate sensors, which is a bug
  the first draft actually had and `-race` found.
- **`max_sensors + 16`** caps connections still handshaking, blunting a
  half-open-connection flood.

Past either bound the connection is closed **before** the TLS or SYNPOIP
handshake runs — the cheapest possible refusal, and Go's `tls.Conn` handshakes
lazily so nothing crypto-related has happened yet. There is no typed SYNPOIP
reject available here: `ServerReject` is a server→client message and the
collector is the client. Rejections are counted
(`rejectedCap`/`rejectedTLS`/`rejectedAuth`/`rejectedProto`) and logged.

A collector whose certificate is missing or unreadable logs one clear line and
the daemon **keeps serving the API** — the same degraded-not-dead posture a NIC
source that cannot open already has (§21).

### 6. Sensor identity rides in the accept's `session_id`

In the reverse direction the sensor answers rather than speaking first, so it has
no ClientHello metadata to fill in. PROTOCOL.md §6 already nominated the accept's
`session_id` for this ("prefixed with the sensor id"); this ADR makes that
prefix structured instead of a bare string:

```
session_id = "<sensor_id>|<location>|<agent_version>|<os/arch>" + "-" + <16 hex>
             e.g.  edge-1|wan|0.1.0-dev|freebsd/amd64-c9a0970e81af3ec8
```

`pcapoverip.FormatSessionPrefix` / `ParseSensorIdentity` are the only
implementation. This is **not** a wire change: `session_id` is already a
free-form UTF-8 string capped at `MaxSessionIDLen` (128). Properties that
mattered:

- **Backwards compatible.** A prefix with no `|` parses as a bare sensor id, so
  the `edge-1-<hex>` session ids older sensors sent still work.
- **Bounded.** Each field is clipped to 48 bytes and the whole prefix to
  `MaxSessionIDLen - 24`, so the random suffix always fits. Fields are stripped
  of the separator and of control bytes, so the value is safe to split on and
  safe to put in a log line (§21 "defend against untrusted packet-derived
  strings").
- **Still unique per stream.** The random suffix is untouched, so log correlation
  across reconnects still works.

Alternatives rejected: a JSON blob in `session_id` (unreadable in logs), and
adding fields to the ClientHello `meta` JSON (the daemon sends that message in
this direction, so the sensor cannot use it).

`synapse-sensor` now resolves identity as **flag → env → derived**:
`--sensor-id` / `SYNAPSE_SENSOR_ID` / the hostname; `--location` /
`SYNAPSE_SENSOR_LOCATION`. `agent_version` comes from `internal/version` and
`os/arch` from `runtime`, both for diagnostics. It logs the identity it will
announce before dialling.

### 7. `GET /api/v1/sensors` — the read surface

The collector, not the Manager, holds the identity and the connect time, so it
owns the projection: `Collector.Sensors()` merges its per-peer facts with the
live counters from the matching Manager row (`pps`/`bps`/`state` come from the
Manager's once-a-second sampler; the rest from the source's atomics).

`capture.SensorStatus` carries the JSON tags and `api.SensorStatusProvider` is
the one-method-pair interface the API sees, so `internal/api` never touches a
concrete `*capture.Collector` — the same shape as `CaptureStatusProvider`. The
provider is a **new twelfth parameter to `api.New`**, appended so existing
positional arguments do not move; `nil` means "no collector", which yields `[]`
and a `404` rather than a `503`, so the Sources / topology UI can always render.

It is **read-only**, and deliberately so: a sensor is added and removed by
connecting and disconnecting, not by an API call. It inherits the loopback-only
posture of the rest of the state surface (§21) and the `TODO(#58)` auth gate.

`events.SensorConnected` / `events.SensorDisconnected` — already in the frozen
`event-envelope-v1` enum, so nothing was added — are published from
`cmd/synapsed` via `Collector.OnConnect` / `OnDisconnect` hooks. The hooks exist
so `internal/capture` does not have to import the event bus.

### 8. Daemon TLS material

`synapse-sensor gen-cert` writes a self-signed ECDSA P-256 pair (reusing
`pcapoverip.SelfSignedCert`) and prints its SHA-256, so an operator can stand a
testing collector up without an `openssl` incantation:

```
synapse-sensor gen-cert --host ids.example --cert collector.crt --key collector.key
```

The certificate is its own CA, so the `.crt` doubles as the `--ca` the sensor
pins. That is the whole of it — there is **no certificate-management subsystem**,
and production deployments provision from their own PKI. `docs/api.md` documents
the equivalent `openssl req` for anyone who would rather not run our binary to
make a key.

`synapse-sensor` with no subcommand now prints its build stamp instead of
exiting 1 with a "not implemented" notice.

## Consequences

- `synapse-sensor pcap-over-ip --connect` is **usable end to end** for the first
  time: sensor dials → collector accepts and sends the ClientHello → sensor
  streams → packets reach the flow engine, the classifier and the live UI, and
  the peer shows up on `/api/v1/sensors` and `/api/v1/captures`.
- `PROTOCOL.md` §6's "Not wired yet" paragraph is retired. §6 itself is unchanged
  because the wire format is unchanged.
- The OPNsense plugin can now default to connect mode against a real collector;
  `contrib/opnsense/` notes it. The plugin's own default is left alone in this
  change — flipping it is a plugin-side decision with its own release.
- **Reconnect is asymmetric, on purpose.** The sensor reconnects with capped
  exponential backoff and jitter (ADR 0014); the collector does not need to,
  because it never dials. A dialled `kind: "pcap-over-ip"` source still has no
  reconnect — that gap is unchanged by this ADR.
- A file-backed `--connect` sensor reconnects after end-of-capture and replays
  again. That is the streamer's existing behaviour and is useful for demos, but
  it does mean a short fixture produces a connect/disconnect cycle every few
  seconds; use a live `--iface` or expect the churn.
- `capture.Collector` is a second thing in `internal/capture` that owns a socket
  lifecycle. It stays off the packet path: it does TLS, a handshake, a map
  insert and a `Manager.Add`, then blocks on `Done()`.

**Left for the follow-ups this does not close:**

- **#45 sensor modes.** Still `raw` records only. `flow` and `feature` modes
  (PROJECT.md §5.3) would need the sensor to run the flow engine / feature
  extractor and a second frame type or a second protocol — a real design, not an
  increment.
- **#46 sensor topology** (§19.15). `/api/v1/sensors` is the data feed it needs —
  `location` is carried and surfaced — but there is no grouping endpoint, no
  topology view and no "scope other views to this location" plumbing.
- Per-sensor tokens / a revocation list; today one shared token is presented to
  every sensor and mTLS is what distinguishes them.
- Surfacing the collector's rejection counters on `/api/v1/status`.
- QUIC (ADR 0012's tracked follow-up) and server-side fan-out of one capture to
  many clients.
