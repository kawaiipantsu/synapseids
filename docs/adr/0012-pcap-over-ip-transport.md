# 0012 — PCAP-over-IP: a framed, authenticated, versioned TLS transport

**Status:** Accepted, 2026-08-31

## Context

Phase 3 (PROJECT.md §6, §26, GitHub issue #31, EPIC #3) calls for a
**PCAP-over-IP** capture source: "a framed authenticated network transport for
streaming capture records from remote systems. Prefer a clearly versioned
protocol. Consider TLS over TCP initially and QUIC later."

This issue is scoped to the **daemon consuming** such a stream as a
`capture.Source`. A full production `synapse-sensor` — raw / flow / feature
modes, reconnect, location identity — is Phase 6 (#43–#45, PROJECT.md §5.3). So
the deliverable is: the wire protocol, the client Source, and a **minimal
reference server** so the feature is testable and demoable end to end.

Constraints are the usual hard ones (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0`, **zero third-party Go dependencies**, clean offline cross-build
to `linux/{amd64,386,arm64,arm}`. `crypto/tls`, `crypto/x509`, `crypto/ecdsa`,
`crypto/subtle` and `encoding/binary` are all stdlib, so a hand-rolled framed
protocol over `*tls.Conn` fits — the same posture as the hand-rolled RFC 6455
server in `internal/wshub`.

## Decision

### The SYNPOIP wire protocol — `internal/capture/pcapoverip`

A small framed protocol over one TLS connection, specified byte-for-byte in
[`PROTOCOL.md`](../../internal/capture/pcapoverip/PROTOCOL.md). `protocol.go` is
the only implementation.

- **Handshake.** `ClientHello` = magic `"SYNPOIP\0"` + `uint16` version + a
  preferred `uint32` link type + a length-prefixed bearer token + a
  length-prefixed JSON metadata blob (`sensor_id`, `filter`, `location`). The
  server replies with a `ServerResponse`: magic + a `status` byte, then on
  accept the negotiated version, the **authoritative** link type, the advertised
  filter and a session id; on reject a code (`unsupported-version`,
  `unauthorized`, `bad-request`, `unavailable`, `link-type-unsupported`) and a
  reason, then it closes.
- **Version rule.** The server accepts `min(client, server_max)` when it still
  supports that version; a client version above the server's max, or below its
  min, is rejected `0x01`. Only v1 exists, so the server accepts exactly
  `version == 1`.
- **Record frames.** `uint8` type (`0x01` packet, `0x02` keepalive, `0x03`
  goodbye) + `uint32` length + payload. A packet payload is a `uint64`
  Unix-nanoseconds timestamp followed by the raw link-layer frame. All integers
  big-endian.
- **Resource caps** (PROJECT.md §21, §28.11). Token ≤ 512 B, metadata ≤ 64 KiB,
  filter/reason ≤ 1 KiB, session id ≤ 128 B, **frame payload ≤ 262208 B**
  (`262144` snaplen ceiling + 64 slack). Every over-cap length is a hard error
  raised *before* the oversized read — a crafted peer cannot make the other side
  allocate the claimed size.
- **Keepalive / idle.** The server emits a `0x02` frame every
  `keepalive_interval` (default 15 s) when idle; the client tears the stream
  down after `read_idle_timeout` (default 60 s) with no frame. Both configurable.
  A `0x03` goodbye, a plain EOF or `close_notify` is a **clean** end — no
  terminal error, the capture-sources row goes to `stopped`.

### `capture.PCAPOverIP` — the client Source

`NewPCAPOverIP(POIPConfig)` validates the config and builds the `*tls.Config`
(TLS 1.2 min; `RootCAs` from `CAFile` or system roots; optional client cert for
mTLS). It **does not dial** — `Packets(ctx)` does, so a sensor that is down at
startup leaves the daemon serving the API in a degraded mode (PROJECT.md §21).

`Packets` dials, runs the handshake, then reads frames → `packet.Decode` → the
packet channel. A decode error is counted, not fatal. A dial failure, auth
reject, TLS verification failure, protocol error or read-idle timeout is a
**single terminal error** on the error channel; the `capture.Manager` flips that
source's row to `state:"error"` and every other source and the pipeline keep
running. **There is no auto-reconnect in this pass** (a tracked follow-up).

`Close()` / context cancellation sends a goodbye, closes the connection, unblocks
the reader and joins the keepalive goroutine — verified leak-free under a
`runtime.NumGoroutine` delta check and `-race`.

`PCAPOverIP` also implements two optional interfaces the Manager now checks:
`ConnLatencyMS()` (the TLS dial + handshake time, surfaced as
`connection_latency_ms`) and `DynamicFilter()` (the sensor-advertised filter,
which overrides the static config label once connected). A local NIC implements
neither, so its row is unchanged.

### Auth / TLS posture and the `authorized` gate

- **Transport:** TLS ≥ 1.2. The client verifies the sensor certificate against a
  pinned `ca_file` or the system roots.
- **Client identity:** a bearer token in the handshake, constant-time compared
  (`crypto/subtle`), never logged. Optional mutual TLS on top.
- **`authorized: true`** is the operator's explicit acknowledgement, required
  for any of: a **non-loopback** sensor address (§21 "remote capture must only
  operate against systems the operator is authorized to monitor"), `insecure_tls`
  (certificate verification off), or a **token-less** connection. Without it,
  `config.validate()` and `NewPCAPOverIP` both refuse to start the source.
- **Secrets stay out of the file** (§23): an inline `token` is a config error;
  the token comes from `token_file` or `SYNAPSE_POIP_TOKEN`. The committed
  example config carries neither.

### The reference server — `synapse-sensor pcap-over-ip`

`synapse-sensor` gains one subcommand:

```
synapse-sensor pcap-over-ip --listen :4789 --from capture.pcap \
    --token-file tok [--cert c.pem --key k.pem] [--client-ca ca.pem] [--speed 1|max|…]
```

It serves SYNPOIP over TLS, sourcing records from a classic-pcap file
(`pcapoverip.PcapFileStream`, a ~90-line stdlib raw-record reader that does not
import `capture`, to avoid an import cycle). With no `--cert`/`--key` it
generates an in-memory ECDSA P-256 self-signed certificate
(`pcapoverip.SelfSignedCert`, also used by the tests) and prints its SHA-256 so a
demo can pin it or run `insecure_tls`. `synapse-sensor` with no subcommand keeps
its "print version / not-implemented" behaviour. This is deliberately the seam
the Phase 6 sensor grows from.

### Why not reuse `capture.decodePCAPStream`

A sibling branch (`feature/tcpdump-and-ssh-capture`) is extracting a shared
`decodePCAPStream(ctx, io.Reader, …)` helper. It is not on `develop` yet, so the
client's read loop decodes frame-by-frame with `packet.Decode` directly. A
follow-up should switch to the shared helper once both land.

## Consequences

- End-to-end demo: `synapse-sensor pcap-over-ip --from testdata/pcap/portscan.pcap`
  on loopback → a `synapsed` `pcap-over-ip` source → `GET /api/v1/captures`
  counts 29 packets with `connection_latency_ms`, `GET /api/v1/classifications`
  returns the port-scan flows as `scan` 0.998. The in-process integration test
  (`internal/capture/pcapoverip_client_test.go`) exercises the same path plus
  version negotiation, bad token, oversized frame, server goodbye, idle timeout,
  context-cancel leak check, mTLS (happy + missing cert) and a
  no-CA verification failure.
- `config.CaptureSource` gains `addr`, `token`/`token_file`, `server_name`,
  `ca_file`, `client_cert_file`, `client_key_file`, `insecure_tls`,
  `authorized`. `Kind` now accepts `"pcap-over-ip"`. `nic` is unchanged and the
  two kinds share one switch, so a merge with the tcpdump/SSH branch is additive.
- No third-party dependency; `crypto/tls` + stdlib compiles for all four Linux
  arches (verified with `make build-linux`).
- **Follow-ups:** client reconnect/backoff with jitter; QUIC; the production
  Phase 6 sensor (flow/feature modes, sensor identity, `/api/v1/sensors`);
  server-side one-capture-to-many fan-out; adopt `capture.decodePCAPStream`;
  a real BPF filter advertised by the sensor instead of the whole capture.
