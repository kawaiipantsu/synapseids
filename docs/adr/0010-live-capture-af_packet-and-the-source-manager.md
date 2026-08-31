# 0010 — Live NIC capture via stdlib AF_PACKET, merged by a source manager

**Status:** Accepted, 2026-08-31

## Context

Phase 3 begins with "local interface capture" (PROJECT.md §6, §26 Phase 3,
GitHub issue #28): `synapsed` must read live traffic from a named network
interface and run it through the very same `packet → flow → features →
inference` pipeline a PCAP replay uses, so the UI behaves identically
(PROJECT.md §6). It also needs the multi-source **Capture Manager** the initial
architecture diagram calls for (PROJECT.md §3), because Phase 3 will add
tcpdump-stream, SSH-tcpdump and PCAP-over-IP sources next and §19.14 wants one
capture-sources view over all of them.

The repo constraints are hard (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0`, **zero third-party Go dependencies**, and a clean offline
cross-build to `linux/amd64`, `linux/386`, `linux/arm64`, `linux/arm` (v7). That
rules out `libpcap`/`gopacket`, `golang.org/x/sys/unix` and `golang.org/x/net/bpf`
— all third-party. The only capture primitive left is a raw `AF_PACKET` socket
through the standard `syscall` package.

Two structural problems:

1. **The flow `Table` is single-goroutine** (`CLAUDE.md`, PROJECT.md §22). N
   live sources produce packets concurrently, but exactly one goroutine may feed
   the table.
2. **`syscall` on Linux has no `AF_PACKET` convenience helpers** — no
   `SetsockoptPacketMreq`, no `GetsockoptTpacketStats` — and on `386` there is
   not even a direct `SYS_SETSOCKOPT`/`SYS_GETSOCKOPT` (it multiplexes through
   `socketcall`). A hand-rolled raw `setsockopt` would need per-arch assembly-ish
   plumbing.

## Decision

### `capture.AFPacket` — a stdlib-only AF_PACKET source (`afpacket_linux.go`)

`NewAFPacket(AFPacketConfig)` opens
`socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC, htons(ETH_P_ALL))`, resolves the
interface index with `net.InterfaceByName`, and then, **in this order**:

- `syscall.AttachLsf(fd, prog)` — attach the optional cBPF filter *before* bind,
  so no unfiltered frame is ever queued (the classic attach-after-bind race is
  eliminated, not just narrowed);
- `syscall.SetsockoptTimeval(fd, SOL_SOCKET, SO_RCVTIMEO, 250ms)` — bounds a
  blocking `Recvfrom` so `Close`/`ctx` cancellation land within 250 ms on an
  idle link;
- `syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ETH_P_ALL),
  Ifindex: idx})`;
- promiscuous mode (when requested): pack the 16-byte `struct packet_mreq`
  (`{int mr_ifindex; u16 mr_type=PACKET_MR_PROMISC; u16 mr_alen; u8 mr_address[8]}`)
  by hand and pass it through **`syscall.SetsockoptString`** — which is just
  `setsockopt(fd, level, opt, ptr, len)` and is implemented per-arch by the
  stdlib (socketcall on 386 included).

The read loop `Recvfrom`s into one reusable `snaplen`-sized buffer (default
262144), decodes each frame with the existing
`packet.Decode(packet.LinkEthernet, time.Now().UTC(), buf[:n])`, counts decode
errors, and never panics on attacker-controlled bytes (PROJECT.md §28.11).
`packet.Packet` holds no slice into the frame, so the buffer is safe to reuse.

**Kernel drops** are surfaced. `capture.Stats` gains a `Drops uint64` field
(`PCAPFile` leaves it 0). `AFPacket.Stats()` reads `PACKET_STATISTICS` and folds
`tp_drops` into a running total (the kernel resets the counter on every read).
stdlib has no getsockopt for an arbitrary struct, so this **reuses
`syscall.GetsockoptIPMreqn`**: its 12-byte buffer is large enough for
`struct tpacket_stats {u32 tp_packets; u32 tp_drops}`, and `tp_drops` lands in
the second 4-byte field (`IPMreqn.Address`). Ugly but honest, stdlib-only, and
byte-for-byte identical on all four arches — no raw `Syscall`, no per-arch code.

**Least privilege** (PROJECT.md §21): opening the socket needs `CAP_NET_RAW`;
promiscuous mode needs `CAP_NET_ADMIN`. On `EPERM`/`EACCES` the error names the
capability and points at `setcap` and the `contrib/systemd` unit (which already
grants both via `AmbientCapabilities`). Running as root is never required.

Non-Linux builds get `afpacket_other.go`: `NewAFPacket` returns
`errUnsupportedPlatform`. Every release target is `linux/*`; the stub only keeps
the tree building on a macOS dev box.

### `capture.Manager` — fan-in to one goroutine (`manager.go`, all platforms)

`Manager` holds named sources (`Add`/`Remove`/`List`/`Get`) and **is itself a
`capture.Source`**. `Packets(ctx)` starts one forwarder goroutine per source
that copies packets from `src.Packets(ctx)` into **one shared output channel**;
`pipeline.Run` consumes that single channel, so the flow `Table` is still fed
from exactly one goroutine. Channel sends are safe from many goroutines, so the
fan-in is race-clean (verified under `-race`).

A source that emits a terminal error is **isolated**: its `SourceStatus.State`
flips to `"error"` with the message, its forwarder drains and exits, and every
other source and the pipeline keep running. A source's own error is never
forwarded on the aggregate error channel — that channel only closes on full
shutdown — so one bad source can never terminate the pipeline (PROJECT.md §22).

`SourceStatus` carries what §19.14 asks for: `state`, `pps`, `bps`, `drops`,
`last_packet`, `filter`, `error`, plus `name`/`kind` and a
`connection_latency_ms` (0 for a local NIC). `pps`/`bps` are computed by the
Manager from each source's `Stats()` sampled once a second, off the packet path
(PROJECT.md §22).

**Replay is untouched.** The `replayController` stays a separate one-shot path;
the Manager owns live NIC sources. The daemon runs *two* pipelines (replay and
live capture) that share one `IDGen`, so flow IDs stay globally unique
(`CLAUDE.md`). `/api/v1/status`'s `flow` object still comes from the replay
controller; live-capture flow-table stats via the Manager are a follow-up.

### cBPF filters only — no expression compiler

`AFPacketConfig.Filter` accepts `""` (everything) or a **built-in preset name**
(`ip`, `ip6`, `ip-any`, `not-arp`) whose cBPF program is a handful of
hand-assembled `syscall.SockFilter` instructions. A full tcpdump-style
filter-expression compiler is **deliberately out of scope** and tracked for a
follow-up (#29+). Pulling in a BPF-compiler dependency is forbidden (§28.16).

`syscall.AttachLsf` is marked deprecated by staticcheck in favour of
`golang.org/x/net/bpf`; that is third-party, so the call carries a `//nolint`
with this reasoning. It is a thin, stable `SO_ATTACH_FILTER` wrapper.

## Consequences

- Live capture is a real vertical slice: `synapsed --capture lo` (or
  `capture.sources[]` in the JSON config, or `SYNAPSE_CAPTURE_IFACE`) →
  `/api/v1/captures` shows the source counting packets, bytes, pps/bps and
  kernel drops → `/api/v1/classifications` shows flows built from live traffic.
- If a source cannot open (missing capability, no such interface) the daemon
  logs a clear line and keeps serving the API in a degraded mode; it never
  crashes (PROJECT.md §21).
- The `GetsockoptIPMreqn`/`SetsockoptString` reuse is a wart. If the stdlib ever
  grows real `AF_PACKET` helpers, or the zero-dependency rule is relaxed for
  `golang.org/x/sys/unix`, both should be revisited.
- `AF_PACKET` without an `mmap` RX ring is a `recvfrom`-per-packet syscall. It is
  fine for a workstation/lab sensor; a high-rate sensor will want `PACKET_RX_RING`
  (or `AF_XDP`), tracked for later.
- Non-Ethernet link types (Linux SLL, raw tunnels) currently decode-error and
  are counted, not handled. Follow-up.
- Runtime add/remove of sources over REST (`POST`/`DELETE /api/v1/captures`) is
  left for the capture-sources UI (#32); `Manager.Add`/`Remove` already exist.
