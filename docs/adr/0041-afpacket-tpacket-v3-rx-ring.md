# 0041 — Opt-in TPACKET_V3 mmap RX ring for AF_PACKET capture

**Status:** Accepted, 2026-09-02 — implemented as an opt-in `Ring` flag on the
Linux AF_PACKET source (issue #163). The default capture path is unchanged;
making the ring the default remains gated on a measurement (issue #127).

## Context

`internal/capture/afpacket_linux.go` reads one frame per `syscall.Recvfrom`
(ADR 0010). Issue #50 split off #163 to explore `PACKET_RX_RING` / `AF_XDP` for
a NIC where that per-packet syscall is the throughput ceiling. PROJECT.md §22
("correctness and observability before premature micro-optimization") and §26
(Phase 8 "Scale — only when measurements require it") both say capture is not
optimised on spec: #163 carries an explicit prerequisite that a profile shows
the syscall is the bottleneck, and that measurement (#127, on real
FreeBSD/OPNsense hardware) is not available yet.

So the question this ADR answers is *how to land the mechanism without changing
the default*, so that an operator who **has** measured a bottleneck can use it,
and #127 later only has to flip a default.

## Decision

### An opt-in `Ring bool`, off by default

`capture.AFPacketConfig` and `capture.LiveConfig` gain `Ring bool`.
`config.CaptureSource` gains `ring` (JSON, `omitempty`), valid only for
`kind: "nic"` — `ring: true` on any other kind is a load-time error, and FreeBSD
`NewLive` rejects it with a pointer to `buffer_len` (its own store-buffer knob).
Nothing selects the ring unless the operator wrote `ring: true`.

### TPACKET_V3, not TPACKET_V2 or AF_XDP

- **TPACKET_V3** packs variable-length frames into blocks the kernel retires on
  a fill-or-timeout basis, so the amortised cost is one `epoll_wait` per *block*,
  not per frame, and the ring tolerates a bursty consumer. TPACKET_V2 is a
  fixed-slot ring with a per-frame poll and worse memory behaviour.
- **AF_XDP** is faster still but needs a BPF program loaded into the kernel, is
  awkward under `CGO_ENABLED=0` without `x/sys`, and its driver `XDP_ZEROCOPY`
  support is uneven. It stays a possible follow-up; TPACKET_V3 is pure
  `syscall`, works on every NIC, and is enough to remove a per-packet syscall.

### stdlib `syscall` only, hand-packed structs

Consistent with the rest of `internal/capture` (ADR 0010, and the
`PACKET_STATISTICS` reasoning there):

- `syscall` exports `PACKET_RX_RING`, `SOL_PACKET`, `Mmap`/`Munmap`,
  `EpollCreate1`/`EpollCtl`/`EpollWait`, `Getpagesize`. `PACKET_VERSION` (10),
  `TPACKET_V3` (2) and the `TP_STATUS_*` flags are defined locally.
- `struct tpacket_req3` (7 × `unsigned int`) is packed into a 28-byte buffer and
  passed via `SetsockoptString`, exactly as `addPromisc` already does for
  `struct packet_mreq`.
- The block descriptor and `struct tpacket3_hdr` are parsed field by field at
  fixed offsets. Every field the code reads is `u16`/`u32` — no pointer-width or
  alignment-sensitive member — so the layout is byte-identical on
  `amd64`/`386`/`arm64`/`arm`. Cross-builds for all four are in CI.

### Geometry

32 blocks × 1 MiB = a 32 MiB ring; `tp_frame_size` 2048; `tp_retire_blk_tov`
60 ms. 1 MiB is a multiple of every Linux page size (4 KiB / 16 KiB / 64 KiB),
and `blockSz` is rounded up to the page size defensively. 32 MiB is a
deliberate, operator-enabled allocation — large enough to ride out a scheduler
gap near line rate, small enough not to surprise. The retire timeout bounds
latency on a quiet link to roughly the `SO_RCVTIMEO` the Recvfrom path uses, so
the ring does not make an idle capture less responsive.

### Read loop

`readLoop` dispatches to `ringReadLoop` when `a.ring != nil`. The loop drains
every user-owned block at the cursor (walking `tp_next_offset` chains, handing
each frame's `[tp_mac : tp_mac+tp_snaplen]` slice to the same `emit` the
Recvfrom path uses), writes the block status back to `TP_STATUS_KERNEL`, and
only `epoll_wait`s (with the existing 250 ms timeout, so `Close`/ctx stay
responsive) when no block is ready. A block descriptor whose offsets fall
outside the mapping is counted in `Stats.DecodeErr` and ends that block's walk —
never a panic (§28.11). The frame slice aliases the mmap and is valid only for
the `emit` call, identical to the Recvfrom path's shared-buffer contract, so
`RawPackets` still copies and `Packets` still decodes synchronously.

Teardown (`munmap` + close the epoll fd) hangs off the same deferred cleanup in
`start` that closes the socket fd, and off `Close` for the never-started case.

## Consequences

- The default capture path is byte-for-byte unchanged; `ring` is inert unless
  set. No behaviour change ships without an operator opting in.
- `Stats` is unchanged: the ring feeds the same `Packets`/`Bytes`/`DecodeErr`
  counters, and `pollDrops` (`PACKET_STATISTICS`) still works on a V3 socket. A
  ring-specific counter (`tp_freeze_q_cnt`, blocks processed) is a possible
  follow-up.
- The live-open and end-to-end capture tests for the ring need `CAP_NET_RAW`, so
  they are opt-in (`SYNAPSE_NIC_TEST=1`), like `TestAFPacketOpenLive`. The
  block/frame parser (`ringWalkBlock`) is covered by table tests that run in
  plain `make test`.
- **Still open (issue #127):** the measurement that would justify making `ring`
  the default, and an `AF_XDP` path if TPACKET_V3 is not enough on the hardware
  that gets profiled. A `synapse-sensor --ring` flag (the sensor takes the same
  `LiveConfig`) is a small follow-up.
