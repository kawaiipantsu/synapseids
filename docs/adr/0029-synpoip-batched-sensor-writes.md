# 0029 — Batched sensor writes on SYNPOIP: coalesce while backlogged, flush when idle

**Status:** Accepted, 2026-08-31

## Context

An OPNsense WAN sensor in `raw` mode lost **63% of frames to BPF kernel drops**
during a single 5 GB download, with `synapse-sensor` at 81% CPU:

```
  Pid  Netif  Flags     Recv       Drop     Match   Sblen   Hblen  Command
 72884 igc2  p-f----  1455970    916190   1448432  474022  524286  synapse-sensor
```

Both BPF buffers (`Sblen`, `Hblen`) are full. The kernel was batching correctly —
immediate mode had already been turned off in an earlier fix — so this is not a
capture-side problem at all. The **consumer could not drain the buffer**, and
everything that arrived while it was busy was dropped by the kernel.

The consumer is one loop in `internal/capture/pcapoverip/server.go`. Per captured
frame it did:

```go
_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
WriteFrame(conn, FramePacket, PacketFramePayload(rec.TS.UnixNano(), rec.Raw))
```

and `WriteFrame` issues **two** `w.Write` calls, header then payload. `conn` is a
`*tls.Conn`, and crypto/tls emits **one TLS record per Write**, each with its own
`write(2)`. So 1.45 M captured packets became:

- ~2.9 M TLS records (header + MAC + a record-layer pass each),
- ~2.9 M syscalls,
- ~1.45 M `SetWriteDeadline` calls (a runtime poller-deadline update each),
- ~1.45 M heap allocations of ~1.5 KB, because `PacketFramePayload` builds a
  fresh timestamp-prefixed copy of every frame before writing it.

That per-frame overhead — not AES; the box has AES-NI — is what pinned the CPU.

The obvious alternative, dropping TLS, was rejected: PROJECT.md §21 requires TLS
for remote sensors, and the measurement above says the cipher was never the cost.

## Decision

**Batch the outbound frames of one connection into a `bufio.Writer` and flush the
moment the source has nothing else ready.** The bytes on the wire are unchanged,
byte for byte; only the TLS record and syscall boundaries move. No wire format,
no protocol version, no schema is touched.

`internal/capture/pcapoverip/framewriter.go` adds an unexported `frameWriter`
owned by the server loop (which is already single-goroutine, so it needs no
lock), with five properties:

### 1. A 64 KiB buffer

64 KiB is four times crypto/tls's 16 KiB maximum record, so a full buffer still
amortises into a handful of maximum-size records; it holds ~42 MTU-sized frames
or ~1000 small ones. Larger buys nothing — a TLS record is capped at 16 KiB
regardless — and costs latency headroom and per-client memory. It is
`ServerConfig.WriteBufferSize`, defaulting to `DefaultWriteBufferSize`.

### 2. Batch while backlogged, flush when idle

After writing a frame the loop does a **non-blocking receive** on the record
channel. That succeeds only if a record is *already* waiting — buffered, or a
sender blocked on an unbuffered channel — so:

- a **saturated** link coalesces its backlog into one flush, and
- a **quiet** link never sits on a packet: with nothing else ready the `default`
  arm fires and the frame is on the wire before the loop iteration ends.

This is the property most likely to regress, so it is tested end to end over real
TLS (`TestIdleLinkFlushesEveryFrame`) with the keepalive interval and the write
timeout set to 10 minutes: nothing but the idle flush can deliver a frame inside
the client's 2 s read deadline. Measured delivery latency on loopback is
**29–55 µs**. PROJECT.md §17 and §22 are the reason this is a hard requirement
rather than a nice-to-have: the live UI is the product, and a batched packet is
an invisible packet.

### 3. One write deadline per batch

The deadline is armed once when a batch opens, not once per frame, and it covers
every write the batch makes — including the implicit flushes `bufio` performs
when the buffer fills.

### 4. Control frames flush; so does every return path

A keepalive or goodbye is written **and flushed**, which also pushes out whatever
was queued behind it. A lost goodbye or a truncated final frame would be a
correctness bug, not a latency one, so `serveConn` also carries a deferred flush
that runs before the deferred `conn.Close`, covering error paths and any future
`return` nobody remembers to annotate.

### 5. A bounded batch

Two bounds stop data sitting in the buffer under any traffic shape:

- **age**: a batch older than `WriteTimeout/2` is flushed and re-armed at the
  next frame (the clock is read once per 64 frames, not per frame). Half the
  timeout, so a batch always ends well before the deadline armed at its start
  could expire — batching can never turn a healthy peer into a write timeout;
- **count**: `maxBatchFrames` (1024) returns control to the server's `select`, so
  a permanently backlogged source cannot starve the keepalive ticker or the
  cancellation check.

### 6. `writePacketFrame`: no intermediate payload

The hot path writes the 5-byte frame header and the 8-byte timestamp from one
reusable 13-byte scratch array, then the raw frame, instead of allocating a
`PacketFramePayload` copy per packet. The emitted bytes are identical — a test
pins them against `WriteFrame(w, FramePacket, PacketFramePayload(ts, raw))` —
and per-packet allocation on the packet path disappears (§22).

## Measured

`BenchmarkSensorWrites{Unbatched,Batched}`, 10 000 × 1514-byte frames, counting
`io.Writer` (Go 1.27, i9-13900H):

| | Write calls | SetWriteDeadline | wire bytes | ns/op | allocs/op | B/op |
|---|---|---|---|---|---|---|
| before | 20 000 | 10 000 | 15 270 000 | 4 726 280 | 20 002 | 15 413 653 |
| after | **235** | **10** | **15 270 000** | **488 225** | **4** | **65 808** |

85× fewer Write calls, 1000× fewer deadline updates, **identical bytes**, and the
benchmark asserts that byte count rather than trusting it.

The same 10 000 frames through a real `*tls.Conn` on loopback
(`BenchmarkSensorWritesOverTLS*`):

| | ns/op | throughput | allocs/op |
|---|---|---|---|
| before | 74 321 786 | 205 MB/s | 20 023 |
| after | **7 039 168** | **2169 MB/s** | **3** |

**10.6× more sensor throughput per CPU-second** with TLS in the loop, which is
the number that decides whether the BPF buffer drains.

## Consequences

- A frame may now leave the sensor as part of a larger TLS record. Nothing
  observes record boundaries: `FrameReader` is a length-delimited stream reader.
- A batch shares one write deadline. A stalled peer still fails inside
  `WriteTimeout`, and the age bound keeps a batch from consuming that window.
- One more 64 KiB buffer per connected client. A sensor serves one daemon (a
  handful at most), against a 512 KiB BPF buffer — negligible.
- The `flow` and `feature` record modes get the same treatment for free; their
  bursts (a flow table flushing many closed flows at once) coalesce too.

### The collector's read side was checked and deliberately left alone

`FrameReader` does issue two `Read` calls per frame, and on a bare socket those
would be two syscalls. But every SYNPOIP connection is a `*tls.Conn`, and
crypto/tls reads a whole record — up to 16 KiB — into its own buffer and serves
subsequent `Read`s from it **without a syscall**. The read path is already
batched by the layer beneath it; the write path was not, because crypto/tls emits
a record per `Write` but does not consume one per `Read`. Measured on loopback
TLS, 10 000 frames per op:

| | ns/op | throughput |
|---|---|---|
| unbuffered (shipping) | 6 945 985 | 2198 MB/s |
| `bufio.Reader`, 64 KiB | 7 693 657 | 1985 MB/s |

A `bufio.Reader` cuts the `Read` *calls* from 20 000 to 234 and buys nothing in
wall clock, while adding one more copy of every packet byte. It is not the same
shape of bug and it does not get the same fix. The measurements are kept as
`TestReadSideCallCount` and `BenchmarkCollectorReads*` in
`internal/capture/pcapoverip/readpath_test.go`, so the next person to ask gets
numbers instead of intuition.

### What this does not fix

Batching removes the sensor's per-frame overhead. It does not change the fact
that **`raw` mode re-streams every captured byte**: a saturated 1 Gbit WAN link
still means ~1 Gbit of TLS out of the sensor, and no amount of write batching
makes that fit down a narrower uplink. The structural answer to that is already
in the tree — `--mode flow` and `--mode feature` (ADR 0024) aggregate on the
sensor and ship records, not frames. This ADR makes `raw` cost what it should;
it does not make `raw` the right mode for a saturated uplink.

**Follow-up:** re-run `netstat -B` on the OPNsense sensor under the same 5 GB
download and record the drop count here. The benchmarks say the write path got
10× cheaper; only the firewall can say how much of the 63% that recovers.
