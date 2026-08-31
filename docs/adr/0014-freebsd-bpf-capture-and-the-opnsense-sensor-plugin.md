# 0014 — FreeBSD BPF capture and the OPNsense sensor plugin

**Status:** Accepted, 2026-08-31

## Context

GitHub issue #98 (EPIC #6, Phase 6) wants an OPNsense firewall to act as an
inbound-WAN sensor: capture on the WAN interface, stream to a central
`synapsed` over the existing SYNPOIP transport (#31, ADR 0012), and be
configured from the OPNsense web UI rather than by hand over SSH.

Three things stood between us and that:

1. **OPNsense is FreeBSD.** The only live-NIC source is Linux `AF_PACKET`
   (ADR 0010). FreeBSD captures through `/dev/bpf*`, a completely different
   interface — different ioctls, a different record framing, a different
   permission model.
2. **A firewall is behind NAT.** ADR 0012 made the *daemon* the dialer, which
   means opening an inbound hole in the box you are trying to monitor.
3. **Nothing built or shipped a FreeBSD artefact.** `make dist`/`deb` produce
   Linux tarballs and `.deb`s only.

The usual hard constraints apply (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0`, **zero third-party Go dependencies**, and the four
`linux/{amd64,386,arm64,arm}` targets are non-negotiable and must not be
disturbed.

## Decision

### 1. A stdlib-only `/dev/bpf` source — `internal/capture/bpf_freebsd.go`

`NewBPFDevice(BPFConfig)` opens a BPF device, binds it to an interface and
configures it, then presents the same `capture.Source` contract `AFPacket`
does. No `golang.org/x/sys/unix`: that is a third-party module, and the whole
point of the stdlib-only rule is that cross-compilation and offline builds stay
trivial. Go's own `syscall` package covers everything needed on FreeBSD —
`Open`, `Read`, `Close`, `Syscall(SYS_IOCTL, …)`, and the `BpfInsn` /
`BpfProgram` / `BpfStat` / `BpfHdr` / `Timeval` types.

`BPFConfig` is `Interface`, `Device` (an explicit `/dev/bpfN`, or probe),
`Promiscuous`, `Snaplen`, `Filter`, `Direction`, `BufferLen` and `ReadTimeout`.
Setup order matters and is:

| step | ioctl | why |
|------|-------|-----|
| buffer size | `BIOCSBLEN` | must precede `BIOCSETIF`; FreeBSD clamps to `net.bpf.maxbufsize` and writes back what it granted |
| filter | `BIOCSETF` | attached **before** the interface, so no unfiltered frame is ever queued |
| bind | `BIOCSETIF` | attaches the descriptor and starts capture |
| promiscuous | `BIOCPROMISC` | |
| immediate | `BIOCIMMEDIATE` | deliver on arrival instead of waiting for a full store buffer (§17, §22) |
| read timeout | `BIOCSRTIMEOUT` | bounds a blocking `read(2)` so `Close()` and context cancellation are responsive on a silent link |
| direction | `BIOCSDIRECTION` | `BPF_D_IN` for an inbound-WAN sensor |
| link type | `BIOCGDLT` | mapped to `packet.LinkEthernet` / `packet.LinkRaw`, anything else refused with advice |
| flush | `BIOCFLUSH` | drops what queued during setup and, on FreeBSD, zeroes the descriptor's counters, so `BIOCGSTATS` is a clean cumulative total |

**There is no snaplen ioctl on BPF.** In classic BPF the `k` of the accepting
`BPF_RET` instruction is a *byte count*, so the snaplen is expressed by the
attached filter. That is why a filter is installed even when no preset was
named, and why the preset table had to grow a `keep` parameter
(`builtinFilterInsns(name, keep)` in `bpffilter.go`, shared with Linux, which
still passes `bpfRetKeep`). `Stats.Drops` comes from `BIOCGSTATS`'s `bs_drop`;
unlike `PACKET_STATISTICS` these counters are cumulative, so the code assigns
rather than accumulates.

### 2. Deriving the ioctl numbers by hand, and proving them twice

FreeBSD ioctl request numbers are a packed encoding (`sys/ioccom.h`):

```
_IOC(inout, group, num, len) = inout | ((len & 0x1fff) << 16) | (group << 8) | num
```

`bpfioctl.go` writes that derivation out with the macro definitions in a
comment, names every command number from `net/bpf.h`, and documents the LP64
argument sizes it assumes (`struct ifreq` 32, `struct timeval` 16,
`struct bpf_program` 16, `struct bpf_stat` 8). It is untagged, so it compiles
and tests on Linux.

The numbers are checked twice, from opposite directions:

- **`bpfioctl_test.go`** (runs on Linux, in CI) asserts the derived constants
  equal the published FreeBSD values — `BIOCSETIF` `0x8020426c`,
  `BIOCSRTIMEOUT` `0x8010426d`, `BIOCGSTATS` `0x4008426f`, and nine more —
  written as literals so the expected side is not computed the same way.
- **`bpf_freebsd_assert.go`** (`freebsd && (amd64 || arm64)`) pins the same
  constants against `syscall.BIOC*` *at compile time*, using paired constant
  subtractions that overflow if the two sides differ. It also pins the assumed
  struct sizes against `unsafe.Sizeof` of the real local types. So
  `GOOS=freebsd go build` — which CI and the release build both run — cannot
  succeed with a wrong number.

`bpf_freebsd.go` itself derives its requests from `unsafe.Sizeof` of the actual
structs rather than from the LP64 constants, so it stays correct on a FreeBSD
GOARCH the assertion file does not cover.

### 3. Splitting BPF read chunks — `bpfchunk.go`, untagged and table-tested

One `read(2)` on a BPF device returns many packets back to back, each prefixed
by a `struct bpf_hdr` (or `bpf_xhdr`) and each starting on a `BPF_WORDALIGN`
(`sizeof(long)`) boundary. Getting this wrong desynchronises the whole stream,
so it is the part that most needed tests — and the part that could least be
tested on FreeBSD from here.

The split therefore lives in `bpfchunk.go` with **no build tag** and no
syscalls: `parseBPFChunk(dst, chunk, layout) ([]bpfRecord, error)`. Only the fd
and ioctl plumbing is FreeBSD-gated. `bpf_freebsd.go` builds the layout from
`unsafe.Offsetof` on `syscall.BpfHdr`, so the offsets are the kernel's own for
that GOARCH rather than a hand-maintained table.

Design points:

- **`bh_hdrlen` is authoritative** for where the frame starts and is read per
  record; the parser never assumes a header size. libpcap does the same.
- The stride is `BPF_WORDALIGN(bh_hdrlen + bh_caplen)`, so bytes inside a
  record's alignment padding are padding — not a truncated next record — and
  the kernel eliding the final pad simply ends the loop.
- **Malformed input is counted, never fatal and never a panic** (§28.11). A
  short header, an over-ceiling `bh_caplen`, a `bh_hdrlen` below the field
  minimum or a record running past the chunk all return the records parsed so
  far plus an error; the read loop counts one decode error and keeps the good
  packets from the same chunk.
- A corrupt sub-second field is reduced modulo `fracPerSec` before the
  nanosecond multiply, so it cannot overflow.
- `dst` is a caller-reused slice, keeping the packet path off the allocator
  (§22).

Tests cover single and multi-record chunks, alignment padding, snaplen
truncation, every malformed shape above, big-endian and ILP32 layouts,
nanotime headers, buffer reuse, and a fuzz target plus a 2000-iteration
random/mutation loop asserting no panic and no slice escaping the chunk.

### 4. Live NIC in the sensor, and a raw-frame path

`capture.NewLive(LiveConfig)` is a small platform-neutral front door —
AF_PACKET on Linux, `/dev/bpf` on FreeBSD, a clear error elsewhere. Fields a
platform cannot honour are **rejected at construction, not silently ignored**:
`Direction` and `Device` are FreeBSD concepts and Linux says so.

SYNPOIP carries *raw* frames, but `capture.Source` yields decoded packets, so
both live sources gained `RawPackets(ctx) <-chan RawFrame`. Rather than making
one a wrapper of the other, the read loop is parameterised by an `emit`
callback: the decoded path keeps its zero-copy decode (no regression to the
daemon's hot path) and only the raw path pays for the copy the receiver needs.
`capture.LiveStreamer` adapts that to `pcapoverip.StreamFunc`, opening an
independent capture per connected client — the same posture the file streamer
already had — and aggregating `Stats` across them so keepalives report real
`BIOCGSTATS` drops (`ServerConfig.Drops`).

### 5. `--connect`: invert the transport, not the protocol

The brief's suggested shape was that the dialing side sends the ClientHello. We
did the opposite, and it is the better trade.

**The SYNPOIP roles stay exactly where they were.** The sensor dials out; on
that established TLS connection the *accepting* daemon still sends the
ClientHello and the sensor still answers with a ServerAccept and streams packet
frames. `pcapoverip.ServeConn` is the identical per-connection handler `Serve`
already ran. Consequences:

- **No wire change, no version bump, no role byte.** The frame layout in
  `PROTOCOL.md` §2–§4 is untouched; §6 documents the inversion.
- **The data direction stays correct.** Flipping the roles instead would have
  made the ClientHello sender the *producer*, which is the opposite of what
  every existing v1 peer means by it — a genuine semantic fork of the protocol
  for no gain.
- **Both ends still authenticate.** The TLS roles do invert, and that maps
  neatly onto the plugin's form: the daemon presents the server certificate
  (sensor verifies it against `--ca`), the sensor presents a client certificate
  for mTLS, and the daemon still presents the bearer token the sensor verifies
  with `crypto/subtle`. Mutual authentication, unchanged handshake.
- Sensor identity moves from the hello's `sensor_id` metadata to the accept's
  `session_id`, prefixed with the configured sensor id
  (`ServerConfig.SessionPrefix`).

The sensor also reconnects with capped exponential backoff and jitter, because
a firewall sensor is a service on a box nobody logs into (PROJECT.md §5.3
"sensors can reconnect").

**What is NOT wired: `synapsed` has no collector endpoint.** Every capture kind
it supports (`nic`, `tcpdump`, `ssh`, `pcap-over-ip`) opens outward or locally;
nothing listens for a sensor to dial in. Adding one is not a small change — it
needs a new listener-shaped capture kind, dynamic per-peer source registration
in `capture.Manager`, config and API surface, and daemon-side TLS material — so
it is deliberately out of scope here and tracked as a follow-up. `--connect`
implements the complete sensor half and is exercised end to end against a test
collector in `cmd/synapse-sensor/connect_test.go`; until the daemon side lands,
the OPNsense plugin defaults to `--listen` mode, which works today.

### 6. Build matrix and a real package

`FREEBSD_ARCHES := amd64 arm64` and `build-freebsd` are **additive**: the
`LINUX_ARCHES` line and `build_linux_arch` are byte-for-byte unchanged (§28.16).
`synapse-sensor` is the binary that must build for FreeBSD; `synapsed` and
`synapse` happen to cross-compile cleanly too, so they ride along in the
tarball.

`scripts/package-opnsense.sh` builds a genuine FreeBSD package. A `.pkg` is a
compressed tar archive whose leading members are `+MANIFEST` and
`+COMPACT_MANIFEST` (UCL, and JSON is valid UCL) followed by the payload under
absolute paths — so `tar` + `xz` + `jq` produce one directly, exactly as
`scripts/package-deb.sh` drives `dpkg-deb` rather than a packaging framework.
The ABI is parameterised (`FreeBSD:14:amd64` by default, `FREEBSD_VERSION`
overridable), one `.pkg` per ABI as with the four `.deb`s, wired into `make
dist`'s `SHA256SUMS` and into the release workflow.

### 7. The plugin, least privilege, and `authorized`

`contrib/opnsense/` is an OPNsense MVC plugin: a `Sensor.xml` model, an ACL, a
menu entry under **Services → SynapseIDS Sensor**, a settings and a service API
controller, a Volt page, configd actions, Jinja2 templates and an `rc.d`
script. Both packaging paths (the port `Makefile` for an upstream
`opnsense/plugins` PR, and `package-opnsense.sh` for CI) install the same file
list, and the build **fails** if the staged tree and `pkg-plist` disagree.

Security posture:

- **Not root.** The sensor runs as the dedicated unprivileged `_synapseids`
  account, in group `net`, with read-only access to `/dev/bpf*` through a devfs
  rule. The device is opened `O_RDONLY`, so the sensor cannot transmit even in
  principle (§28.17). An `EACCES` produces the exact `devfs.rules` fix rather
  than "operation not permitted" (§21).
- **The devfs rule is opt-in.** Changing device permissions on someone's
  firewall is not a package's business, so `pkg add` does not do it; the
  installer's `--grant-bpf`, or two documented commands, does.
- **The token never touches a command line.** The configd template renders
  *variables*, not a ready-made command line, precisely so the one value that
  must never reach `argv` can live in its own file: the token is written only
  to `/usr/local/etc/synapseids/sensor.token` (`0400 _synapseids:_synapseids`)
  and passed with `--token-file`. It is therefore absent from `ps(1)`, from
  shell history, from `sensor.conf` (`0640 root:wheel`, flags only) and from
  every log line (§23). A `fixperms` configd action clamps the modes
  immediately after each `template reload`, closing the window configd's
  default umask would otherwise open; the `rc.d` script re-checks before every
  start. The installer never asks for the token: it is entered in the UI
  afterwards, so it cannot land in shell history or the process table.
- **TLS PEM material is a known gap.** `sensor.conf` only *names*
  `peer-ca.pem` / `sensor-cert.pem` / `sensor-key.pem`; rendering the text from
  the config store needs three more configd template targets that this package
  does not install yet, so an operator places those files by hand for now. It
  fails safe: `rc.d` refuses to start, naming the missing path, whenever a flag
  references a PEM that is not on disk, so a missing certificate can never
  silently downgrade the transport.
- **`authorized` is a hard gate** (§28.18, §21). The model refuses to save an
  enabled sensor without it, and the CLI refuses `--iface` without
  `--authorized` and `--insecure-tls` without it too. Monitoring a network is
  an authorization decision, not a default.
- **Piping a script to a shell as root on a firewall is a real risk.** The
  documented default is therefore download-read-run; the one-liner is offered
  as the convenience option with that said plainly.

## Consequences

- `GOOS=freebsd GOARCH={amd64,arm64} CGO_ENABLED=0 go build ./...` and
  `GOOS=freebsd go vet ./...` pass, which — because of
  `bpf_freebsd_assert.go` — is also a proof that every derived ioctl number
  matches the FreeBSD ABI. `linux/{amd64,386,arm64,arm}` and `darwin` still
  build.
- One shared preset table now feeds both live sources. `afpacket_linux.go`
  keeps identical behaviour (`bpfRetKeep`, which is `DefaultSnaplen`; a test
  pins the two together).
- `errUnsupportedPlatform` moved to an untagged file so the `!linux` and
  `!freebsd` stubs can share it without their build tags colliding.
- `Stats.Drops` is now meaningful on FreeBSD and travels to the daemon in
  keepalives.

**What is unverified.** This was written and tested on Linux. Nobody has run
the BPF source on FreeBSD, installed the plugin on OPNsense, or captured real
WAN traffic with it. Specifically:

- the BPF code is compile-verified only — the ioctl *numbers* are machine-
  checked, the runtime behaviour is not;
- the package is structurally verified (member order, manifest keys, per-file
  checksums against the archived bytes, modes, ownership) but has never been
  through `pkg add`;
- the PHP is `php -l`-clean and the XML/Volt are conventional, but no OPNsense
  MVC runtime has loaded them, and the template's interface-name lookup carries
  an explicit `TODO(verify):`;
- `--connect` has no daemon to connect to yet.

`contrib/opnsense/README.md` lists the exact commands a maintainer must run on
real hardware to close each of those gaps.

**Follow-ups:** the daemon-side SYNPOIP collector (the missing half of
`--connect`); a `capture.Manager` that can register a source per inbound peer;
`GOOS=freebsd` in CI once a runner exists; sensor `flow` / `feature` modes
(§5.3); `PACKET_IGNORE_OUTGOING` so `Direction` works on Linux too.
