# 0011 — Subprocess capture: local tcpdump stream and SSH remote tcpdump

**Status:** Accepted, 2026-08-31

## Context

Phase 3 continues with two more capture sources (PROJECT.md §6, §26 Phase 3,
GitHub issues #29 and #30):

- **tcpdump stream** — "accept a stream produced by tcpdump-compatible capture
  output";
- **SSH remote tcpdump** — "allow an authorized remote capture such as
  `ssh sensor-host tcpdump -U -w - <capture-filter>`; the application should
  manage the subprocess/SSH stream rather than requiring temporary capture
  files."

Both are, mechanically, the same thing: spawn a program whose **stdout is a
classic-pcap byte stream**, decode that stream through the very same
`packet → flow → features → inference` pipeline a PCAP file or a live NIC uses
(PROJECT.md §6), and manage the child's lifecycle. They differ only in the argv.

Repo constraints are unchanged (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0`, zero third-party Go dependencies, clean offline cross-build to
the four `linux/*` targets. `os/exec` + `syscall` are stdlib, so this is all
in-budget with no new dependency.

## Decision

### One shared engine: `decodePCAPStream` + `pcapSubprocess`

The classic-pcap decode loop that lived inside `PCAPFile.Packets` is lifted into
an unexported, source-agnostic function in `internal/capture/pcapstream.go`:

```go
func decodePCAPStream(ctx context.Context, r io.Reader,
        out chan<- packet.Packet, errc chan<- error, st *streamStats)
```

It reads the 24-byte global header from `r`, sniffs **classic pcap** (µs/ns,
LE/BE) or **pcapng** (`0x0A0D0D0A`), dispatches to the classic record loop or
the existing minimal pcapng reader (`streamPCAPNGRecords`), decodes every record
with `packet.Decode`, folds counts into a shared `streamStats`, and respects
`ctx`. A single malformed frame is counted, never fatal (§28.11).

`PCAPFile.Packets` is now a thin wrapper: open the file, hand the reader to
`decodePCAPStream`. Its behaviour is **byte-for-byte unchanged** — the golden
feature tests, the `internal/capture` tests and the `internal/pipeline`
end-to-end tests all pass untouched, and a new table test
(`TestDecodePCAPStreamMatchesPCAPFile`) asserts the extracted engine yields
exactly the packets and counters `PCAPFile` yields for every committed fixture
(`http.pcap`, `portscan.pcap`, `udp.pcap`, `http.pcapng`).

`pcapSubprocess` (`subprocess.go`) is the shared child-process engine that both
new sources embed:

- `exec.CommandContext(ctx, bin, args...)` — **an argv slice, never a shell
  string** (§28.18 spirit: nothing the operator configures is ever handed to a
  shell on the local side);
- the child runs in **its own process group** (`Setpgid`), and `cmd.Cancel`
  kills the whole group with `SIGKILL` so an `ssh`-wrapped remote `tcpdump`
  (which `ssh` runs through a login shell) dies with us rather than being
  orphaned; `cmd.WaitDelay` bounds `Wait` if a grandchild holds the pipe;
- stdout → `decodePCAPStream`; **stderr → a bounded ring buffer**
  (`stderrRingBytes`, 8 KiB);
- on a non-zero exit the terminal error is
  `fmt.Errorf("%s: exit %d: %s", label, code, stderrTail)`; a deliberate
  `Close`/ctx-cancel is **not** an error;
- **no auto-restart** in this pass — a crash surfaces as `state:"error"` on
  `GET /api/v1/captures` via the Manager, and the operator (or a future
  supervisor, #31/#32) decides.

`streamStats.Drops` stays 0. tcpdump reports kernel drops only as a
`"N packets dropped by kernel"` line on **stderr at exit**, which the Manager's
once-a-second live sampling cannot consume; wiring that in is deferred rather
than done half-way.

### `TcpdumpStream` (#29) — `tcpdump_stream.go`

```
tcpdump -U --immediate-mode -w - -i <iface> -s <snaplen> [extra args...] [filter tokens...]
```

- `-U` + `--immediate-mode`: deliver frames as they arrive, not on tcpdump's
  output buffer, so the pipeline sees live latency;
- `-w -`: classic pcap on stdout;
- **`Filter` is a real tcpdump expression**, tokenised on whitespace
  (`strings.Fields`) and appended as trailing argv elements — never
  interpolated;
- `exec.LookPath` up front: a missing binary is a clear construction-time error
  pointing at the source's `binary` field.

### `SSHTcpdump` (#30) — `ssh_tcpdump.go`

```
ssh [-p PORT] [-i IDENTITY] -o BatchMode=yes -o StrictHostKeyChecking=<mode> \
    [extra ssh args...] <destination> "<remote command>"
```

The **remote command** is built from a fixed template and passed as one argv
element for `ssh` (which hands it to the remote login shell):

```
<remote-bin> -U -w - -i <iface> -s <snaplen> <filter tokens...>
```

Because the *remote* side runs it through a shell, every operator-influenced
field (`remote-bin`, `iface`, each filter token) is quoted with a tiny local
`shQuote` (POSIX single-quote, `'\''` for embedded quotes; left bare only when
the token is entirely `[A-Za-z0-9_@%+=:,./-]`). A crafted interface name or
filter token cannot break out of the command.

- **`BatchMode=yes`** — `ssh` never blocks on an interactive
  password/passphrase prompt; a password-only host fails fast with guidance to
  use a key, instead of hanging the daemon.
- **`StrictHostKeyChecking`** — `KnownHostsMode` is `"strict"` (default →
  `=yes`) or `"accept-new"` (TOFU). `=no` is deliberately not offered.

### §28.18 authorization gate for remote capture

PROJECT.md §21: *"remote capture must only operate against systems the operator
is authorized to monitor."* The config therefore carries an **explicit
acknowledgement**: `capture.sources[].authorized` (JSON `authorized`). An `ssh`
source with `authorized != true` is a config error:

> `remote capture requires "authorized": true — you must be authorised to
> monitor <destination> (PROJECT.md §28.18)`

`NewSSHTcpdump` enforces the same gate defensively, so the source cannot be
constructed unauthorized even outside the config path. Local `tcpdump` capture
is a local-traffic concern like `nic` and carries no such gate.

### Config + daemon wiring

`config.CaptureSource` gains optional per-kind fields: `Binary`, `ExtraArgs`
(tcpdump); `Destination`, `Port`, `IdentityFile`, `RemoteBinary`, `KnownHosts`,
`ExtraSSHArgs`, `Authorized` (ssh). `Kind` now also accepts `"tcpdump"` and
`"ssh"`. `Filter`'s meaning is **per-kind**: a `capture.BuiltinFilters` preset
name for `nic` (a cBPF program), a raw tcpdump filter expression for
`tcpdump`/`ssh`. `validate()` checks per-kind required fields
(`nic` → interface + known preset; `tcpdump` → interface; `ssh` → destination +
interface + `authorized:true`). The `synapsed` startup loop builds a
`TcpdumpStream` / `SSHTcpdump` for those kinds and `manager.Add`s them exactly
like a NIC source; a source that cannot start is logged and skipped, the API
keeps serving (PROJECT.md §21).

## Consequences

- `synapsed` with a `kind:"tcpdump"` source on `lo` was run end to end on a box
  with `tcpdump` + `CAP_NET_RAW`: `GET /api/v1/captures` counts packets/bytes
  and shows `state:"running"` and the filter expression;
  `GET /api/v1/classifications` shows flows built from the live stream; SIGINT
  reaps the child with no zombie. SSH argv assembly and the authorization gate
  are covered by tests (a fake binary stands in for `ssh`/`tcpdump`); a real
  remote host is out of scope here.
- The `decodePCAPStream` extraction is behaviour-preserving; it is now the one
  place classic/pcapng stream decoding lives, ready for PCAP-over-IP (#—) to
  reuse.
- No auto-restart: a dropped SSH connection or a killed tcpdump leaves the
  source in `state:"error"` until the operator intervenes. A supervisor/backoff
  policy is a follow-up (EPIC Phase 3, #31/#32), as is runtime add/remove of
  sources over REST and parsing tcpdump's kernel-drop line into `Stats.Drops`.
- `Setpgid` + group-kill is Linux/Unix; every release target is `linux/*`.
