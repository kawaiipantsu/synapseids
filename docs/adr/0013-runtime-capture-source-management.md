# 0013 — Runtime capture-source management: a REST add/remove and the capture-sources UI

**Status:** Accepted, 2026-08-31

## Context

Phase 3 (GitHub issue #32, EPIC #3 — the last issue in that epic) asks for the
**Capture Sources** view of PROJECT.md §19.14: "manage local interfaces, PCAP
inputs, SSH captures, network streams, and sensors", displaying state,
packets/sec, bytes/sec, drops, connection latency, last packet time, current
filter and error state.

By the time #32 started, everything underneath already existed: four capture
adapters (`AFPacket`, `TcpdumpStream`, `SSHTcpdump`, `PCAPOverIP`), a
`capture.Manager` that fans N sources into one channel for the single pipeline
goroutine (§22, ADR 0010), and a read-only `GET /api/v1/captures[/{name}]`. Two
things were missing: **there was no way to add or remove a source without
editing the config file and restarting the daemon**, and the SPA route rendered
a "Planned — Phase 3" placeholder.

"Manage" in §19.14 means more than "display", so this ADR is mostly about the
mutating half and the import-graph refactor it forced.

## Decision

### `POST /api/v1/captures` and `DELETE /api/v1/captures/{name}`

The request body of `POST` is exactly a `config.CaptureSource` JSON object — the
same shape as one element of `capture.sources[]` in the config file, decoded
with `DisallowUnknownFields`, capped at 64 KiB. The handler runs, in order:

1. reject an inline `token` for **any** kind (§23 — the UI and the config file
   both offer `token_file` / `SYNAPSE_POIP_TOKEN` only);
2. `config.ValidateCaptureSource(cs)` — the shared validator, below;
3. duplicate-name check → `409`;
4. `capturewire.Build(cs, log.Printf)` — the shared builder, below;
5. `Manager.Add(name, src, meta)` with `meta.Origin = "api"`;
6. `201` with the new `capture.SourceStatus`.

Status codes: `400` bad body / failed validation / inline token (the config
error text is echoed verbatim so the operator sees the same sentence they would
see at startup), `409` duplicate name, `422` a **local** source (`nic`,
`tcpdump`) that could not be opened, `502` a **remote** one (`ssh`,
`pcap-over-ip`), `503` no capture manager wired. A source that fails to open is
never registered and never crashes the daemon (§21) — the cause is named in the
response body.

`DELETE /api/v1/captures/{name}` calls `Manager.Remove(name)` → `200
{"removed": name}`, or `404`. Sources loaded from config and sources added via
the API are **both** removable; the removal is logged and published as a
`CaptureSourceDisconnected` event.

### The shared validator — `config.ValidateCaptureSource`

The per-kind rules (required fields, the `known_hosts` enum, the pcap-over-ip
TLS/token posture, and the §28.18 `authorized: true` gate for `ssh` and for any
non-loopback / insecure-TLS / token-less `pcap-over-ip`) were previously private
to `config.validate()`. They are now one exported function that `validate()`
calls in its loop, wrapping the error with the array index for file context.
**There is exactly one copy of the rules**, so the file path and the runtime path
cannot drift; a test asserts the two agree for good and bad cases of all four
kinds. Cross-source concerns (duplicate names) stay in `validate()`.

### The shared builder — a new `internal/capturewire` package

`newCaptureSource` and `resolvePOIPToken` lived in `cmd/synapsed`. `internal/api`
needs them and **cannot import a `package main`**, so they had to move. The
obvious alternative — putting the builder in `internal/capture` — is barred by
the import graph documented in `docs/architecture.md`: `capture` is a data-plane
leaf that must not import `config` (it lists `config` in its "cannot import"
column, and `config` is stdlib-only by design so the dependency could only go
the wrong way).

So the builder lives in a new, small `internal/capturewire` package that imports
**both** `capture` and `config` and is imported by `cmd/synapsed` and
`internal/api` — neither of which is on the packet path. Nothing in
`capture → packet → flow → features → inference` imports it back, so the graph
stays a DAG and `capture` stays a leaf.

```
config ──┐
         ├──▶ capturewire ──▶ cmd/synapsed, internal/api
capture ─┘
```

It exposes `Build(cs, logf) (capture.Source, target, error)`,
`Meta(cs) capture.SourceMeta` and `ResolvePOIPToken(cs)`. `cmd/synapsed`'s
startup loop now calls the same three functions the REST handler does, so a
config source and a runtime source are constructed identically.

### Dynamic fan-in in `capture.Manager`

`Manager.Add` already handled the after-`Packets()` case (`if m.started {
m.launch(ms) }`): the new source's forwarder goroutine is created under the
manager mutex and writes to the same already-running `out` channel, and the
single global rate sampler picks it up on its next tick because it iterates the
live source map. No change was needed; a test now pins that behaviour
(packets from a runtime-added source reach the merged stream, the pre-existing
source is undisturbed, `-race` clean).

`Remove` was hardened: each forwarder now closes a per-source `done` channel on
exit, and `Remove` cancels the source, `Close()`s it and **joins** that goroutine
(with a 5 s safety bound for a wedged source) before returning, so nothing
outlives the HTTP request. A goroutine-count test asserts no leak.

`Remove` **drops the row immediately** rather than parking it as a lingering
`stopped` entry — a `GET /api/v1/captures/{name}` straight after a `DELETE` is a
`404`. Keeping a tombstone would need an eviction policy and a second source of
truth for "is this thing running", for no operator benefit: the removal is
already in the log and on the event bus.

`SourceMeta`/`SourceStatus` gain an `origin` field (`"config"` | `"api"`) so the
UI can badge where a source came from.

### Wiring: widen `CaptureStatusProvider`

Rather than add a parameter to the already-wide `api.New`, the existing
`CaptureStatusProvider` interface grew `Add` and `Remove`. `capture.Manager`
satisfies it unchanged and `api` stays off the concrete type. A `nil` provider
still means "no capture manager": the GETs degrade to an empty list / `404` and
the mutating routes return `503`.

`cmd/synapsed` now **always** hands the Manager to the API and **always** starts
the capture pipeline goroutine, even with zero configured sources — otherwise a
runtime-added source would have no consumer draining `Manager.out` and its
forwarder would block on the first packet.

### The SPA view — `CAPTURE ▸ Sources`

`web/ui/src/routes/CaptureSources.tsx` replaces the placeholder. A table polled
once a second off `GET /api/v1/captures` shows every §19.14 field — name (+ a
"from config" / "runtime" badge), kind, colour-coded state, packets, bytes, pps,
bps, drops, decode errors, last packet (relative, absolute on hover), current
filter, connection latency (`n/a` for anything but `pcap-over-ip`) — and spills
the error string into a prominent full-width row when a source is in `error`.
Polling, not the WebSocket: the hub carries `CaptureSourceConnected/Disconnected`
transitions but not the rolling counters, and 1 Hz on a handful of rows is far
cheaper than adding a counter event to the bus.

The add-source form reveals only the fields relevant to the selected kind and
carries an explicit **"I am authorised to monitor this target"** checkbox mapped
to `authorized: true`. The UI mirrors the server rule — required for `ssh`, and
for `pcap-over-ip` when `insecure_tls` is set, the address is not loopback, or
there is no `token_file` — and disables submit until it is ticked, naming the
reason. The mirror is a courtesy; the daemon is the authority and its rejection
text is shown verbatim. There is no inline-token field at all. The draft is
persisted to `localStorage` (it holds only names and filesystem paths, never a
secret). Removal asks for confirmation, since it kills a live capture,
a subprocess or an SSH session.

## Consequences

- Live demo without a restart: `synapsed` with no configured sources, then
  `POST /api/v1/captures` a `tcpdump` source on `lo`, watch it count in
  `GET /api/v1/captures` and produce flows in `GET /api/v1/classifications`,
  then `DELETE` it.
- **These are powerful endpoints.** `POST /api/v1/captures` opens a raw socket,
  spawns a `tcpdump` subprocess, dials a TLS sensor or starts an SSH session on
  the operator's behalf — strictly more dangerous than
  `POST /api/v1/models/{id}/activate`. They inherit the repo's existing posture
  and nothing more: the daemon binds loopback by default (§21) and the routes
  carry `// TODO(#58): gate behind auth/RBAC`. Issue #58 must land before the
  management API is exposed off loopback; the §28.18 `authorized:true` assertion
  is an operator declaration, not an authorization control.
- With #32 done, **EPIC #3 (Phase 3 — live capture) is complete.**
- **Follow-ups:** a real pcap-filter-expression compiler for `nic` (still
  built-in cBPF presets only); client reconnect/backoff and a subprocess
  supervisor / auto-restart; editing a source in place rather than
  remove-then-add; persisting a runtime-added source back to the config file;
  and #58 for authentication.
