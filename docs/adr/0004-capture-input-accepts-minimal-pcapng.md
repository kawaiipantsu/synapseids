# 0004 — The capture input contract accepts minimal pcapng

**Status:** Accepted, 2026-08-31

## Context

`internal/capture` originally read only the classic libpcap file format
(`0xa1b2c3d4` / `0xa1b23c4d` magic, µs or ns, either byte order, `EN10MB` or
`RAW` link types). Anything else — including pcapng, the format Wireshark,
`dumpcap` and `tcpdump` now write by default — was rejected with `ErrNotPCAP` and
a hint to run `editcap -F pcap` first (GitHub issue #73).

That hint is a real papercut: most captures a user already has on disk in 2026
are pcapng, and the conversion step is easy to forget and annoying to script
around. PROJECT.md §6 lists "PCAP / PCAPNG" as one capture source, so reading
pcapng is in scope, not a new capability.

The competing constraint is the zero-third-party-dependency rule (PROJECT.md
§27, §28.16): a pcapng library is not an option. pcapng is also a much larger
format than classic pcap — arbitrarily many sections, per-interface timestamp
resolutions, name-resolution and statistics blocks, custom blocks, decryption
secrets — and a full reader would be a lot of stdlib-only surface for a Phase-1
slice.

## Decision

**`capture.PCAPFile` gains a minimal, read-only pcapng reader (`pcapng.go`),
stdlib-only, behind the unchanged `Source` interface.** A file is treated as
pcapng when it starts with the Section Header Block type `0x0A0D0D0A`.

Supported:

- **one** Section Header Block; byte order taken from the `0x1A2B3C4D` magic
  (little- or big-endian);
- Interface Description Block — link type, snap length, and the `if_tsresol`
  option (code 9, decimal `10^-n` or binary `2^-n`; default `10^-6`);
- Enhanced Packet Block — interface id, 64-bit timestamp scaled by that
  interface's resolution, captured vs. original length;
- Simple Packet Block — length only, interface 0, no timestamp;
- Ethernet and RAW link types, decoded by the existing `packet.Decode`.

Every other block type is skipped by its `total_length`. Both the leading and
trailing block lengths are read; each is bounded (`maxSnapLen` + slack) before
any allocation and the two must agree. Malformed structure returns an error on
the terminal error channel — never a panic (PROJECT.md §28.11). `Stats()`
semantics (packets / decoded / decodeErr / bytes / lastTS) are identical to the
classic path.

**Explicitly not implemented, still handled with the `editcap -F pcap` hint:**
multiple sections; a mid-file endianness change; non-Ethernet/RAW link types
(same rejection the classic path gives); `if_tsoffset`; the obsolete Packet
Block (type 2) and other blocks are silently skipped.

`ErrNotPCAP` now means "neither classic pcap nor pcapng". A golden twin fixture,
`testdata/pcap/http.pcapng` (hand-encoded by `testdata/gen`, committed alongside
the classic files per §25 / §31.9), is asserted to decode to the same packets,
flows and `flow-features-v1` vectors as `http.pcap`.

## Consequences

- A user can `synapse replay capture.pcapng` directly; the common case no longer
  needs a conversion step.
- No new dependency; the reader is ~250 lines of `encoding/binary` and
  `math/bits`, cross-compiles to every target like the rest of `capture`.
- The accepted-input contract widened: the replay-start `409`, `SECURITY.md`,
  `docs/architecture.md` and `CLAUDE.md` now describe classic **and** minimal
  pcapng.
- pcapng captures with multiple sections or exotic link types still fail closed,
  with the same actionable hint — the reader never guesses.
- A second hand-encoded container format now lives in `testdata/gen`; a future
  `flow-features` change that re-runs `-update` must keep both twins in sync.
- Simple Packet Blocks yield a zero timestamp (the format carries none); flows
  built purely from an SPB-only capture have no wall-clock timing. Real-world
  pcapng from `dumpcap`/`tcpdump` uses Enhanced Packet Blocks, so this is a
  theoretical gap.

**Revisit when:** Phase 3 live capture lands (a shared block/record reader may be
worth extracting), or a real capture shows up that needs multi-section support,
`if_tsoffset`, or a non-Ethernet link type — at which point the choice is a
larger stdlib reader vs. keeping `editcap` for the long tail.

---

⟦THUGS⟧ (c) 2026
