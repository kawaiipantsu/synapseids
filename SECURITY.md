# Security Policy

SynapseIDS ingests traffic it did not create — including deliberately hostile
packets, crafted PCAP files, and untrusted model and dataset uploads — and it
handles sensitive network telemetry. A defect that lets crafted input crash it,
hang it, exhaust memory, make it touch a file or host the operator did not
authorize, or leak secrets into logs is not a cosmetic bug. Please treat this
file as more than boilerplate.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to <https://github.com/kawaiipantsu/synapseids/security/advisories/new>
2. Describe the issue, the impact, and how to reproduce it.

If private reporting is unavailable, open a public issue that says only *"I have a
security report, please provide a private channel"* — no detail — and wait for a
maintainer to respond.

### What to include

- `synapsed --version` output and how the binary was built or installed.
- Operating system and architecture.
- The **smallest input that triggers it** — a PCAP, a config, an API request, a
  model/dataset bundle. If it is small, attach it (base64 is fine); if it is
  large, attach a generator.
- What an attacker gains and what access they need to start (can they only reach
  the loopback API? do they control captured traffic? do they control an upload?).
- A proof of concept if you have one.

### What to expect

SynapseIDS is a young project maintained by volunteers. We will acknowledge your
report, tell you whether we consider it in scope, and keep you informed. Fixes
ship in a release with a `Security` section in `CHANGELOG.md`. We credit you in
the advisory and changelog unless you ask us not to. If a report goes unanswered
for a month, disclose.

## Supported versions

SynapseIDS is pre-1.0. Only the latest release and the `develop` branch are
supported. There are no backports.

## What is in scope

- **A crafted PCAP or packet that crashes, hangs or OOMs `synapsed`** — an
  out-of-range slice in a decoder, a parser that does not terminate, an input
  that makes the flow table or a buffer grow without bound. Decoders are
  bounds-checked and must never panic on hostile bytes.
- **Unbounded resource use from any input** — a capture, a replay at `--speed
  max`, a flood of WebSocket clients, a large upload — that is not bounded by the
  documented caps (`capture.max_flows`, `storage.max_flows`,
  `live.client_queue_size`).
- **Reading or writing a path the operator did not name** — path traversal
  through a replay `path`, a future model/dataset upload path, or a config value;
  following a symlink out of the state directory; a TOCTOU between check and open.
- **Any capture against a host the operator did not authorize** — a bug in a
  current or future remote-capture adapter (SSH, PCAP-over-IP) that connects
  somewhere other than the configured, authorized target.
- **Secrets in logs or telemetry** — SSH keys, tokens, or credentials written to
  stdout/journald or any log.
- **Management API or live channel exposed without authentication** when the
  operator followed the documented deployment (localhost by default; an
  authenticating reverse proxy for remote access).
- **Privilege issues** — `synapsed` requiring more than `CAP_NET_RAW` /
  `CAP_NET_ADMIN` for capture, or the shipped systemd unit / packaging granting
  more than it needs.
- **A model bundle that bypasses the compatibility gate** (`schema.ValidateBundle`)
  and runs against an incompatible feature or output contract.
- Dependency vulnerabilities SynapseIDS actually reaches. `make security` runs
  `govulncheck`; CI runs it on every push and PR.

## What is out of scope

- **The classifier being wrong.** The Phase-1 model is a transparent heuristic; a
  misclassification is a quality issue, filed as a normal bug, not a
  vulnerability. The same applies to trained models later — detection accuracy is
  not a security boundary.
- **A slow but bounded analysis** of a legitimately enormous capture within the
  configured caps. Lower the caps.
- **An operator pointing SynapseIDS at traffic and it being analysed.** That is
  the entire purpose. The interesting question is whether *malformed* input
  breaks the tool.
- **An operator binding the API to `0.0.0.0` with no proxy and no auth.** The
  daemon warns; heeding the warning is on the operator.
- Vulnerabilities in the Go standard library itself — report those upstream.
  SynapseIDS's *handling* of a bad result from it is in scope.
- Attacks requiring an attacker who already has a shell on the host or can
  already write to the files and config SynapseIDS reads.

## The security model

- **Localhost by default.** `server.listen` is `127.0.0.1:8080`; a non-loopback
  bind is logged as a warning on startup. Remote access is expected to go through
  an authenticating TLS reverse proxy (see `contrib/nginx/`).
- **Least privilege.** The data plane needs only `CAP_NET_RAW` / `CAP_NET_ADMIN`
  for live capture (nothing for PCAP replay). The shipped systemd unit runs as a
  dedicated unprivileged user with `NoNewPrivileges`, `ProtectSystem=strict` and a
  syscall filter.
- **Bounded by construction.** The flow table, the storage rings and the
  per-client WebSocket queues all have configurable caps; over-cap work is
  dropped and counted, never queued without limit. Packet ingestion never blocks
  on storage or the UI.
- **Untrusted input, enforced.** Every decoder is bounds-checked; a malformed
  frame is counted and skipped. The classic-pcap and minimal-pcapng readers cap
  every declared block/record length before allocating; unknown link types,
  multi-section pcapng and structurally broken files are refused rather than
  guessed at.
- **Safe model deployment.** A model whose feature/output contract does not match
  the daemon is rejected before inference (`schema.ValidateBundle`). Newly
  trained models are never auto-activated — activation is an explicit,
  audit-logged operator action (a Phase-2 requirement, PROJECT.md §21, §28.10).
- **Observe only.** SynapseIDS does not implement exploitation, counter-attack, or
  traffic modification. It observes, classifies, explains and alerts.

## Known limits

- Storage is in-memory in this release; there is no auth on the local API itself.
- Remote-capture adapters (SSH, PCAP-over-IP) are not implemented yet; when they
  land, "authorized targets only" is a hard requirement.
- `.deb` packages are unsigned pending release-signing infrastructure; verify the
  archive checksums against the release `SHA256SUMS`.
