# 0022 — The audit log gets a read path, and activation gets an operator surface

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §21 requires two things of this system that are easy to satisfy on
paper and easy to get wrong in practice:

> - maintain an audit log for model activation, training, dataset edits, and
>   human label changes;
> - require explicit action to deploy a newly trained model.

and §28.10 states the second one as a rule: **do not activate newly trained
models automatically.**

Most of the machinery already existed before this change.
[ADR 0009](0009-model-registry-lineage-and-explicit-activation.md) built
`internal/registry` (the §19.12 entry, lineage, `SetStatus`) and the explicit
`POST /api/v1/models/{id}/activate` · `deactivate` pair against a swappable
`inference.Runtime`, including the deliberate rule that a persisted `active`
entry is reconciled to `deactivated` on restart so activation never survives
implicitly. `internal/audit` appended a JSONL line per model, dataset
([ADR 0015](0015-versioned-datasets-on-disk.md)) and training-run
([ADR 0019](0019-external-training-runs-reported-over-http.md)) lifecycle event.

Two things were missing, and both of them mattered more than they looked.

**The audit log was write-only.** Nothing in the daemon, the API or the SPA could
read it back. A trail an operator cannot inspect does not satisfy §21 — it is a
file that costs disk and delivers nothing. "Who activated what, when" was
answerable only by someone with shell access to `models.directory`.

**Activation was curl-only.** `ML ▸ Models` was a "Planned — Phase 2"
placeholder, so the one operation §28.10 singles out as needing a deliberate
human act had no human interface at all. That is a bad failure mode in both
directions: an operator who cannot see the registry cannot make an informed
decision, and an operator driving `curl` has no confirmation step between
"inspect a model" and "this model now classifies all production traffic".

Auditing also had real gaps, which only became visible once the log could be
read as a sequence of state changes rather than appended to blindly.

## Decision

### 1. A bounded, newest-first reader in `internal/audit`

`Tail(n int, filter Filter) ([]Record, error)` — as a package function taking a
path, and as a method on `*Logger` for callers that already hold one. Records
come back **newest first**, because that is the question an operator asks.

The scan seeks to EOF and walks backwards in 64 KiB chunks, splitting on newline
boundaries and carrying a partial line into the next (earlier) chunk. It stops as
soon as it has `n` matching records. It is bounded twice, and both bounds are
part of the contract rather than an implementation detail:

- **`MaxTail = 1000`** caps the returned slice; `DefaultTail = 100` applies when
  `n <= 0`.
- **`MaxScanBytes = 8 MiB`** caps how far back from EOF the reader will look.
  Records earlier than that window are not served. The file on disk remains the
  complete record — the API is a bounded view of it, not the archive.

The whole log is never read into memory, and a long-lived daemon cannot turn one
`GET` into an unbounded read (§22, the same reasoning as the `classFilterScan` /
`hostScanLimit` caps in `internal/api`).

**Corruption is expected, not exceptional.** A crash between `write` and the
trailing newline leaves a torn line at EOF. `Tail` skips any line that is blank,
is not JSON, or carries no `event`, and keeps every complete record around it. A
missing file returns no records and **no error**: "nothing auditable has happened
yet" is a normal state, not a failure. This is the same non-fatal posture
`registry.Open` takes toward a corrupt `registry.json`.

### 2. `Filter` is generic over subject types, on purpose

`Filter` narrows on `subject_type`, `subject`, `event` and an inclusive
`From`/`To` range. Every string field is an **exact match, compared as an opaque
string** — `Filter` never validates `subject_type` against the `SubjectModel` /
`SubjectDataset` / `SubjectTraining` constants, and there is no enum anywhere in
the read path or in `GET /api/v1/audit`.

That is a deliberate design choice, not laziness. §21's fourth category —
**human label changes** — arrives with the review loop (issue #42) as a new
`review` subject type. Because the reader, the route and the SPA's filter chips
all treat `subject_type` as data, those lines become readable and filterable the
moment they are first written, with no change to this package, no route change,
and no coordinated release. The SPA derives its chip set from the records it
receives unioned with a fixed base set, so a new subject type appears in the UI
by itself.

A record whose `ts` is not RFC3339 cannot satisfy a *bounded* window (there is no
honest way to place it), but it is still returned by an unbounded query — a bad
timestamp must not make a line disappear.

### 3. `GET /api/v1/audit` — read-only, and read-only forever

One route: `limit` (default 100, clamped to 1000), `subject_type`, `subject`,
`event`, `from`, `to` (RFC3339, inclusive). It reuses the existing `limitParam`
and `parseTimeRange` helpers so clamping and the `400` on a bad timestamp behave
exactly as they do on `/api/v1/timeline` and `/api/v1/hosts/{ip}/flows`. The
response echoes `limit`, `max_limit` and `scan_bytes_cap` so a client can tell
the operator what it is *not* showing.

**There is no `DELETE`, no `PATCH` and no `POST`, and there never will be.** An
audit log an operator can edit records nothing worth reading: the whole value of
the artefact is that it cannot be curated after the fact. The only writers are
`internal/audit`'s appenders, called from a state change that actually happened.
`POST`/`DELETE /api/v1/audit` return `404` because the route does not exist, and
that is the intended permanent answer. Log rotation, when it is needed, is an
operator-and-filesystem concern outside this API, and it should archive rather
than truncate.

The audit trail is **sensitive operational history**: it names every model that
went live and when, every dataset built or deleted, and every training run. It
therefore inherits the API's §21 posture unchanged — bound to loopback by
default, unauthenticated until RBAC lands (issue #58), and never to be exposed
beyond localhost before then. It is strictly more sensitive than
`/api/v1/classifications`, and the SPA says so where it renders it.

### 4. Three audit gaps closed

Reading the log as a sequence of state changes exposed cases where the log
disagreed with reality. All three are fixed:

- **The implicit demotion was invisible.** `registry.SetStatus` enforces a single
  active entry, so activating B silently demotes A. Only B's line mentioned it
  (`replaced=A`), so "the most recent record for A" still said *activated* while
  A was not live. `handleModelActivate` now writes a `ModelDeactivated` record
  under **A's own subject**, ordered before B's activation, so per-model reads
  give the right answer.
- **The restart reconciliation was unaudited.** A model active at shutdown is
  loaded back as `deactivated` — a genuine state change with no record of it.
  `registry.Reconciled()` now reports the IDs `Open` demoted, and `cmd/synapsed`
  audits each one. The reconciliation is persisted, so this is written once, not
  on every boot.
- **`ModelRegistered` was written on every boot.** `Register` is idempotent, so
  the startup sweep re-registered known bundles and appended a duplicate line
  each restart, burying real changes in noise. The daemon now audits only a
  genuinely new registration.

A fourth, smaller honesty fix: deactivating an entry that was never the live
primary is a legal no-op, and its record no longer claims it "restored the
heuristic".

### 5. `ML ▸ Models` — the registry view, gated on confirmation

The placeholder is replaced with the §19.12 field set: a registry table (id,
name/version, family, status pill, parameter count, artifact size, short content
hash, created, trainer version, live-in-runtime), a detail pane with schemas and
I/O sizes, a read-only architecture breakdown reusing `lib/arch`'s
`layerBreakdown`, training dataset ids, metrics, the confusion matrix, lineage as
a small tree (§15), and the audit trail — scoped to the selected model, plus a
global view with a chip per subject type.

`architecture` and `metrics` are rendered **defensively**. Both are
pass-throughs from a bundle's own JSON (`metrics` is a `json.RawMessage` the
daemon never inspects field-by-field), so the view parses what it recognises,
lists the remaining scalars verbatim, and says "not reported" rather than
inventing a zero. An unreported metric is missing, not 0.0.

**The activation workflow is the point of the issue.** `Activate` opens a
confirmation that names the model, states in plain words that it will become the
primary classifier for **all live traffic**, names what it replaces (the
previously active model, or the built-in heuristic), lists the content hash,
parameter count, artifact size and provenance, and states that the action is
audited and **does not survive a restart**. `Deactivate` confirms that the
heuristic will be restored. A `409` from the daemon — the bundle no longer loads,
no longer validates, or cannot be compiled — is surfaced **verbatim**, because a
paraphrase of a validation failure is worse than useless when deciding whether to
trust a model.

There is deliberately **no** "auto-activate on register" affordance, no "activate
the newest model", and no bulk activate. §28.10 is not a preference to be
defaulted; it exists because a model that silently starts classifying production
traffic is a model nobody vetted, and an IDS whose detector changed without a
recorded human decision cannot be trusted or debugged after an incident. A
convenience toggle would be the exact mechanism the rule forbids, so the UI
offers no switch that could grow into one. Every path that makes a model live
runs through one confirmed operator action and leaves one audit line.

## Consequences

- §21's audit requirement is now actually met: the trail is inspectable by the
  people who need it, through the same API and UI as everything else.
- The audit log's usefulness now depends on the reader's bounds being understood.
  `MaxScanBytes` means a very old event is on disk but not in the API. This is
  documented in `docs/api.md` and stated in the UI, and it is the right trade:
  an unbounded read is a worse failure than a bounded view.
- Newest-first is now a contract. Callers wanting chronological order reverse the
  slice; the tests assert the ordering so it cannot drift silently.
- Audit coverage for models, datasets and training runs is asserted by a test
  that drives all three through the API against one log, so a future state-change
  handler that forgets to audit is a test failure, not a silent gap.
- Human label changes (issue #42) are still the one §21 category with no writer.
  The read path, the route and the UI are already generic over it and need no
  change when it lands.
- `Registry` grew one accessor (`Reconciled()`), used only by the daemon's
  startup audit.
- Some state-changing routes still do not audit — `POST /api/v1/captures`,
  `DELETE /api/v1/captures/{name}`, `POST /api/v1/replay`. They are outside §21's
  four named categories and are left alone here rather than expanded into scope,
  but the global audit view makes their absence conspicuous, which is the point.
- The SPA grows ~5.8 KB gzip of JS and ~0.3 KB gzip of CSS.

**Revisit when:** issue #42 adds `review` lines (verify they appear in the chips
with no code change); issue #58 adds auth/RBAC, at which point `actor` stops
being the constant `"local"` and the audit trail becomes genuinely attributable —
the field is already in the record shape for exactly this reason; or the log
grows large enough that rotation is needed, which is when `MaxScanBytes` should
be reconsidered alongside an archive format.

---

⟦THUGS⟧ (c) 2026
