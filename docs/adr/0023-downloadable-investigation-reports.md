# 0023 — Downloadable investigation reports are server-rendered, self-contained artefacts

**Status:** Accepted, 2026-08-31

## Context

Investigation mode (PROJECT.md §19.4, ADR 0016) gives an operator everything they
need *while they are looking at the daemon*. Issue #66 is about the moment after
that: they have found something, and now they have to hand it to someone else —
attach it to a ticket, mail it to a peer team, paste it next to an incident
write-up, keep it as the record of what the sensor saw at 02:14 on a Tuesday.

Today that is impossible without screenshots. Everything lives behind the live
API, which means the recipient needs network access to the daemon, an account on
whatever fronts it, and the same data still retained in `storage.Mem`'s ring by
the time they look. None of those hold for the people who most need the
information.

Three things make this harder than "serialise the profile":

1. **The data is deliberately lossy.** `storage.Mem` is a bounded ring that
   evicts. `internal/insight`'s host map is capped at 2048 addresses and its
   per-host top-N lists at 128 distinct ports and peers, with the lowest-count
   half discarded on overflow — a port scan evicts its own tail *by design*.
   Every one of those discards is counted. A report that silently presents a
   pruned top-N as "this host's ports" is worse than no report.
2. **Half of §19.3/§19.4 does not exist yet.** Behavioural baselines, anomaly
   history and unusual-feature callouts are Phase 7. ADR 0016 already decided not
   to fake them, and the SPA labels them as stubs. A downloadable file has no
   such context: an empty anomaly chart in a document someone reads a week later
   reads as *"checked, nothing anomalous"*.
3. **Every string in it is untrusted.** Addresses, protocol names, sensor names,
   close reasons, model IDs, traffic-class names from a bundle, and the filter
   string echoed back from the query — all packet- or request-derived (§21,
   §28.11). The output is a document an operator opens in a browser, which is a
   markup-injection sink, and it is then forwarded and re-opened somewhere with
   fewer defences than the SPA.

## Decision

A new package, **`internal/report`**, builds a report from live state and renders
it as JSON or as one standalone HTML file. Two read-only REST routes serve it.

### The report is a snapshot, not a query result

`report.Build(Sources, Options) (*Report, error)` reads `storage.Store`,
`*insight.Index` and `*inference.Runtime` — nothing else — and returns a struct
that carries everything an outside reader needs:

- the generation time and the exact daemon `version` / `commit` / build date, so
  a reader can tell how stale the artefact is;
- the frozen `feature_schema` / `output_schema` IDs, so two reports can be told
  apart when the contracts move;
- the scope: the host address, or the time window, plus whether the window was
  bounded at all and which classification filters applied;
- the host profile (host scope), the in-scope classification breakdown, the
  timeline buckets, top peers / ports / protocols;
- the **notable flows** — every in-scope verdict that either disagreed across
  models (§12) or landed on something other than `normal` — each with its tuple,
  timing, volume, ensemble verdict, **every model's own output**, and the named
  raw `flow-features-v1` values behind it, plus a legend so those values are
  interpretable offline;
- the active model set at generation time.

`Build` is deterministic given the same state and the same `Options.GeneratedAt`,
which is what makes the content assertable in a test. Every ordering is total:
notable flows sort by (disagreement, then descending confidence, then newest,
then flow ID), classes are in frozen schema order, top-N ties break on the key.

Nothing here measures anything new. `Build` is an aggregation and the renderers
are projections — this is why it is a package and not two handlers: the selection
and honesty rules are unit-testable without an HTTP round trip, and the two
routes stay one mux line each.

### Honesty rules are structural, not best-effort

This is the part of the design that matters most. A report is an artefact someone
may act on, so **not misleading the reader outranks completeness**. Three rules
are enforced by the type, not by discipline:

`Coverage` is the machine-readable half — every limit that applied and every
discard the daemon had already made, with `partial: bool` as the single flag a
consumer can branch on. `Notes []Note` is the human-readable half: a `code`, a
`level`, and prose that names the actual numbers.

| condition | `Coverage` field | note code | what the reader is told |
|---|---|---|---|
| baselines/anomaly not computed | `baseline_available`, `anomaly_available` (always false) | `baseline_unavailable` | *unconditional* warning that Phase 7 has not landed and that the **absence of an anomaly finding does not mean the traffic was checked against a baseline and found normal** |
| feature table is a fixed subset | — | `feature_attribution_unavailable` | the per-flow features are the named values this build's classifier reads, **not** a ranked attribution |
| record ring evicted | `flows_evicted`, `classifications_evicted` | `partial_store_evicted` | PARTIAL VIEW, with the counts, the retained totals and the driver |
| report scan filled its budget | `scan_exhausted`, `scan_limit` | `partial_scan_window` | PARTIAL VIEW, naming the budget and the oldest verdict considered |
| window predates retention | `range_starts_before_retention` | `partial_before_retention` | PARTIAL VIEW, naming both timestamps |
| host map evicted | `hosts_evicted`, `host_cap` | `partial_hosts_evicted` | PARTIAL VIEW, naming the cap |
| top-N pruned | `keys_pruned`, `key_cap` | `partial_topn_pruned` | PARTIAL VIEW: top ports/peers are exact for heavy hitters and incomplete for long tails; **per-host totals are unaffected** |
| aggregation queue dropped | `observations_dropped` | `partial_observations_dropped` | PARTIAL VIEW: counters undercount by up to that much |
| verdicts missed their bucket | `timeline_late` | `partial_timeline_late` | PARTIAL VIEW: missing from the series, counted everywhere else |
| notable list capped | `notable_flows_truncated`, `notable_candidates` | `flows_truncated` | TRUNCATED, naming both counts and how to narrow the scope |
| verdict outlived its flow record | `flow_records_missing` | `flow_records_missing` | those rows are **marked**, not shown as zeroes |
| no store / index / model wired | — | `no_store`, `no_insight`, `no_models` | the section is empty for reasons unrelated to the traffic |

Two smaller consequences of the same principle:

- A `NotableFlow` whose `FlowRecord` has already been evicted carries
  `record_available: false` and an **empty** `features` array, and the HTML prints
  `—` — never a zero that reads as a measurement.
- An empty timeline renders as *"this is an absence of retained data, not a
  statement that the window was quiet"*, and the timeline panel always states
  that there is no anomaly series because none is computed.

### `html/template` is the injection control, not a style choice

The HTML path renders through **`html/template`**. This is a security decision
and is recorded as one.

`text/template` would compile the same template source, produce identical output
for benign input, and emit `<script>alert(1)</script>` verbatim for a crafted
hostname, sensor name or filter string. `html/template`'s contextual
auto-escaping is applied by the engine per context (element text, attribute
value, URL, CSS, JS) rather than by remembering to call a helper, which is
exactly the property a document assembled from ~15 untrusted string sources
needs.

Two further choices follow from taking that control seriously:

- **No untrusted value reaches a CSS or URL context.** Per-class colours are
  selected by a *class suffix* drawn from a closed table (`classSuffixes`) against
  pre-declared `.f-*` rules, so an attacker-controlled class name picks a rule or
  falls through to `--dim` — it is never interpolated into a stylesheet.
  (`html/template`'s `cssValueFilter` would reject a `var(--x)` value anyway.) The
  only CSS interpolation left is a bar width, which is a Go-formatted `"%.1f%%"`.
  There are **no** URL-bearing attributes in the document at all — no `href`, no
  `src`, no `action` — so there is no URL context to escape into.
- **The document is entirely self-contained.** One inline `<style>`, no external
  stylesheet, no CDN, no `<script>`, no `<img>`, no webfont, no `data:` URI. It
  opens from `file://` with no network access, which also means there is nothing
  loadable for a crafted value to point at. A `@media print` block flips the dark
  palette to ink-on-white so the same file prints.

**Tests.** `TestHTMLEscapesHostileStrings` feeds eleven payloads —
`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`,
`'><svg/onload=alert(1)>`, `</style><script>…`, `</title><script>…`,
`javascript:alert(1)`, `" onmouseover="alert(1)`,
`</textarea></noscript><iframe src=//evil.example>`, a CRLF payload, a
`{{template}}` action and a CSS-breakout attempt — through the host address, a
peer address, the protocol name, the sensor name, the close reason, the model ID,
the traffic-class name and the echoed filter description. It asserts the payload
reaches the document model, does not survive verbatim, and that a tag-level scan
of the output finds no element outside an allowlist and no attribute outside an
allowlist (so no injected element and no `on*` handler exists anywhere).

`TestTextTemplateWouldNotEscape` is the negative control: it renders the *same*
template source through `text/template` and asserts the payload **does** come out
verbatim. Without it the escaping test could pass for the wrong reason — a value
that is never rendered is trivially "escaped". `TestHTMLHasNoExternalReferences`
asserts the self-containment claim.

### Bounding

A report is a download, not a database export.

| bound | default | ceiling |
|---|---|---|
| notable flows listed | 500 | 2000 (`limit=`, clamped) |
| stored verdicts walked | newest 5000 | — |
| timeline buckets | as `insight` (max 1440) | — |
| top peers / ports / protocols | 16 each | — |

The scan limit is the same substitute-for-an-index that filtered
`/api/v1/classifications` and the `/api/v1/hosts/{ip}/*` collections already use;
`storage.Mem` has no index beyond flow ID. Both bounds are reported in
`Coverage` and both produce a note when they bite.

### API surface

Two read-only routes in `internal/api/reports.go`, one mux line each:

```
GET /api/v1/reports/host/{ip}?format=json|html&from=&to=&bucket=&limit=&class=&model=&min_confidence=&disagreement=
GET /api/v1/reports/range?format=json|html&from=&to=&bucket=&limit=&class=&model=&min_confidence=&disagreement=
```

`{ip}` is re-parsed and canonicalised with `net/netip` (`400` on a non-literal,
`404` on an address `insight` has never observed). The optional filters reuse
`parseClassFilters` **verbatim**, so `class=`, `model=`, `min_confidence=` and
`disagreement=` mean exactly what they mean on `/api/v1/classifications` and a
filtered report agrees with a filtered list; the report echoes the applied
predicates back in `scope.filter`.

Both formats respond with `Content-Disposition: attachment; filename="…"` so a
browser downloads rather than renders inline, plus `Cache-Control: no-store` (a
snapshot must not be served stale from a proxy) and `X-Content-Type-Options:
nosniff`. The filename comes from `Report.Filename`, which reduces the scope
segment to `[a-z0-9._-]`, collapses `-` runs and trims leading punctuation — so a
crafted address can neither break out of the quoted header parameter nor produce
a traversal or a dotfile when the browser writes it.

**`api.New` gains no parameter.** The routes read the `store`, `insight` and `rt`
the `Server` already holds, which also keeps this branch out of the way of the
sibling branches that *are* extending the constructor.

### Sensitivity

These routes are read-only, so like `/api/v1/hosts*` they need no
explicit-action gate. But a report is a **concentrated** dump of sensitive
telemetry in a form built to be forwarded: one unauthenticated GET yields every
observed peer of a host, its service ports, its volume, its verdicts, and the raw
feature values behind them, packaged as a file that will outlive the daemon's
retention window and travel further than any API response. It inherits the
loopback-only default and the standing requirement for an authenticating proxy on
any non-loopback listener (§21).

This is a **stronger** argument for the API authentication work (#58) than the
individual read routes are: the blast radius of one unauthorised request is much
larger, and unlike a live API response the artefact cannot be un-shared.

### SPA

Deliberately thin, because the rendering is server-side. `#/investigate?host=`
gets a **Download report** control with HTML and JSON links that carry the
currently-brushed timeline range and the active class/disagreement filters — the
operator has already framed the window they care about, so the artefact should
describe that and not silently widen back to everything. `#/hosts` gets a
per-row `report` link (no range: a list row has no framed window, and the report
says so in its own scope block). Both are plain `<a href>` navigations, so the
browser's own download path and the daemon's chosen filename are used rather than
a `fetch`+`Blob` that would hold a large document in JS memory.

## Consequences

- One new package with no new dependency. `internal/report` imports `features`,
  `inference`, `insight`, `schema`, `storage`, `version` and stdlib
  `html/template` + `encoding/json`. It imports neither `api` nor `pipeline`, so
  the data plane is untouched and the packet path is not on this path at all.
- `DecisionFeatures` — the named subset carried per flow — is currently the exact
  set the Phase-1 heuristic reads, ordered by frozen schema index, and
  `orderedBySchema` **panics at init** on a name `flow-features-v1` does not
  define. A typo would otherwise ship a silent column of zeroes into an artefact
  someone acts on. When a trained model replaces the heuristic, this list is the
  thing to revisit, and the `feature_attribution_unavailable` note is the marker.
- `investigation-report-v1` is a new versioned document. It is not frozen the way
  `flow-features-v1` is, but it is versioned for the same reason (§28.14): a
  breaking change becomes `-v2` rather than a silent re-meaning.
- The report inherits every limit of the read models it draws on, and now says so
  out loud. When SQLite lands (§20) the scan-budget note should become rarer and
  the `from`-before-retention note more meaningful; neither goes away.
- Reports are generated on demand and never stored. There is no report history,
  no scheduled export and no e-mail. Those are plausible later features; none is
  needed to make the artefact useful, and each would add retention questions to a
  document explicitly full of sensitive telemetry.

## Deliberately deferred

- **Baselines, anomaly scores and per-feature attribution** — Phase 7 (§13,
  §19.3, §19.4). Present as explicit unavailability notes, never as an empty
  chart or a zero.
- **Related detections** (§19.4) — there is still no `/api/v1/detections`
  resource and nothing publishes `AlertCreated`, so a report does not have a
  detections section rather than having an empty one.
- **PDF.** A `@media print` block on a self-contained HTML file gets the same
  result through the browser's own print-to-PDF, with no renderer, no font
  embedding and no new dependency (§27, §28.16).
- **Human review status** (§16) — no review store exists yet; when it does, the
  notable-flow rows are the natural place for it.
