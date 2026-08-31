# 0025 — The Flow Inspector explains the heuristic exactly, and claims nothing else

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §19.3 lists fourteen things the Flow Inspector must show for a selected
flow. Most of them shipped with the SPA (#20) and were extended by the
investigation work and the human review loop (#42): the full tuple and
direction, sensor, timing, packet/byte statistics, TCP metadata, all 48 raw
`flow-features-v1` values joined to the frozen schema, the complete
`traffic-classes-v1` probability vector, per-model outputs, the disagreement
flag, and human review status.

Four items were still labelled stubs in the drawer: **normalized model inputs**,
**historical snapshots of the flow**, the **anomaly score**, and the
**explanation panel** ("a useful explanation panel such as top feature
contributions or deviation from training baseline"). Issue #38 closes them.

Three facts about this build shape the whole decision:

1. **Normalization is a per-model concern** (§8, CLAUDE.md). `pipeline.Run` hands
   `inference.Runtime` the *raw* vector. `Heuristic` reads raw values;
   `ONNXModel` applies the normalizer built from its own bundle's
   `normalizer.json`. There is no pipeline-wide normalized vector, so there is no
   single "normalized input" to display.
2. **There are no training baselines.** §19.3's example shows a "Current vs
   Baseline" table, but behavioural baselines are Phase 7. `insight.Profile` and
   `report.Coverage` already report `baseline_available: false` precisely so a
   client can label the gap.
3. **`storage.Mem` was discarding snapshot history.** `flow.Table` emits a
   `ReasonSnapshot` record per interval for a long-lived flow plus a terminal
   record, and `pipeline` stores every one of them — but `Mem.byID` was
   `map[uint64]FlowRecord`, one entry per flow id, last write wins. The ring
   held every version; nothing could address them by flow id.

## Decision

### Two sibling routes, not a fatter flow-detail route

`GET /api/v1/flows/{id}` keeps its documented contract — "a single
`storage.FlowRecord`" — because several views depend on that exact shape. The
additions are two single-purpose siblings, answering two different questions:

- `GET /api/v1/flows/{id}/explain` — per-model inputs and the verdict's rationale
- `GET /api/v1/flows/{id}/snapshots` — the retained version history of one flow

A test pins the flow-detail route's key set so it cannot drift.

### Normalized inputs are reported per model, from that model's own bundle

`/explain` builds `models[]` from the **stored classification's**
`Result.Models` — the models that actually scored this flow — not from whatever
is loaded now. Each entry reports an `input.kind`:

| `kind` | meaning |
|:--|:--|
| `raw` | the model scores raw values. `features` is **absent**: there is no transformation, and rendering an identity table would imply a step that does not happen. This is the `Heuristic`. |
| `normalized` | raw→normalized pairs for all 48 features, from the model's own `normalizer.json` via `registry.Active()` → `model.Load` → `Bundle.Normalizer()`. |
| `unknown` | the normalizer could not be resolved (no registry, nothing active, the verdict's model is no longer loaded, or the bundle is gone). Nothing is shown and `note` says why. |

Because `model.Load` reads and sha256-hashes `model.onnx`, resolved normalizers
are cached per `<model id>@<content hash>` for the process lifetime — a
registered bundle is immutable, which makes the content hash a sound key. Same
reasoning as `dataset.Stats`.

A model named in a stored verdict but no longer in the runtime is reported with
`loaded: false`; its verdict is still shown, because it really happened, but its
inputs and rationale are not reconstructed.

### The explanation panel: exact for the heuristic, absent for trained models

`inference.Explanation` carries a `kind` that governs what the panel may claim.

**`kind: "rules"` — an exact account.** `Heuristic.Classify` and
`Heuristic.Explain` both call one private `evaluate(v, explain bool)`, so the
fired-rule list is produced by the *same* evaluation that produced the verdict
and cannot drift from it. Each `FiredRule` carries a stable id
(`<class>.<condition>`), a human sentence, and the **feature values its condition
compared**, each with its schema name and unit. `class_weights` reports the real
pre-softmax weights. A test asserts that soft-maxing the reported weights
reproduces `Classify`'s scores bit-for-bit, which is what makes the panel
trustworthy rather than decorative.

This is the highest-value part of the issue: it turns `SCAN 99.3%` into
"because `tcp_syn_count=1`, `packets_backward=0`, `flow_duration=0s`".

There is deliberately **no per-rule contribution percentage**. Several rules can
feed one class, and rule→probability runs through a softmax over class weights,
so any per-rule share would be invented.

**An empty rule list is a finding, not an empty state.** When nothing fires, the
panel says so and reports `normal_prior` (3.0) as what actually decided the
verdict, with the explicit warning that "nothing was detected" is not the same as
"checked against a baseline and found normal". The UI boxes this rather than
leaving dim text that reads like a failed load.

**`kind: "unavailable"` — for a trained model, nothing is claimed.** An exact
attribution needs gradients or SHAP over the network. `internal/nn` deliberately
exposes only `Run`/`InputSize`/`OutputSize`/`OpCounts` and no weights, so even a
first-layer-weight linear proxy would mean inventing new `nn` accessors — not
cheap, and not honest either: a proxy rendered as bars in a panel captioned
"explanation" reads as an explanation no matter what the caption says. So
`*ONNXModel` does not implement `inference.Explainer`, and the API returns prose
saying attribution is not implemented, pointing at the full class-probability
vector as the model's complete output. A test asserts `*ONNXModel` is **not** an
`Explainer`, so it cannot acquire a fake one by accident.

### Why there is no baseline column

§19.3's example table has a `Baseline` column. This build does not have one and
will not fake one. A fabricated "expected range" is worse than an absent one: it
converts *"this was never checked"* into *"this was checked and looks fine"*,
which is exactly the failure mode an IDS must not have. So:

- `/explain` returns `baseline: {available: false, note: …}` — two keys, and
  **no value field**, so there is nothing for a client to plot.
- The drawer prints "**No baseline comparison.**" where the column would be.
- A test asserts on the raw JSON that the `baseline` and `anomaly` objects carry
  exactly `available` + `note`, and that the strings `anomaly_score`,
  `baseline_value`, `baseline_range` and `training_baseline` appear nowhere in
  the response.

The anomaly score is handled identically (Phase 7, §13) and gets its own labelled
section in the drawer, which it previously did not have — it had been folded into
the explanation stub.

### Snapshot retention: a bounded per-flow history

`storage.Store` gains `FlowHistory(id) []FlowRecord`, oldest first.
`Mem.byID map[uint64]FlowRecord` becomes `hist map[uint64][]flowVersion`.

Two independent bounds:

- **Global:** the existing flow ring. Every retained version corresponds to
  exactly one live ring slot, so total versions held can never exceed
  `storage.max_flows` regardless of how many flows snapshot. Memory is what it
  was.
- **Per-flow:** `storage.FlowHistoryCap = 64` versions, oldest dropped first,
  counted in the new `Stats.FlowVersionsDropped` (distinct from `FlowsEvicted`).
  At the default 60s `snapshot_interval` a flow must stay open for over an hour
  to reach it. `/snapshots` reports `truncated: true` when it bit — detected
  exactly, since a flow's first snapshot carries index 1, so a history starting
  above that is missing earlier versions.

Versions are identified by an internal monotonic sequence number, **not** by
`SnapshotIndex`. This also fixes a latent bug: `flow.Table` increments
`SnapshotIndex` on the live entry, so a long flow's terminal record inherits the
last snapshot's index. The old eviction guard compared
`cur.SnapshotIndex == old.SnapshotIndex` and therefore deleted the map entry for a
flow whose *older* duplicate-index snapshot left the ring — a **spurious 404 from
`GET /api/v1/flows/{id}` for a flow whose terminal record was still retained**.
A regression test covers it.

Each version is paired with the verdict computed from it: `pipeline` stamps
`Classification.TS` from the record's `LastSeen`, so this is an exact timestamp
join, consumed so two versions sharing a `last_seen` cannot claim one verdict. A
version whose verdict has aged out reports `verdict: null` and the response notes
the retention gap — never "was not classified".

## Consequences

- An operator can read *why* a Phase-1 verdict happened, exactly, and watch a
  long flow's counters and verdict evolve. On a real 28 MB capture this is 1176
  addressable flow versions where it was previously 1124.
- `flow.Table`'s `SnapshotIndex`-on-close behaviour still contradicts the frozen
  schema text for feature 47 (`"nth periodic snapshot of a long-lived flow; 0 on
  close"`). This ADR deliberately does **not** change it: feature 47 feeds the
  golden vectors and every dataset CSV, so correcting it is a separate, reviewed
  change. `/snapshots` surfaces the duplicate index in a note instead. **Tracked
  as a follow-up.**
- The explanation panel is only as good as the heuristic, which is a hand-tuned
  stand-in and not an operational detector (ADR 0003). Making its rules legible
  makes that limitation legible too, which is the point.
- When Phase 2 puts a trained model in front of live traffic, the explanation
  panel goes quiet for it. That is the intended, visible cost of not shipping a
  proxy — and it is what will justify real attribution work later.
- `Store` grew a method. `Mem` is still the only implementation, so the SQLite
  work must implement `FlowHistory` with the same two bounds.

**Revisit when:** Phase 7 lands anomaly scoring and behavioural baselines — the
two stub sections become real, and §19.3's "Current vs Baseline" table can finally
be built. Also when a trained model becomes the default primary and per-feature
attribution (integrated gradients over `internal/nn`, most likely) is worth its
own issue.

---

⟦THUGS⟧ (c) 2026
