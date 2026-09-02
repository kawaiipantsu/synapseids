# 0036 — Feature drift monitoring against the active model's training distribution

**Status:** Accepted, 2026-09-01

## Context

PROJECT.md §19.13 asks for a Drift view: "Compare current feature distributions
with model training distributions. Show drift per feature and overall drift
state. Drift is informational initially; do not automatically retrain/deploy
models without an explicit policy and operator approval." Issue #49, part of
EPIC Phase 7 (#7).

The SPA already carries a labelled `#49` Drift stub (issue #118). The pieces the
comparison needs are all present:

- every stored `FlowRecord` carries its raw `flow-features-v1` vector
  (`internal/storage`);
- a trained bundle's `normalizer.json` records, for a `standard` normalizer, the
  per-feature training **mean** and **std** — which *is* a summary of the
  training feature distribution (`internal/model`, ADR 0006/0007);
- the registry knows which model is active (`registry.Active`).

Constraints: zero third-party deps (CLAUDE.md); nothing on the packet path
(§22); no fabricated numbers where a signal is missing (§16).

## Decision

### A read-side API route, no new package, no packet-path work

`GET /api/v1/drift` folds the newest window of stored flow vectors on demand —
the same pattern `GET /api/v1/matrix` uses for a filtered query
(`internal/api/drift.go`). One Welford pass computes the current per-feature
mean and std over up to 5000 rows × 48 values; the route is operator-facing and
low-QPS, so an incremental aggregator (an `internal/insight`-style goroutine)
would be more machinery than the job needs. `from` / `to` and the shared
`sensor` / `location` scope filter the window.

### The reference is the active bundle's `standard` normalizer

The per-feature drift metric is the **standardized mean shift**

```
z_i = |current_mean_i − training_mean_i| / training_std_i
```

with `training_std_i` floored at 1e-9 (the trainer already floors it). Bands:
`stable` (`z < 2`), `warn` (`2 ≤ z < 4`), `drift` (`z ≥ 4`); the overall `state`
is the worst band present. `std_ratio_i = current_std_i / training_std_i` is
also reported so a change in spread with a steady mean is still visible.

> The bands were documented constants here; the `drift.*` config block and an
> advisory retraining suggestion followed in issue #65 /
> [ADR 0038](0038-drift-config-and-retraining-suggestion.md).

`z` is a coarse first-cut signal, deliberately. A distribution-distance measure
(PSI, KL, a two-sample test) is a better metric and is left for when a trained
model and real drift exist to tune it against; the response shape (a per-feature
object with a `state`) does not change when the metric is upgraded.

### No baseline is a state, not a guess

`identity` and `minmax` normalizers carry no mean+std pair, and a daemon running
only the heuristic has no training distribution at all. In those cases `state`
is `no_baseline`, `baseline.source` is `none`, a `baseline_note` explains why,
and the per-feature `current_mean` / `current_std` are still returned (§16: a
labelled gap is correct, a fabricated zero is a defect). `minmax` as a baseline
(its file *does* summarise the training range) is a possible follow-up.

### Informational only

The route computes and reports. It never retrains, never deploys, never
activates (`advisory` string in the payload; PROJECT.md §19.13, §28.10). EPIC
Phase 7 stays open — this is one leaf of it.

## Consequences

- The SPA's Drift stub can render real per-feature bars and an overall state as
  soon as a `standard`-normalized model is active; until then it shows the
  labelled `no_baseline` state and the current distributions.
- Reading `normalizer.json` per request is one small-file read on a low-QPS
  route; unlike the Flow Inspector's normalized-inputs path it does not call
  `model.Load` (no ONNX hashing), so no cache is warranted yet.
- The metric will be revisited (PSI/KL) when there is real drift to calibrate
  against; the API contract is stable across that change.
- Per-sensor drift falls out of the shared `sensor=` / `location=` scope for
  free.
