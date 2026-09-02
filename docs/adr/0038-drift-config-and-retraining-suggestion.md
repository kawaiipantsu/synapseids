# 0038 — A drift config block and an advisory retraining suggestion

**Status:** Accepted, 2026-09-02

## Context

[ADR 0036](0036-feature-drift-monitoring.md) shipped `GET /api/v1/drift` with the
per-feature bands (`warn` at `z ≥ 2`, `drift` at `z ≥ 4`) as **documented
constants**, and explicitly left "a `drift.*` config block" and PROJECT.md
§19.13's "surface a retraining suggestion when drift crosses a threshold —
suggestion only" as follow-ups. Issue #65, the last non-idea leaf of EPIC Phase 7
(#7).

## Decision

### A `config.Drift` block

`Config` gains a `drift` block (JSON and the hand-rolled YAML both, one schema,
`DisallowUnknownFields`, `validate()`):

| key | default | meaning |
|---|---|---|
| `warn_z` | `2.0` | per-feature `warn` band on the standardized mean shift `z` |
| `drift_z` | `4.0` | per-feature `drift` band |
| `retrain_suggest_z` | `6.0` | overall `max_z` at/above which retraining is suggested |
| `retrain_suggest_features` | `3` | that many features individually in the drift band also suggests it |

`ValidateDrift` requires all three `z` values `> 0` and ordered
(`warn_z ≤ drift_z ≤ retrain_suggest_z`) and `retrain_suggest_features ≥ 1`. The
`drift.go` route reads `s.cfg.Drift` instead of the ADR 0036 constants;
`driftStdEps` stays a constant (it is a numeric floor, not a policy knob).

### An advisory `suggestion` object

When a training baseline exists, the response gains:

```json
"suggestion": {
  "retrain_suggested": <max_z ≥ retrain_suggest_z  OR  features_drift ≥ retrain_suggest_features>,
  "reason": "<which trip fired, naming the active model — or why none did>",
  "advisory": "Suggestion only. Retraining and activation are always an explicit operator decision (PROJECT.md §19.13, §28.10)."
}
```

It is absent when `state` is `no_baseline` (nothing to compare against, so
nothing to suggest). It is **read-only advice**: no event, no storage, no
packet-path work, and the daemon never retrains, deploys or activates a model —
consistent with ADR 0036 and PROJECT.md §28.10. A stronger "drift high **and**
the anomaly model is firing → retrain" signal can fold in the `Result.Anomaly`
data added by #47 later without changing this shape.

## Consequences

- Operators can tune the drift bands and the suggestion sensitivity per
  deployment without a rebuild; the shipped `contrib/config/synapse.{json,yaml}`
  carry the defaults.
- The SPA Drift view (#49 stub) can render the suggestion banner as soon as it is
  built.
- The metric is still the coarse `z` from ADR 0036; a distribution-distance
  measure (PSI/KL) remains a later refinement and the `suggestion` shape does not
  change when it lands.
