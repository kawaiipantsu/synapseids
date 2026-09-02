# 0037 — Anomaly autoencoder model as a second model family

**Status:** Accepted, 2026-09-02

## Context

PROJECT.md §13 asks for a separate novelty detector once the supervised
classifier works: "add a separate anomaly model such as an autoencoder … Do not
force unknown behavior into a known attack class simply because softmax always
has a maximum." §26 lists the anomaly autoencoder as the first Phase 7
deliverable. Issue #47, part of EPIC Phase 7 (#7).

The runtime is already shaped for it: `inference.RoleAnomaly` exists,
`inference.Runtime.Score` already excludes an anomaly-role model from the verdict
and the disagreement set, and roughly a dozen surfaces — `GET
/api/v1/flows/{id}/explain`, the timeline, insight host profiles, the downloadable
report, and the SPA Flow Inspector / Dashboard / Timeline / Hosts / Investigate
views — carry labelled "anomaly scoring is Phase 7, NOT AVAILABLE" stubs that are
placeholders for a real score field.

What is missing is an actual model. An autoencoder is a 48-input / 48-output
network — it reconstructs the feature vector and the reconstruction error is the
novelty signal. That collides with three frozen assumptions:

- `traffic-classes-v1` is a frozen 7-class contract, and the whole trained-model
  path (`schema.ValidateBundle`, `schema.ValidateArchitecture`,
  `inference.NewONNXModel`, `inference.Scores [7]float64`) is hard-wired to it.
- `internal/registry` allows exactly one Active entry, and
  `inference.Runtime.Activate` replaces the entire live model set with a single
  primary — there is no way to run a primary classifier and an anomaly model
  together.
- The Python trainer (`trainer/synapse_trainer/`) is locked to the
  `flow-classifier-v1` family: 48→7, cross-entropy loss, softmax at export.

Constraints unchanged: zero third-party Go deps, `CGO_ENABLED=0`, nothing on the
packet path (§22), no fabricated numbers where a signal is missing (§16), never
reorder or re-mean a released schema (§8, §9, §28.5-6).

## Decision

### A new frozen output contract: `reconstruction-v1`

`schemas/outputs/reconstruction-v1.json` — `frozen: true`, `version: 1`,
`output_size: 48`. Its 48 entries mirror `flow-features-v1` element for element:
`index` 0..47, `name` = the corresponding feature name, `description` =
"reconstruction of `<feature>`". `internal/schema`'s `init()` gains a guard that
the entry count is 48 and the names match `flow-features-v1` in order, so the
reconstruction target ordering is locked to the feature vector it mirrors.

Rejected: reusing the string `"flow-features-v1"` in the bundle's
`output_schema` slot. That is an *input* contract carrying per-entry
`calc`/`unit`/`norm`/`missing` metadata that is meaningless in an output
position, and it would force every validator to special-case an input name where
an output name is expected. A distinct name lets the daemon recognise an
autoencoder bundle from the `(family, output_schema, output_size)` tuple alone.

### A new model family: `flow-anomaly-v1`, and family-aware validation

`internal/schema` gains a family table:

| family              | feature_schema  | input | output_schema      | output |
|---------------------|-----------------|-------|--------------------|--------|
| `flow-classifier-v1`| `flow-features-v1` | 48  | `traffic-classes-v1` | 7    |
| `flow-anomaly-v1`   | `flow-features-v1` | 48  | `reconstruction-v1`  | 48   |

`ValidateBundle` switches on `BundleMeta.Family`. The `flow-classifier-v1` branch
keeps its four current checks unchanged — a bundle that passed still passes, one
that failed still fails. An unknown or empty family is an error.

A new `ValidateArchitectureForFamily(family, a)` carries the family-aware edge
check (`flow-anomaly-v1` requires `input_size == output_size == 48`); the
existing `ValidateArchitecture(a)` becomes a thin wrapper =
`ValidateArchitectureForFamily("flow-classifier-v1", a)` so existing callers and
`architecture_test.go` do not move. `validateHiddenStack` is objective-neutral
and unchanged: a symmetric encoder→bottleneck→decoder is expressed as one flat
`hidden[]` list, and `ParameterCount`/`RoughFLOPs` are already generic over
`OutputSize`.

### A parallel Go interface, not an overloaded `Classifier`

`Classifier.Classify` returns `Scores`, a fixed `[7]float64`. Routing a 48-wide
reconstruction through it is exactly the wart to avoid, so anomaly models
implement a sibling interface:

```go
type AnomalyScorer interface {
	ID() string
	Family() string
	Role() Role                       // always RoleAnomaly
	ScoreAnomaly(v features.Vector) AnomalyOutput
}
```

`Runtime.Score` type-switches per live model: a `Classifier` takes today's path;
an `AnomalyScorer` gets `ScoreAnomaly`, and its result is attached to
`Result.Anomaly` — never added to the disagreement set, never a verdict driver.

### Reconstruction error → a bounded, comparable score

The error is measured in **normalised** space (what the net sees, so per-feature
terms are comparable): `err = mean_i((in_i − out_i)^2)`. The bundle records the
reconstruction-error percentiles over the training NORMAL set. The reported
score is the rational squash

```
score = err / (err + p50)      ∈ [0, 1)
```

— monotone in `err`, zero tuning parameters beyond `p50`, no dependencies.
`Exceeds = err ≥ threshold`, where `threshold` defaults to the recorded p99. A
bundle with no calibration still scores: `score = err/(err+1)`, `threshold = 0`,
`Exceeds = false`, `Available = true`.

`z` and `err` are coarse first-cut signals, deliberately. A distribution-distance
formulation is left for when a trained autoencoder and real traffic exist to tune
against; the response shape does not change when the metric is upgraded.

### `Result.Anomaly`, additive and optional

`inference.Result` gains `Anomaly *AnomalyResult` with `json:",omitempty"`:
`Available, ModelID, Score, ReconError, Threshold, Exceeds`. A `Result` with no
anomaly model serialises exactly as before, so `storage.Classification` (which
embeds `inference.Result` verbatim) needs no migration in either the memory or
the bbolt driver.

Per-feature reconstruction deltas are **not** stored — five scalars keep the hot
path and the bounded ring lean. `GET /api/v1/flows/{id}/explain` recomputes the
top-K feature deltas on demand by re-running the live anomaly model against the
stored `FlowRecord.Features`, the same "reconstruct model input from the stored
vector" pattern that endpoint already uses for classifiers.

### One Active model per role; primary and anomaly coexist

`registry.Entry` gains a persisted `Role string json:"role,omitempty"`, derived
from the family at `Register` time (`flow-classifier-v1` → `primary`,
`flow-anomaly-v1` → `anomaly`). `fileVersion` stays 1 — the field is additive and
a `registry.json` written before this change loads with `role` defaulting to
`primary`. `SetStatus(id, StatusActive)` demotes only *other Actives whose Role
matches*; `Active()` still returns the first Active `primary` (its callers assume
one); a new `ActiveByRole(role)` covers the anomaly slot.

`inference.Runtime` gains `ActivateRole(role, Classifier, AnomalyScorer)` and
`DeactivateRole(role)`, which replace only that role's slot under the existing
lock. `Activate`/`Deactivate`/`SetModels` stay for current tests; the API
activation path switches to the role-aware pair. `handleModelActivate` learns the
role from the bundle's family — it is intrinsic to the model, not an operator
choice, so there is no `?role=` parameter. The startup reconcile (a persisted
Active is demoted on load — activation never survives a restart, §28.10) is
unchanged and applies to both roles.

### Calibration travels in `metadata.json`

The error percentiles and suggested threshold go in `metadata.json` under an
additive optional `"anomaly"` key, following the `derived_from` precedent: it is
not part of `schema.BundleMeta`, and `model.Validate` does not check it.
`internal/model/metadata.go` gains `Anomaly *AnomalyCalibration
json:"anomaly,omitempty"`.

Alternative considered: `metrics.json`, which the registry already carries
through verbatim into `Entry.Metrics` and which is not key-order-frozen. It
avoids touching `Metadata` and `test_export_layout` at all, at the cost of
`modelrun` reading calibration from a metrics blob rather than typed metadata.
`metadata.json` won because the threshold is part of the model's runtime
contract, not a training report.

### No always-on pure-Go stand-in

The supervised path shipped `Heuristic` as a transparent Phase 1 stand-in.
The anomaly path does **not** get an equivalent default: "anomaly scoring is
available" means "a trained `flow-anomaly-v1` model is Active", nothing more —
consistent with the heuristic primary still reporting several classes
unsupported. A stand-in would necessarily reuse the *classifier's* normalizer
statistics and compute a plain standardised-deviation aggregate, which is a
different statistic from autoencoder reconstruction error and overlaps ADR 0036's
drift view. An unexported z-aggregate helper inside `internal/inference` gives
the destub tests a deterministic scorer; it is never constructed by
`cmd/synapsed`. A real always-on baseline scorer is filed as a follow-up.

### Trainer: a `reconstruction` objective on the same CLI

`recipe.objective: "classification" | "reconstruction"`, default
`"classification"`. The reconstruction objective:

- trains on **NORMAL rows only** — the filter is applied to the train partition
  *after* the per-dataset split, so the "split each dataset before mixing"
  guarantee (§14) holds and the validation/test sets keep their attack rows for
  threshold and separation measurement;
- uses MSE loss with the feature vector as its own target, no class weighting;
- exports with **no softmax wrapper**, ONNX output name `reconstruction`, shape
  `[1, 48]`;
- writes an `anomaly` calibration block — reconstruction-error percentiles
  (p50/p90/p95/p99/max) over the NORMAL validation set, a suggested threshold at
  p99, and, when labelled attack rows are present, ROC-AUC and TPR/FPR at that
  threshold.

`architecture.py` becomes family-aware for the locked output width
(`FAMILY_OUTPUT = {"flow-classifier-v1": 7, "flow-anomaly-v1": 48}`); the hidden
stack, parameter-count and FLOP math are already generic. Architecture is still
chosen only through the recipe file. The `flow-classifier-v1` export path is
byte-for-byte unchanged.

## Consequences

- The daemon can run a primary classifier and an anomaly model at the same time;
  `GET /api/v1/models` lists both with their `role`, and deactivating one leaves
  the other scoring.
- Every "anomaly is Phase 7 / NOT AVAILABLE" stub becomes a real value when a
  `flow-anomaly-v1` model is Active, and stays honestly dark otherwise — no
  fabricated zero line (§16).
- `event-envelope-v1` is untouched: the classification event payload is the
  `storage.Classification` struct, and `Result.Anomaly` is an additive optional
  field on it. No new event type ships with #47 — `events.AnomalyDetected` and
  alert-policy integration for `Exceeds` flows are follow-ups.
- The frozen `flow-classifier-v1` validation and export paths are unchanged; the
  family switch is strictly additive.
- The trainer gains a second objective on the same `train` command; a bundle it
  produces passes the Go `model.Validate` gate and activates into the anomaly
  role. A hand-built `internal/model/testdata/good-ae-bundle/` fixture keeps Go
  tests independent of trainer merge order, with one integration test over a
  real trainer bundle.
- A follow-up can add an always-on pure-Go baseline anomaly scorer, a
  distribution-distance reconstruction metric, and an anomaly-score Prometheus
  series without changing the API contract.
