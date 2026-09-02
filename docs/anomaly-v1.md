# reconstruction-v1 and the flow-anomaly-v1 model family

The anomaly autoencoder (PROJECT.md §13, issue #47,
[ADR 0037](adr/0037-anomaly-autoencoder-model.md)). It answers "how unfamiliar
is this flow?" with a reconstruction error, never "which class?" — a supervised
softmax always has a maximum, and forcing unknown traffic into a known class is
exactly what this model exists to avoid.

## The contract

`flow-anomaly-v1` is a second model family alongside `flow-classifier-v1`:

| family              | feature schema  | in | output schema      | out |
|---------------------|-----------------|----|--------------------|-----|
| `flow-classifier-v1`| `flow-features-v1` | 48 | `traffic-classes-v1` | 7 |
| `flow-anomaly-v1`   | `flow-features-v1` | 48 | `reconstruction-v1`  | 48 |

`schemas/outputs/reconstruction-v1.json` is **frozen** (`"frozen": true`,
`output_size: 48`). Its 48 slots mirror `flow-features-v1` name-for-name — the
autoencoder reconstructs the feature vector, so its output ordering is locked to
the vector it targets. `internal/schema` `init()` panics if the count, indices
or names drift from `flow-features-v1`.

`schema.ValidateBundle` and `schema.ValidateArchitectureForFamily` switch on the
bundle's `family`. The `flow-classifier-v1` branch is unchanged; the
`flow-anomaly-v1` branch requires `input_size == output_size == 48`. An unknown
or empty family is rejected.

## Scoring

`inference.ONNXAnomalyModel` (built from a bundle by `modelrun.BuildAnomaly`):

1. Normalize the raw `flow-features-v1` vector with the bundle's
   `normalizer.json` — the reconstruction error is measured in the model's
   input space, so a normalizer is required.
2. Run the 48→48 network. `recon_error = mean_i((in_i − out_i)^2)`.
3. `score = recon_error / (recon_error + p50)` ∈ [0, 1) — monotone in the
   error, no tuning parameters beyond the training-set median. With no
   calibration the denominator falls back to `1`.
4. `exceeds = recon_error ≥ threshold` (the bundle's calibrated p99; `0` and
   never `true` when uncalibrated).
5. The 8 largest per-feature gaps (`|out_i − in_i|`) are returned for the Flow
   Inspector; they are **not** stored on the per-flow verdict.

If the network fails to run the model abstains (`available: false`) rather than
emit a fabricated score.

### Calibration

A trained bundle records, under an additive optional `"anomaly"` key in
`metadata.json`:

```json
"anomaly": {
  "space": "normalized",
  "error_percentiles": { "p50": …, "p90": …, "p95": …, "p99": …, "max": … },
  "threshold": <p99>
}
```

It is not part of the frozen `BundleMeta` and `model.Validate` does not check it.

## Training a bundle

`synapse-trainer` grows a second **objective** on the same `train` command:

```json
{ "objective": "reconstruction", "datasets": [ … ], "architecture": { "hidden": [ … ] } }
```

- `objective: "reconstruction"` selects the `flow-anomaly-v1` family. The
  architecture is a symmetric autoencoder — `Architecture` locks the output
  width to 48 for this family; `default_architecture` is `48 → 32 → 16 → 32 →
  48`. Hidden activations are `relu` / `leaky_relu` / `sigmoid` / `tanh` (what
  `internal/nn` can run).
- **Training data is NORMAL rows only.** `build_mixture(...,
  train_label_filter={class_id("normal")})` restricts the train partition
  *after* the per-dataset split, so validation and test keep every class — the
  reconstruction error's threshold and its separation are measured against
  held-out attack traffic. `class_weighting` is inert and forced to `none`;
  early stopping is on `val_loss` (the MSE).
- The loss is `nn.MSELoss()` with the normalized feature vector as its own
  target. `train.reconstruction_metrics` (numpy only) reports the
  reconstruction-error percentiles over the NORMAL validation rows, a suggested
  threshold at p99, and ROC-AUC + TPR/FPR-at-threshold when attack rows are
  present.
- `export_onnx` writes the 48→48 net **with no softmax**, output name
  `reconstruction`, shape `[1, 48]`. `metadata.json` carries the `family`,
  `output_schema: reconstruction-v1`, `output_size: 48`, and the additive
  `anomaly` calibration block above; `metrics.json` carries the
  reconstruction-error stats instead of a confusion matrix.

See `trainer/examples/anomaly-recipe.json`.

## In the ensemble

`RoleAnomaly`. `inference.Runtime` keeps anomaly models in a slice separate from
the classifiers; `Score()` records their verdict in `Result.Anomaly` and it
never touches `Result.Class` / `Score` / `Disagreement` / `Models`.

Activation is role-aware: a primary classifier and an anomaly model can be
Active at the same time. `POST /api/v1/models/{id}/activate` derives the role
from the bundle family and swaps only within that role;
`POST …/deactivate` drops that role's model (the primary falls back to the
heuristic; the anomaly role simply goes dark). Activation never survives a
daemon restart, for either role.

## Where the score surfaces

- `inference.Result.anomaly` → the `ClassificationCreated` event payload and the
  stored `Classification`.
- `GET /api/v1/flows/{id}/explain` → the `anomaly` object (scalars from the
  stored verdict; per-feature gaps recomputed while the model is loaded).
- `GET /api/v1/timeline` → per-bucket `anomaly_n` / `anomaly_mean` /
  `anomaly_max` / `anomaly_exceeds` and `anomaly_available`.
- `GET /api/v1/hosts/{ip}` → `anomaly_flows` / `anomaly_mean` / `anomaly_max` /
  `anomaly_exceeded`.
- The downloadable report → `coverage.anomaly_available` and the timeline
  section.

Every one of these is an explicit `available: false` with zeroed fields when no
`flow-anomaly-v1` model is active.

## Not yet built

- The SPA panels that plot the score (Flow Inspector, timeline, dashboard) —
  issue #167.
- `events.AnomalyDetected` and alert-policy integration for `exceeds` flows —
  the score is informational only for now.
