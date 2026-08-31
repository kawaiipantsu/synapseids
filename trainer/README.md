# synapse-trainer

Offline training service for SynapseIDS `flow-classifier-v1` models (PROJECT.md
§5.4, §10, §11; [ADR 0007](../docs/adr/0007-python-trainer-and-bundle-export.md)).

It reads a labelled `flow-features-v1` dataset, builds a configurable MLP
(input 48 / output 7 **locked**, hidden stack editable), normalizes features,
splits reproducibly, trains with PyTorch, and exports a **self-describing bundle**
the Go daemon validates before it runs. The daemon never calls Python at
inference time.

```
dataset.csv ──▶ dataset.split ──▶ Normalizer.fit ──▶ train (PyTorch MLP)
                                                        │
                                                        ▼
                                     export_bundle ──▶ out_dir/
                                                        ├── model.onnx            (opset 17, batch 1, softmax)
                                                        ├── metadata.json         (the bundle-gate contract)
                                                        ├── normalizer.json       (48 per-feature entries)
                                                        ├── metrics.json
                                                        └── training-recipe.json  (resolved: seed, split, datasets)
```

## Install

```bash
python -m venv trainer/.venv && . trainer/.venv/bin/activate
pip install -e trainer/            # pulls torch/onnx/onnxruntime/numpy/scikit-learn
# or, pinned:
pip install -r trainer/requirements.txt
```

The interactive dev box these files were written on has **no** torch / onnx /
onnxruntime and cannot fetch the large wheels. Every heavy import is guarded:
the package imports, `inspect-arch` works, and the non-torch test suite passes
with only `numpy` present. CI installs the CPU wheels and runs the full suite
(`.github/workflows/trainer-ci.yml`).

## Use

```bash
# no torch needed — parameter count / fp32 size / rough FLOPs for the recipe's net
python -m synapse_trainer inspect-arch --recipe trainer/examples/recipe.json

# train and write a bundle (needs torch)
python -m synapse_trainer train \
    --recipe trainer/examples/recipe.json \
    --data   ./data \
    --out    ./bundle \
    --name   flow-classifier-baseline
```

`--data` is a dataset CSV or a directory containing one. The header carries the
48 `flow-features-v1` columns (by frozen schema name; file order is irrelevant)
plus a `label` column holding a `traffic-classes-v1` class name or id 0..6. Feed
**raw** feature values — the trainer fits its own normalizer and records it.
See [`examples/README`](examples/README).

The recipe (`training-recipe.json`) — every field except `datasets` has a
default; `datasets[].weight` and `split` must each sum to ~1.0:

```json
{
  "name": "flow-classifier-baseline",
  "datasets": [{"id": "thugs/lab-attacks-2026-08", "weight": 0.7},
               {"id": "hq-copenhagen/baseline-2026-08", "weight": 0.3}],
  "architecture": {"hidden": [
    {"width": 64, "activation": "relu", "dropout": 0.3, "batchnorm": true, "residual": false},
    {"width": 32, "activation": "relu", "dropout": 0.2, "batchnorm": false, "residual": false}
  ]},
  "normalizer": "standard",
  "optimizer": "adam", "lr": 0.001, "batch_size": 256, "epochs": 50,
  "early_stopping": {"patience": 8, "metric": "val_loss"},
  "class_weighting": "balanced", "scheduler": "cosine", "seed": 1337,
  "split": {"train": 0.7, "val": 0.15, "test": 0.15}
}
```

## The bundle contract

`export_bundle` always writes these five files. `metadata.json` and
`normalizer.json` are parsed by the Go daemon's bundle-gate — the shapes below
are frozen (a change is a coordinated trainer + daemon change, or a new model
family).

### `metadata.json`

Keys in this exact order:

| key | type | value |
|---|---|---|
| `model_id` | string | `flow-classifier-v1-<UTC yyyymmddHHMMSS>-<8 hex>` |
| `name` | string | model name |
| `version` | string | `"1"` |
| `family` | string | `"flow-classifier-v1"` |
| `feature_schema` | string | `"flow-features-v1"` |
| `input_size` | int | `48` |
| `output_schema` | string | `"traffic-classes-v1"` |
| `output_size` | int | `7` |
| `architecture` | object | `{input_size:48, output_size:7, hidden:[{width,activation,dropout,batchnorm,residual}]}` |
| `training_dataset_ids` | string[] | non-empty |
| `created_at` | string | RFC3339 UTC, e.g. `2026-09-01T12:00:00Z` |
| `trainer_version` | string | this package's version |
| `parameter_count` | int | > 0 |
| `model_hash` | string | `sha256:<64 lowercase hex of model.onnx bytes>` |

### `normalizer.json`

```json
{
  "method": "standard",
  "feature_schema": "flow-features-v1",
  "per_feature": [ {"index": 0, "name": "flow_duration", "mean": 0.0, "std": 1.0}, "... 48 entries, index 0..47 in order" ]
}
```

- `method` ∈ `standard` | `minmax` | `identity`.
- `minmax` entries carry `"min"` / `"max"` instead of `"mean"` / `"std"`.
- `identity` writes 48 `standard`-form entries with `mean` 0.0 / `std` 1.0 (a true no-op).
- `std` is floored at `1e-9`; `min == max` is nudged to `max = min + 1e-9`. The
  file never contains `std <= 0` or `min >= max`.

### `metrics.json`

`accuracy`, `macro_f1`, `macro_precision`, `macro_recall`, `train_loss`,
`val_loss`, `per_class[]` (`class`, `precision`, `recall`, `f1`, `support`),
`confusion` (7×7 int), `test` (same shape as the top level, or `null`).

### `training-recipe.json`

The resolved recipe: `name`, `datasets[]` (`id`, `weight`), `architecture`,
`normalizer`, `optimizer`, `lr`, `batch_size`, `epochs`, `early_stopping`,
`class_weighting`, `scheduler`, `seed`, `split`. `train` also attaches
`split_result` (seed, fractions, realised sizes).

### `model.onnx`

`torch.onnx.export`, **opset 17**, **fixed batch 1**. Input `features` `[1, 48]`
(float32), output `scores` `[1, 7]` — a softmax is baked into the graph, so the
output is a probability vector over `traffic-classes-v1`.

## Package layout

| module | needs torch? | purpose |
|---|:--:|---|
| `schema.py` | no | reads the frozen `flow-features-v1` / `traffic-classes-v1` JSON; `INPUT_SIZE`, `OUTPUT_SIZE`, `FEATURE_NAMES`, `CLASS_NAMES`, `check_compatible` |
| `architecture.py` | no | `HiddenLayer`, `Architecture` (locked 48/7); `parameter_count`, `estimated_size_bytes`, `rough_flops`, JSON round-trip |
| `normalize.py` | no | pure-numpy `Normalizer` (`standard` / `minmax` / `identity`) + `normalizer.json` I/O |
| `dataset.py` | no | CSV load, reproducible stratified/seeded `split` (no test leakage) |
| `recipe.py` | no | parse + validate `training-recipe.json` (weight-sum, split-sum, defaults) |
| `train.py` | **yes** | build the MLP, train (optimizer/scheduler/early-stop/class-weighting), stream per-epoch progress, compute metrics (metrics helpers are numpy-only) |
| `export.py` | export only | write the 5-file bundle; JSON builders are torch-free |
| `cli.py` | `train` only | `synapse-trainer train` / `inspect-arch` |

## Tests

```bash
python -m pytest trainer/ -q
```

Torch-dependent asserts self-skip when torch is absent.

---

⟦THUGS⟧ (c) 2026
