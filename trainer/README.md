# synapse-trainer

Offline training service for SynapseIDS `flow-classifier-v1` models (PROJECT.md
§5.4, §10, §11; [ADR 0007](../docs/adr/0007-python-trainer-and-bundle-export.md)).

It reads one or more labelled `flow-features-v1` datasets, combines them into a
weighted training mixture, builds a configurable MLP (input 48 / output 7
**locked**, hidden stack editable), normalizes features, splits reproducibly,
trains with PyTorch, and exports a **self-describing bundle** the Go daemon
validates before it runs. The daemon never calls Python at inference time.

```
datasets[] ──▶ split each ──▶ weight+mix train ──▶ Normalizer.fit ──▶ train (PyTorch MLP)
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

# no torch needed — resolve the recipe's datasets and print the training mixture
python -m synapse_trainer inspect-recipe \
    --recipe trainer/examples/recipe.multi-dataset.json \
    --data   trainer/examples/data          # add --json for the machine-readable plan

# train and write a bundle (needs torch); --dry-run stops after the plan
python -m synapse_trainer train \
    --recipe trainer/examples/recipe.json \
    --data   ./data \
    --out    ./bundle \
    --name   flow-classifier-baseline
```

`--data` is the **dataset root** each `datasets[].id` resolves under (a single
CSV file still works when the recipe names exactly one dataset). Every CSV
header carries the 48 `flow-features-v1` columns (by frozen schema name; file
order is irrelevant) plus a `label` column holding a `traffic-classes-v1` class
name or id 0..6. Feed **raw** feature values — the trainer fits its own
normalizer and records it. See [`examples/README`](examples/README).

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

## Multi-dataset mixtures

A recipe may combine several compatible datasets with relative weights
(PROJECT.md §14 — "70% Copenhagen baseline / 20% attack corpus / 10% reviewed
local detections"). `synapse_trainer/mixture.py` owns this;
[ADR 0017](../docs/adr/0017-multi-dataset-training-mixtures.md) records why.

### Dataset resolution order

For entry `{"id": "hq-copenhagen/baseline-2026-08"}` under `--data ROOT`, the
first hit wins:

1. the entry's explicit `"path"` — absolute, else relative to `ROOT`, else to the cwd;
2. `ROOT/<id>.csv`;
3. `ROOT/<id>/dataset.csv`;
4. `ROOT/<id>/<latest version dir>/dataset.csv` — highest immediate subdirectory
   by a **numeric-aware** natural sort (`v10` > `v9`), limited to subdirectories
   that hold a readable CSV;
5. any single `ROOT/<id>/*.csv`.

Nothing found is a hard error listing every path tried. An id may be namespaced
(`site/name`) but never absolute and never contains `..`. A `manifest.json` (or
`dataset.json`) beside the CSV — or `ROOT/<id>.manifest.json` for the flat
layout — is read for the §14 dataset metadata; its `content_hash` is copied into
the bundle so a model is traceable to the exact data version. The manifest is
metadata only: the CSV is the source of truth for rows and labels.

### Compatibility gate

Every dataset must carry all 48 `flow-features-v1` columns and agree with every
other dataset (and with any manifest) on `feature_schema` / `output_schema`. A
mismatch is a named `DatasetIncompatible` / `MixtureError` — columns are never
dropped, reordered or coerced to make two datasets fit (§5.4, §8, §28.5-6).

### Weighting semantics

Weights are the **relative contribution to the training mixture**, not metadata:

* `target_n = Σ len(train_i)` after each dataset is split;
* quotas `n_i` come from largest-remainder apportionment of `target_n` by weight,
  so `Σ n_i == target_n` exactly, with no rounding drift and no order dependence;
* `n_i ≤ len(train_i)` → down-sample without replacement;
* `n_i > len(train_i)` → up-sample: every row once, then the remainder drawn with
  replacement;
* the mixture is shuffled once, deterministically.

Each draw uses a generator seeded by `sha256(seed, purpose, dataset-id)`, so the
mixture is reproducible **from the recipe alone**, and adding a dataset does not
reshuffle the others. `--dry-run` / `inspect-recipe` prints realised rows,
effective (post-rounding) weights, split sizes, the label distribution, and
warnings for a dominant class, a class absent from the mixture, a dataset that
contributes zero rows and heavy (≥3×) up-sampling.

### Split before mix — and why

Each dataset is split **first**, on its own; only the train portions are then
weighted and mixed. Val and test are plain unions of the per-dataset val/test
splits and are **never** resampled.

The order is load-bearing. Mixing first and splitting after would let
up-sampling place two copies of one source row on both sides of the split
boundary, leaking test rows into training (§14: *never leak the test split into
training*). Because a row belongs to exactly one of train/val/test inside its own
dataset and only the train side is ever duplicated, the three row-id sets are
provably disjoint —
`tests/test_mixture.py::test_no_leak_under_aggressive_upsampling` asserts it, and
its companion `test_naive_mix_then_split_would_leak` shows the naive order does
leak, so the assertion is not vacuous.

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

The resolved recipe: `name`, `datasets[]` (`id`, `weight`, optional `path`),
`architecture`, `normalizer`, `optimizer`, `lr`, `batch_size`, `epochs`,
`early_stopping`, `class_weighting`, `scheduler`, `seed`, `split`. `train` also
attaches two blocks describing what actually happened:

- `split_result` — `seed`, `fractions`, overall `sizes`, `stratified`,
  per-split `label_counts`, and `per_dataset` (source rows, split sizes, train
  rows after weighting, split seed).
- `mixture` — `strategy` (a versioned name), `seed`, `split_before_mix`,
  `resampled_splits`, `target_train_rows`, `sizes`, `label_counts`, `warnings`,
  and `datasets[]` with, per contributing dataset: `id`, requested `weight`,
  `effective_weight`, `path`, `resolved_by`, `content_hash` (from its manifest,
  or `null`), `source_rows`, `split_sizes`, `stratified`, `split_seed`,
  `sample_seed`, `train_rows`, `resampling` (`none`/`up`/`down`),
  `duplicated_rows` and `train_label_counts`.

`metadata.json`'s `training_dataset_ids` lists **every** contributing dataset id;
the Go bundle-gate sees no new keys (§14, §28.9).

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
| `recipe.py` | no | parse + validate `training-recipe.json` (weight-sum, split-sum, unique ids, defaults) |
| `mixture.py` | no | resolve `datasets[]` under `--data`, gate schema compatibility, split-per-dataset **then** weight/resample the train side, record provenance + imbalance warnings |
| `train.py` | **yes** | build the MLP, train (optimizer/scheduler/early-stop/class-weighting), stream per-epoch progress, compute metrics (metrics helpers are numpy-only) |
| `export.py` | export only | write the 5-file bundle; JSON builders are torch-free |
| `cli.py` | `train` only | `synapse-trainer train` (`--dry-run`) / `inspect-recipe` / `inspect-arch` |

## Tests

```bash
python -m pytest trainer/ -q
```

Torch-dependent asserts self-skip when torch is absent.

---

⟦THUGS⟧ (c) 2026
