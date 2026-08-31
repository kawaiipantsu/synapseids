# 0017 — Multi-dataset training mixtures: split before mix, weight by resampling

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §14 makes datasets first-class versioned objects and requires that
"a training recipe must be able to combine multiple compatible datasets with
optional weighting", giving the worked example:

```text
70% Copenhagen normal baseline
20% known attack corpus
10% manually reviewed local detections
```

The same section adds two non-negotiables: **never leak the test split into
training**, and **dataset splitting must be reproducible and recorded in model
metadata** (see also §5.4 "load one or more datasets; validate feature/output
schema compatibility", §28.8 reproducibility, §28.9 "store training
configuration and dataset versions with every model").

Before this change the trainer's `recipe.py` already parsed and validated
`datasets: [{id, weight}]` — weights had to sum to ~1.0 — but nothing consumed
them: `cli.py train` loaded exactly one CSV via `--data`, split it, and trained.
The weights were decoration and a multi-dataset recipe silently trained on one
file. Three questions had to be answered to close that gap:

1. how a dataset **id** becomes a file on disk (the Go dataset manager, issue
   #33, is being built in parallel and its on-disk layout is not yet frozen);
2. what a **weight** actually *does* to the data;
3. in which **order** splitting and mixing happen — which turns out to be a
   correctness question, not a stylistic one.

## Decision

### 1. A documented resolution order, with the manifest as metadata only

For entry `{"id": "<id>"}` under `--data ROOT`, the first hit wins: the entry's
explicit `path` → `ROOT/<id>.csv` → `ROOT/<id>/dataset.csv` →
`ROOT/<id>/<latest version dir>/dataset.csv` → any single `ROOT/<id>/*.csv`.
"Latest" is the highest immediate subdirectory by a numeric-aware natural sort
(`v10` beats `v9`, which a lexicographic sort gets wrong), restricted to
subdirectories that actually hold a readable CSV. Nothing found is a hard error
that lists every path tried.

This deliberately spans the plausible layouts (flat export, canonical directory,
versioned directory) instead of coupling to an unfinished sibling branch. Ids may
be namespaced (`hq-copenhagen/baseline-2026-08`) but are never absolute and never
contain `..`, so a recipe cannot read outside its data root.

A `manifest.json` / `dataset.json` beside the CSV (or `ROOT/<id>.manifest.json`
for the flat layout) supplies the §14 dataset metadata — most importantly the
immutable `content_hash`, which is copied into the bundle. It is **metadata
only**: the CSV remains the source of truth for rows and labels, so a stale or
absent manifest degrades traceability, never correctness.

### 2. Weights resample the training mixture

Weights are the relative contribution to the training mixture:

* `target_n = Σ len(train_i)` — the pooled training rows across all datasets;
* quotas are the largest-remainder (Hare–Niemeyer) apportionment of `target_n` by
  weight, so `Σ n_i == target_n` exactly — no rounding drift, ties broken towards
  the earlier entry, no dependence on iteration order or RNG;
* `n_i ≤ len(train_i)` → down-sample without replacement (no duplicates);
* `n_i > len(train_i)` → up-sample: every row once, then `n_i − len(train_i)`
  more drawn with replacement, so a small dataset never loses coverage;
* one deterministic shuffle of the concatenation, so datasets are not fed to the
  optimizer in blocks.

Resampling — not loss re-weighting — was chosen because it composes with the
existing per-class `class_weighting: balanced` (which addresses a different
imbalance, between *classes*, not *datasets*), it is visible in the recorded row
counts, and it makes `--dry-run` able to show an operator the exact mixture size
they are about to train on.

Every draw uses `np.random.default_rng(derive_seed(recipe.seed, purpose, id))`
where `derive_seed` is a SHA-256 of the recipe seed, a fixed purpose tag and the
dataset id. `hash()` is not used (it is salted per process). Consequences: the
mixture is byte-reproducible from the recipe alone, and adding or re-weighting a
dataset does not reshuffle the *others'* splits or samples — a property a
recipe author will rely on when tuning weights, and one asserted by a test.

### 3. Split each dataset **before** mixing — the leakage rule

Each dataset is split independently first (stratified when scikit-learn is
importable, otherwise a seeded shuffle; which one was used is recorded). Only the
train portions are then weighted and mixed. Val and test are plain unions of the
per-dataset val/test splits and are **never** resampled.

The order is the crux of §14's "never leak the test split into training". Under
the naive order — mix first, split the mixture afterwards — up-sampling with
replacement produces two copies of one source row, and the split can hand one
copy to train and the other to test. The model then memorises rows it is later
scored on, and every reported test metric is inflated. Splitting first makes the
leak structurally impossible: a source row belongs to exactly one of
train/val/test within its own dataset, and only the train side is ever
duplicated.

Because the guarantee is structural, it is also testable. Every row carries a
`<dataset id>#<row id>` identity through the mixture;
`test_no_leak_under_aggressive_upsampling` up-samples a small dataset ~10× and
asserts the three id sets are pairwise disjoint (and that duplication really
happened, so the assertion is not vacuous). Its companion,
`test_naive_mix_then_split_would_leak`, reproduces the naive order inline and
asserts it *does* leak — so the pair documents the failure mode and would catch a
future refactor that swapped the order back.

### 4. Compatibility is a gate, never a coercion

Every dataset must carry all 48 `flow-features-v1` columns and agree with every
other dataset — and with any manifest — on `feature_schema` / `output_schema`.
A mismatch raises a named `DatasetIncompatible` / `MixtureError` naming the
dataset and the disagreement. Columns are never dropped, reordered or coerced to
make two datasets fit (§8, §28.5-6): silently training on a "close enough" vector
would produce a model whose ONNX input means something different from what the Go
daemon extracts.

### 5. Record what actually happened

`training-recipe.json` gains two blocks: `split_result` (seed, fractions, sizes,
stratified, per-split label counts, per-dataset detail) and `mixture` — a
versioned `strategy` name, the seed, `split_before_mix`, `resampled_splits`,
`target_train_rows`, sizes, label counts, warnings, and per dataset: requested
and effective weight, resolved path and which rule resolved it, `content_hash`,
source rows, split sizes, split/sample seeds, realised train rows, whether it was
up- or down-sampled and by how much.

`metadata.json` is **unchanged in shape**: only the *content* of the existing
`training_dataset_ids` changes, to list every contributing dataset. The Go
bundle-gate validates that file's key set and order, so new provenance lives in
`training-recipe.json`, which the Go side only requires to be present and valid
JSON.

## Consequences

- A recipe's weights now change the model. An existing single-dataset recipe is
  unaffected (one dataset at weight 1.0 resamples to itself), and `--data` may
  still point at one CSV when the recipe names exactly one dataset.
- Up-sampling duplicates rows, so a heavily up-weighted small dataset can be
  memorised. `inspect-recipe` warns at ≥3× duplication, alongside warnings for a
  dominant class (>90% of the mixture), a class absent from the mixture, a class
  under 10 rows, a dataset contributing zero rows, and an empty val/test split
  (§19.10). They are warnings, not errors: an operator may legitimately want a
  lopsided mixture.
- Test metrics are measured on natural, never-duplicated data, so they stay
  comparable across recipes with different weights — but they describe the pooled
  test distribution, *not* the weighted mixture. A model tuned for a 70/20/10
  mixture is still scored on whatever the datasets naturally contain.
- Stratification depends on scikit-learn being installed, so the exact split can
  differ between a lean CI runner and a full training box. The choice is recorded
  per dataset (`stratified`), and the seeded fallback is itself deterministic.
- `inspect-recipe` / `train --dry-run` resolve, split and weight everything with
  numpy alone. An operator can validate a recipe on a laptop with no torch, which
  is what makes the plan worth printing before a long run.
- The resolution order is now a contract the Go dataset manager (#33) should
  write into: the canonical `datasets/<id>/<version>/dataset.csv` +
  `manifest.json` layout it is expected to produce is rule 4, and the
  `content_hash` it stamps is what lands in the bundle.
