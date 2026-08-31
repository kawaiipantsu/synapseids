# 0007 — The Python trainer and the ONNX bundle contract

**Status:** Accepted, 2026-08-31

## Context

Phase 2 turns the Phase-1 heuristic into real inference: a trained
`flow-classifier-v1` model, an ONNX artefact, a Go ONNX runtime, and a
self-describing bundle the daemon validates before it runs (PROJECT.md §26
Phase 2, §10, §11; [ADR 0001](0001-go-owns-the-data-plane.md),
[ADR 0003](0003-phase1-scope-in-memory-store-heuristic-classifier.md)). Two of
those pieces live on the training side: the trainer itself (issue #21) and the
ONNX + normalizer + metadata export (issue #23), both under a new top-level
`trainer/` tree — the only non-Go part of the repo.

`PROJECT.md` §2.2 and §27 already commit training to **Python + PyTorch**, ONNX
as the hand-off. What still had to be decided: how the trainer stays buildable
and testable on a machine that cannot install PyTorch, and the **exact byte-level
shape** of the bundle, because the Go bundle-gate parses it and a silent
divergence means every deployed model is either rejected or quietly mis-fed.

The dev environment has Python 3.11 + numpy but no `torch` / `onnx` /
`onnxruntime` / `pytest`, and cannot fetch the large wheels. CI can.

## Decision

**1. `trainer/` is a standalone `synapse-trainer` package**, PEP 621
(`pyproject.toml`), console script `synapse-trainer`, also runnable as
`python -m synapse_trainer`. Two subcommands: `train --recipe --data --out` and
`inspect-arch --recipe` (parameter count / fp32 size / rough FLOPs, no torch).

**2. Heavy imports are guarded.** `torch` is imported behind `try/except` in
`train.py` and `export.py` only; `schema.py`, `architecture.py`, `normalize.py`
(pure numpy), `dataset.py`, `recipe.py` and the JSON builders in `export.py`
import and run with numpy alone. Torch-only code raises a clear
`TrainingUnavailable`. Tests use `pytest.importorskip("torch")` for anything
that needs a real graph, and ship a **non-torch companion** that writes a dummy
`model.onnx` blob and exercises every JSON emitter and the on-disk layout.
`python -m pytest trainer/` is green with torch absent (those asserts skip).

**3. The trainer re-reads the frozen schemas** (`schemas/features/flow-features-v1.json`,
`schemas/outputs/traffic-classes-v1.json`) from the repo root, or
`$SYNAPSE_SCHEMA_DIR`. It never hard-codes the 48/7 lists — same JSON the daemon
embeds (ADR 0002). Input 48 / output 7 are locked in `architecture.py`; only the
hidden stack is configurable (PROJECT.md §10, §28.6).

**4. ONNX export is fixed and total.** `torch.onnx.export`, **opset 17**, **fixed
batch = 1** (no dynamic axes), input tensor `features` `[1, 48]`, output tensor
`scores` `[1, 7]`, **softmax included** in the exported graph. `model_hash` is
`"sha256:"` + the lowercase hex digest of the bytes read back from the written
`model.onnx`.

**5. The bundle contract (trainer → daemon interface).** `export_bundle` writes
exactly five files into `out_dir/`:

```
model.onnx  metadata.json  normalizer.json  metrics.json  training-recipe.json
```

`metadata.json` — keys in this order, types as shown:

```json
{
  "model_id": "flow-classifier-v1-<UTC yyyymmddHHMMSS>-<8hex>",
  "name": "string",
  "version": "1",
  "family": "flow-classifier-v1",
  "feature_schema": "flow-features-v1",
  "input_size": 48,
  "output_schema": "traffic-classes-v1",
  "output_size": 7,
  "architecture": {
    "input_size": 48,
    "output_size": 7,
    "hidden": [
      {"width": 64, "activation": "relu", "dropout": 0.3, "batchnorm": true, "residual": false}
    ]
  },
  "training_dataset_ids": ["..."],
  "created_at": "2026-09-01T12:00:00Z",
  "trainer_version": "0.1.0",
  "parameter_count": 5575,
  "model_hash": "sha256:<64 lowercase hex>"
}
```

`normalizer.json` — one entry per feature, in frozen index order:

```json
{
  "method": "standard",
  "feature_schema": "flow-features-v1",
  "per_feature": [ {"index": 0, "name": "flow_duration", "mean": 0.0, "std": 1.0}, "... 48 entries" ]
}
```

`minmax` swaps the stat keys for `"min"` / `"max"`. `identity` is a genuine
no-op that still writes 48 `standard`-form entries (`mean` 0.0 / `std` 1.0).
`std` is floored at `1e-9`; a degenerate `min == max` becomes `max = min + 1e-9`
— the file never carries `std <= 0` or `min >= max`.

`metrics.json`: `accuracy`, `macro_f1`, `macro_precision`, `macro_recall`,
`train_loss`, `val_loss`, `per_class[] {class, precision, recall, f1, support}`,
`confusion` (7×7 int rows), `test` (same shape, or `null`).

`training-recipe.json`: the fully-resolved recipe — `seed`, `split`, dataset ids
+ weights, architecture, optimizer/lr/batch/epochs/early-stopping/scheduler
(PROJECT.md §14, §28.9).

**6. Parameter-count model** (matches the PyTorch MLP the trainer builds):
Dense `prev→width` = `prev*width + width`; `+ 2*width` when `batchnorm`;
activation / dropout / residual add nothing; output Dense `last→7` =
`last*7 + 7`. A `48→64→32→7` net is 5 447 parameters; add batchnorm on the first
hidden layer → 5 575.

**7. Dependency pins** live in `trainer/requirements.txt`: `torch==2.2.*`,
`onnx==1.16.*`, `onnxruntime==1.17.*`, `numpy==1.26.*`, `scikit-learn==1.4.*`
(only used to stratify the split; a seeded shuffle is the fallback). A new
`Trainer CI` workflow (issue #61) runs the non-torch tests on every `trainer/**`
change and the torch/onnx tests in a second job that installs the CPU wheels
from `download.pytorch.org/whl/cpu`.

## Consequences

- The trainer package imports, `inspect-arch` runs, and 36 of 37 tests pass with
  only numpy — the ONNX-export test skips. Full coverage needs the CI torch job.
- Feature extraction now exists twice (Go `internal/features`, Python
  `flow-features-v1` column handling). The frozen schema + golden vectors keep
  them honest (ADR 0001); the trainer reads, never redefines, the list.
- `metadata.json` / `normalizer.json` are a hard interface: any change is a
  coordinated trainer + daemon change, and for a contract change, a new family
  (`flow-classifier-v2`) — never an edit (§28.6).
- Opset 17 + fixed batch 1 keeps the Go ONNX runtime's surface minimal; batched
  inference, if it is ever needed, is a `v2` export option, not a reshape of v1.
- `scikit-learn` is a soft dependency: absent, splits are still reproducible but
  not stratified.
- The `[Unreleased]` changelog and `docs/architecture.md` now describe a
  component that is real in `trainer/` but not yet wired to a running daemon (no
  Go ONNX runtime or model registry yet).

**Revisit when:** the Go ONNX runtime + bundle-gate land and the first real
bundle is validated end to end (PROJECT.md §25 "trainer → ONNX bundle → daemon
validation → inference"); or `flow-features-v2` / `flow-classifier-v2` forces a
second export path.

---

⟦THUGS⟧ (c) 2026
