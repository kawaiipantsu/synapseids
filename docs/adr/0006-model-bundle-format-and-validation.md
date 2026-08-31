# 0006 — Model bundle format and the pre-activation validation gate

**Status:** Accepted, 2026-08-31

## Context

Phase 2 replaces the rule-based `inference.Heuristic` with trained neural
networks. A trained model arrives from `synapse-trainer` (Python/PyTorch → ONNX)
as a self-describing bundle (PROJECT.md §11). Before `synapsed` runs one, it has
to prove the model still fits this build's frozen contracts: the wrong
`feature_schema`, a 47-input net, or a silently corrupted `model.onnx` must be a
loud rejection, not a quietly-wrong classifier (PROJECT.md §9, §10, §28.6). Two
rules bound the design:

- **Loading is not activating.** A newly registered model is inert until an
  operator explicitly turns it on (PROJECT.md §28.10, §29 steps 16–17).
- **Stay independent of the ONNX runtime.** The Go inference runtime
  (`internal/nn`, issue #24) lands on a sibling branch. Bundle validation must
  not depend on it — it validates *metadata, hash and file presence*, never by
  executing the graph.

## Decision

### Bundle layout

A bundle is a directory containing exactly five files (`model.RequiredFiles()`):

```text
<bundle>/
├── model.onnx            serialized network; opaque to internal/model (only hashed)
├── metadata.json         the §11 descriptor (see below)
├── normalizer.json       fitted per-feature input transform (see below)
├── metrics.json          evaluation metrics — carried through, not interpreted
└── training-recipe.json  optimizer / schedule / seed — carried through, not interpreted
```

`metrics.json` and `training-recipe.json` are only required to be present and to
parse as JSON; their shape is the registry's concern, not the gate's.

### `metadata.json`

```jsonc
{
  "model_id": "string",
  "name": "string",
  "version": "string",
  "family": "flow-classifier-v1",
  "feature_schema": "flow-features-v1",
  "input_size": 48,
  "output_schema": "traffic-classes-v1",
  "output_size": 7,
  "architecture": {
    "input_size": 48,
    "output_size": 7,
    "hidden": [
      { "width": 64, "activation": "relu", "dropout": 0.3, "batchnorm": true, "residual": false }
    ]
  },
  "training_dataset_ids": ["..."],
  "created_at": "2026-08-31T12:00:00Z",   // RFC3339
  "trainer_version": "string",
  "parameter_count": 5383,
  "model_hash": "sha256:<64 lowercase hex of the raw model.onnx bytes>"
}
```

`architecture.hidden[]` is the only editable part of the shape; the input and
output layers are locked to the family (PROJECT.md §10). Unknown extra keys are
ignored, so the trainer can add fields without breaking older daemons.

### `normalizer.json`

```jsonc
{
  "method": "standard",              // "standard" | "minmax" | "identity"
  "feature_schema": "flow-features-v1",
  "per_feature": [
    { "index": 0, "name": "flow_duration", "mean": 0.0, "std": 1.0 }
    // ... exactly 48 entries, index 0..47 ascending, no gaps or duplicates
  ]
}
```

For `method: "minmax"` each entry carries `"min"`/`"max"` instead of
`"mean"`/`"std"`. For `method: "identity"` the transform is a no-op and
`per_feature` may be empty or omitted. `internal/model` turns a `standard` /
`minmax` spec into a fitted `features.Affine` (`(x-mean)/max(std,1e-9)` or
`(x-min)/max(max-min,1e-9)`), and `identity` into `features.Identity`. This is a
**per-model** transform applied only on the trained-model path — the heuristic
keeps reading raw features and the pipeline never installs a normalizer
([ADR 0001](0001-go-owns-the-data-plane.md), CLAUDE.md).

### The gate — `model.Bundle.Validate()`

`model.Load(dir)` reads the five files, parses the four JSON descriptors, and
recomputes `sha256:<hex>` over the `model.onnx` bytes; it returns an **inactive**
`*Bundle` and never activates anything. `Bundle.Validate()` then rejects, with an
error naming the offending field, when any of:

- a required file is missing or is not valid JSON (`model.Load` / re-`stat`);
- `feature_schema` ≠ `flow-features-v1` or `input_size` ≠ 48; `output_schema` ≠
  `traffic-classes-v1` or `output_size` ≠ 7 (`schema.ValidateBundle`);
- `architecture` is absent, or `architecture.input_size` / `output_size` ≠ 48 / 7
  (`schema.ValidateArchitecture`);
- `family` is empty, `parameter_count` ≤ 0, or `created_at` is not RFC3339;
- `model_hash` lacks the `sha256:` prefix, is not 64 lowercase hex digits, or
  does not equal the recomputed hash of `model.onnx`;
- `normalizer.json` names a different `feature_schema`, uses an unknown `method`,
  or (for `standard` / `minmax`) does not carry exactly 48 ascending in-order
  entries with `std > 0` / `min < max`.

The frozen-contract checks (schema names, sizes, architecture edges) live in
`internal/schema` so there is one authority on what this build speaks; file
presence, JSON validity, the hash rule and the normalizer-shape rules live in
`internal/model`.

### Startup scan

`cmd/synapsed` calls `model.Scan(cfg.Models.Directory, cfg.Models.Primary,
log.Printf)` once at startup (skipped cleanly if the directory is absent). It
`Load`+`Validate`s every immediate subdirectory and logs one line each —
`loaded model "<dir>" (family …, N params) — INACTIVE` or
`rejected model bundle "<dir>": <reason>`. A valid bundle whose directory name or
`model_id` matches `cfg.Models.Primary` gets an extra line noting that activation
is a separate explicit step that is *not yet wired*. Nothing is added to
`inference.Runtime`; the heuristic stays the only scoring model.

### Executor seam

`model.Executor` (`Run([]float32) ([]float32, error)`) and `Bundle.Bind` are
defined but unused. Issue #24's ONNX runtime supplies the implementation; keeping
the seam here lets validation stay runtime-free.

## Consequences

- A model that does not fit the contract is rejected at load with a specific
  reason; it can never reach inference.
- `cfg.Models.Primary` is matched against **both** the bundle directory name and
  the `model_id`. `contrib/config/synapse.annotated.md` documents it as a model
  id; the (future) activation step must settle on one and update the annotation.
- `internal/model` depends only on `internal/schema` and `internal/features` — no
  ONNX, no pipeline, no API. It is a leaf that the future registry/activation
  code builds on.
- `metrics.json` / `training-recipe.json` are accepted almost sight-unseen; a
  bundle can pass the gate with useless metrics. The registry UI (Phase 4) is
  where those get scrutinised.
- Feature-order knowledge now exists in three places — the schema JSON,
  `features.Extract`, and a trainer-side writer. The 48-entry `per_feature`
  contract and the golden vectors are what keep them aligned; a `flow-features-v2`
  is a new schema, a new family and a new bundle, never an edit
  ([ADR 0002](0002-flow-features-v1-frozen-and-json-config.md)).

**Revisit when:** issue #24 lands the ONNX runtime (wire `Bind` + an
`executable?` check into `Validate` or a second gate), or the model registry and
explicit activation endpoint arrive (Phase 4, PROJECT.md §19.12, §29).

---

⟦THUGS⟧ (c) 2026
