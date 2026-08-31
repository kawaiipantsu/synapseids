# 0009 — Model registry with lineage, and explicit runtime activation

**Status:** Accepted, 2026-08-31

## Context

[ADR 0005](0005-go-onnx-inference-runtime.md) gave the daemon a dependency-free
ONNX runtime (`internal/nn`); [ADR 0006](0006-model-bundle-format-and-validation.md)
gave it a bundle format and the pre-activation validation gate (`internal/model`).
Both stop short of running a trained model: `model.Scan` loads and validates the
bundles under `models.directory` at startup and then only *logs* the result. The
vertical slice (PROJECT.md §29 steps 16–18) needs the last three moves — a model
is **registered and validated**, then **explicitly activated**, then used for
classification on the next replay — plus the registry's own requirements: lineage
(§15, §19.12), an audit trail (§21, §28.14), and "do not activate newly trained
models automatically" (§28.10).

Constraints carried from the rest of the repo: zero third-party dependencies,
`CGO_ENABLED=0`, the frozen `flow-features-v1` / `traffic-classes-v1` /
`event-envelope-v1` contracts, and the packet path must not block on API or disk
work (§22). SQLite is still a separate tracked issue, so the registry cannot
assume a database.

## Decision

### `internal/registry` — a JSON-file registry

`registry.Open(dir, logf)` loads `dir/registry.json` and returns a
mutex-guarded `*Registry`. `Register(*model.Bundle)` runs `Validate()` (the gate),
then records one `Entry`: the §11 metadata, plus `content_hash` (`bundle.Hash()`),
`artifact_bytes` (`stat` of `model.onnx`), `derived_from`, `status`,
`registered_at`, `activated_at` and the on-disk `dir`. It rejects a bundle whose
content hash is already registered under a different `model_id`, or whose
`model_id` is already registered with a different hash; re-registering the
identical pair is an idempotent refresh so a restart's startup sweep is a no-op.

Reads: `List` (newest first), `Get`, `Active`, and the lineage trio `Lineage(id)`
(root → id chain via `derived_from`), `Children(id)`, `Tree()` (the forest, cycle-
and orphan-safe). `SetStatus(id, status)` moves an entry between `registered`,
`active` and `deactivated`, stamping `activated_at` and demoting any prior
`active` entry so at most one is active.

Persistence is `registry.json`, written atomically (temp file + `os.Rename`). A
missing file starts empty; a corrupt or unreadable file is logged and also starts
empty — the bundles on disk are the source of truth and startup re-registers
them, so a bad file can never wedge the daemon. No database (SQLite stays a
separate issue).

### Explicit activation, and a swappable runtime

`inference.Runtime` gains `Activate(primary)`, `Deactivate()` and `SetModels(…)`,
each replacing the live model slice **wholesale** under an `RWMutex`; `Score`
takes the read lock and ranges over the snapshot, so a concurrent activation is
never observed half-applied. `NewRuntime(models…)` is unchanged and its arguments
become the *fallback* set that `Deactivate` restores.

`internal/modelrun.Build(id, bundle)` is the seam from "validated bundle" to
"live `Classifier`": `nn.LoadFile(bundle.ONNXPath())`, bridge the bundle's
`normalizer.json` (`features.Normalizer`) into `inference.Normalizer`, and wrap
with `inference.NewONNXModel(id, RolePrimary, net, bridged)`.

`POST /api/v1/models/{id}/activate` re-loads and re-validates the bundle from its
recorded `dir`, `modelrun.Build`s it, calls `Runtime.Activate`, then
`registry.SetStatus(id, "active")`. `deactivate` calls `Runtime.Deactivate()` and
`SetStatus(id, "deactivated")`. Nothing on the load/scan/startup path activates
anything (§28.10); `models.primary` at startup only logs a line pointing at the
activate route. Activation does not survive a restart: a persisted `active` entry
is reconciled to `deactivated` when the registry loads, since the runtime comes
up with only the heuristic.

### Heuristic as fallback, not shadow

When a trained model is active it is the *only* model in the runtime; the
heuristic is not scoring. `Deactivate` restores it as the sole `RolePrimary`.
Running the heuristic as a permanent `RoleExperimental` shadow (for continuous
disagreement signal) is deferred — `Runtime.SetModels` is the seam, and a real
multi-model ensemble (trained primary + anomaly/location peers, §12, §13) is
Phase 7 work.

### Audit trail, and events

`internal/audit` appends one `{ts,event,actor,model_id,detail}` JSON line per
`ModelRegistered` / `ModelActivated` / `ModelDeactivated` to `audit.log`, next to
the bundles, and mirrors it to the structured log. `actor` is `"local"` until
RBAC ([#58](https://github.com/kawaiipantsu/synapseids/issues/58)). Writes are
best-effort and never fail the request.

The same three envelopes are **also** published on the live event bus. They are
already members of the frozen `event-envelope-v1` enum, so this adds no new
type; the bus drops under backpressure by design, which is why `audit.log` — not
the bus — is the record an operator audits.

### Additive metadata field

`model.Metadata` gains `DerivedFrom string \`json:"derived_from,omitempty"\``,
read from an optional `metadata.json` `derived_from`. It is not part of the
validation contract; the trainer may populate it later, and an absent value marks
a lineage root.

## Consequences

- `api.New` takes two new parameters (`*registry.Registry`, `*audit.Logger`),
  both nil-tolerant; all callers/tests updated. With a nil registry the
  `/api/v1/models*` reads still return the live runtime and the state-changing
  routes answer `503`.
- `GET /api/v1/models` changes shape from a bare array to
  `{ "models": [...registry entries with runtime status...], "runtime": [...live classifiers...] }`.
  `/api/v1/status` keeps its lightweight `models` list.
- New packages: `registry`, `modelrun`, `audit`, and the test-only `modeltest`
  (builds a valid bundle with a real runnable `model.onnx`, so no binary fixture
  is committed).
- The trainer contract question: `derived_from` is the only new field it needs to
  emit for lineage; everything else the registry stores it already writes.
- Still deferred: multi-model ensembles, an `models.auto_activate_primary` opt-in
  (would need explicit-flag gating + an audit entry), and moving the audit trail
  into SQLite.
