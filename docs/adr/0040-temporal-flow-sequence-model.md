# 0040 — Design for a temporal model over flow sequences (`flow-sequence-v1`)

**Status:** Accepted, 2026-09-02 — Go runtime implemented as a windowed FFN
(the `[T, 48]` history flattened, no `internal/nn` change); the trained
`Conv`/`GRU` model that keeps the time axis, and the `synapse-trainer`
`objective: "sequence"`, are follow-ups behind the interfaces below.

## Context

PROJECT.md §30 lists "recurrent/temporal models using sequences of flows" as a
future idea (issue #62, EPIC Phase 7). Every model the daemon runs today scores
**one** `flow-features-v1` vector in isolation — `inference.Classifier.Classify`
and `inference.AnomalyScorer.ScoreAnomaly` both take a single `features.Vector`.
A slow port sweep, a beacon that phones home every 60 s, a login that fails five
times then succeeds — these are patterns *across* a host's flows, invisible to a
per-flow model.

Unlike the anomaly autoencoder (ADR 0037), there is **no honest non-learned
stand-in** for a recurrent model: "temporal model" without a model is not a
temporal model. Shipping this needs three things that do not exist yet, so this
ADR records the design and the work rather than a stand-in.

## Decision (design, not yet built)

### A third model family: `flow-sequence-v1`

| family              | feature schema  | input        | output schema      | output |
|---------------------|-----------------|--------------|--------------------|--------|
| `flow-classifier-v1`| `flow-features-v1` | `[48]`     | `traffic-classes-v1` | 7    |
| `flow-anomaly-v1`   | `flow-features-v1` | `[48]`     | `reconstruction-v1`  | 48   |
| **`flow-sequence-v1`** | `flow-features-v1` | **`[T, 48]`** | `traffic-classes-v1` | 7 |

Input is the **last `T` feature vectors of one sequence key**, oldest first, and
the output is the verdict *for the newest flow given its history*. `T` is a
frozen family parameter (proposed `T = 16`); a shorter history is left-padded
with the frozen `default_missing` (`0.0`) vector and a companion length is not
passed (padding at 0 is the documented "no data" state, §16). Reusing
`traffic-classes-v1` keeps the ensemble contract unchanged — a sequence model is
just another supervised peer whose top class can raise `Result.Disagreement`.

### The sequence key and the per-key ring (pipeline)

The key is the **direction-normalized 5-tuple** (`flow.Key`) — the same identity
the flow table uses — so "sequence" means "successive versions and successors of
one conversation". A per-host key (`initiator IP`) is a v2 if host-level
temporality is wanted.

`internal/pipeline` gains a bounded `map[flow.Key]*ringBuffer[[48]float64]`
(cap ~4096 keys, oldest-idle eviction, mirroring the flow table's own bounding —
§21, §22). On each `features.Extract`, the vector is pushed to its key's ring
*before* scoring, and a `flow-sequence-v1` model is handed the ring's contents as
`[T, 48]`. The ring is single-goroutine like `flow.Table` — fed from
`pipeline.Run`'s packet loop only. Memory: 4096 × 16 × 48 × 8 B ≈ 24 MB worst
case; the cap makes it a fixed cost.

### The `internal/nn` gap

The stdlib executor runs `Gemm, MatMul, Add, Relu, LeakyRelu, Sigmoid, Tanh,
BatchNormalization, Dropout, Softmax, Identity, Flatten, Reshape` — an MLP op
set. A recurrent model needs one of:

- **`LSTM` / `GRU`** ops (opset-17 defines both) — the direct route, ~150 lines
  each: gate matmuls + activations over the time axis, hidden-state carry. No
  new dependency (still pure-Go stdlib).
- **1-D causal convolution / TCN** — needs `Conv` (1-D) only, simpler than an RNN
  cell and often as accurate for this; `Conv` is also reusable.
- **Attention over `[T, 48]`** — needs `MatMul` (have), `Softmax` (have),
  `Transpose`, `Add`, a `Gather`/`Slice` for masking — several small ops.

Recommendation: add **1-D `Conv`** first (smallest, reusable) and a TCN
architecture; add `GRU` if a recurrent cell proves necessary. Each op ships with
a hand-computed golden test like the existing `evalGemm` / `evalSoftmax` tests.

### `inference` and the runtime

A parallel interface, as with anomaly:

```go
type SequenceScorer interface {
    ID() string
    Family() string
    Role() Role
    ScoreSequence(seq [][features.Size]float64) Scores  // seq is oldest-first, len ≤ T
}
```

`Runtime` keeps a `sequence []SequenceScorer` slice (like `anomaly`), an
`ActivateRole`/`DeactivateRole` case, and `Score` type-switches. A sequence
model's output feeds `Result.Models` and the disagreement set exactly like a
`location`/`global` peer — it is a supervised verdict, just one with memory.

### Trainer

`synapse-trainer` gains `objective: "sequence"`: `mixture.py` builds
`[N, T, 48]` windows per key from a labelled corpus (the label is the newest
row's), `train.py` builds a torch `Conv1d`/`GRU` net, `export.py` writes the
`[1, T, 48]` → `[1, 7]` ONNX (softmax included, like the classifier). The
`architecture.py` family table gains `flow-sequence-v1` with a `seq_len`
parameter alongside the hidden stack.

## What shipped (the windowed-FFN cut)

The Go runtime for `flow-sequence-v1` is done and does not touch `internal/nn`:
the graph is a plain `[T*48] -> … -> [7]` softmax MLP (the `[T, 48]` window
flattened, oldest-first, left-padded with the zero vector).

- `schema`: `FamilySequenceV1`, frozen `SequenceLenV1 = 16`; `BundleMeta.SeqLen`
  and `Architecture.SeqLen` (additive, `omitempty`). `ValidateBundle` /
  `ValidateArchitectureForFamily` branch on the family; the param-math funcs use
  `effectiveInputSize() = SeqLen*InputSize` (768) for the first Dense.
- `inference`: `SequenceScorer` + `RoleSequence`; `ONNXSequenceModel` does the
  pad/flatten/per-step-normalise/run. `Runtime.ScoreSequence(v, window)` folds
  the peer into `Result.Models` and the disagreement set — never the verdict
  driver. `ActivateRole(role, any)` grows a sequence slot alongside
  primary + anomaly.
- `internal/pipeline`: a bounded, lock-free per-conversation feature-vector ring
  (`seqWindows`, capped off the flow-table size, least-recent-quarter eviction
  counted in `Stats.SeqWindowsEvicted`); `publish` feeds `ScoreSequence` a
  window whenever a sequence model is loaded.
- `modelrun.BuildLive`, `registry.roleForFamily`, the `/api/v1/models` list and
  activation route all recognise the family.

## Still a follow-up

- The trained model that keeps the time axis: add **1-D `Conv`** to
  `internal/nn` (smallest, reusable; a TCN architecture) and, if a recurrent
  cell proves necessary, `GRU` — each with a hand-computed golden test like
  `evalGemm` / `evalSoftmax`.
- `synapse-trainer` `objective: "sequence"`: `[N, T, 48]` windows per key, a
  torch `Conv1d`/`GRU` net, `[1, T, 48]` → `[1, 7]` ONNX. Until then the
  runtime is exercised with `internal/modeltest` sequence bundles.
- Surfacing `Stats.SeqWindowsEvicted` on `/api/v1/status`.

## Consequences

- Issue #62's runtime is in; the remaining work is a trained model and its
  trainer support — tracked as a follow-up. Per PROJECT.md §30 this cadence is
  explicitly acceptable.
- The `[T, 48]` input, `T = 16`, and the `traffic-classes-v1` output are the
  frozen choices; the model architecture (flatten-MLP now, TCN/GRU later) is the
  trainer's to pick within the family, like the hidden stack.
