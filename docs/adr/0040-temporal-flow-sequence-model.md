# 0040 — Design for a temporal model over flow sequences (`flow-sequence-v1`)

**Status:** Proposed, 2026-09-02

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

## Consequences

- This is **Phase-9-scale**: a new frozen family, an `internal/nn` op-set
  expansion with its own golden tests, per-key ring plumbing on the packet path
  (with its own eviction counters on `/api/v1/status`), a trainer objective, and
  a windowed dataset. It is not a follow-up commit.
- Until it is built, issue #62 stays open as the one deferred Phase-7 item; the
  other six leaves (#47, #48, #49, #63, #65, plus this design) are done. Per
  PROJECT.md §30 this is explicitly acceptable — "keep in mind but do not
  block".
- The `[T, 48]` input and the `traffic-classes-v1` output are the only frozen
  choices here; the model architecture (TCN vs GRU vs attention) is the
  trainer's to pick within the family, exactly like the hidden stack today.
