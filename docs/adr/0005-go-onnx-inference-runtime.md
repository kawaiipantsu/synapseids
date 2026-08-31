# 0005 — A minimal pure-Go ONNX executor for trained-model inference

**Status:** Accepted, 2026-08-31

## Context

Phase 2 adds real inference: the Python trainer exports a model as ONNX inside a
bundle, and `synapsed` must load and run it for normal classification. PROJECT.md
is categorical that "the Go daemon must not depend on Python for normal
inference" (§5.4), and [ADR 0001](0001-go-owns-the-data-plane.md) already commits
the data plane to Go with a "Go ONNX runtime" as the named Phase-2 risk.

The repo constraints are hard (`CLAUDE.md`, PROJECT.md §27, §28.16):
`CGO_ENABLED=0` everywhere, **zero third-party Go dependencies**, and a clean
offline cross-build to `linux/amd64`, `linux/386`, `linux/arm64`,
`linux/arm`. That rules out the realistic off-the-shelf options:

- **`onnxruntime` via C bindings** (`github.com/yalue/onnxruntime_go` and
  friends) — needs CGO and a per-arch native `libonnxruntime`. Fails the CGO and
  offline-cross-build rules outright.
- **`onnx-go` / `gorgonia`** — pure Go but a large dependency tree
  (`gorgonia.org/tensor`, `gonum`, BLAS shims), and it is not maintained against
  current ONNX opsets. Fails the zero-dependency rule.
- **A WASM build of onnxruntime + a Go WASM runtime** — enormous, and still a
  dependency.

What actually has to run is small. The Architecture Builder (§10, §19.9) locks
the input and output layers and only lets the operator edit *hidden* layers:
width, activation, dropout, batch-norm, optional residual blocks. The trainer
therefore emits one narrow class of graph — a feed-forward MLP over a 48-value
input to a 7-way softmax. That is a few matrix multiplies and elementwise
functions, not a general tensor VM.

## Decision

Add `internal/nn`: a **minimal, stdlib-only, CGO-free executor** for exactly the
graph class the builder produces, plus a hand-rolled reader for the slice of the
ONNX protobuf wire format needed to load one.

**Wire format.** An unexported protobuf decoder (`protobuf.go`) implements just
varint / length-delimited / fixed32 / fixed64 reading, bounds-checked, never
panicking. `onnx.go` walks `ModelProto → GraphProto → {NodeProto,
TensorProto initializers, ValueInfoProto}`. Initializers are read from
`float_data` or little-endian `raw_data`; `int32` / `int64` initializers (Reshape
shapes) are accepted and cast. No protobuf library is vendored or generated.

**Ops in scope** — anything else is a hard load-time error
(`nn: unsupported op %q`), never silently skipped (§28.11 spirit):

| Op | Notes |
|---|---|
| `Gemm` | `alpha`, `beta`, `transA`, `transB`; the `nn.Linear` export shape |
| `MatMul` | 1-D/2-D operands, batch 1 |
| `Add` | NumPy broadcast — covers bias adds and residual-block joins |
| `Relu`, `LeakyRelu` (`alpha`), `Sigmoid`, `Tanh` | elementwise activations |
| `BatchNormalization` | inference form only: folded to a per-channel affine from `scale`/`B`/`mean`/`var` + `epsilon` |
| `Dropout` | identity at inference (extra `mask` output and `ratio`/`training_mode` ignored) |
| `Softmax` | numerically stable, per `axis` (default -1) |
| `Identity`, `Flatten` (`axis`), `Reshape` | shape bookkeeping; `Reshape` needs a constant/initializer shape and resolves one `-1` and per-dim `0` |
| `Constant` | folded to an initializer before execution (so a `Reshape` shape may come from a `Constant` node, not only an initializer) |

**Runtime shape.** Batch size is fixed at 1. Every value is `float32` and every
operation is deterministic (fixed evaluation order, `float32` accumulation,
`math` functions applied in `float64` then narrowed). Nodes are topologically
ordered by a fixpoint scan; a cycle or dangling tensor is an error. Input and
output sizes are resolved from the graph's declared shapes (last concrete
dimension, batch pinned to 1), falling back to the first/last `Gemm`/`MatMul`
weight when a model carries only a symbolic batch axis. A malformed model always
returns an `error` — a top-level `recover` converts any unforeseen panic into
one.

**Public API** (`nn.go`): `Load(io.Reader)`, `LoadFile(path)`,
`(*Model).Run([]float32) ([]float32, error)` (validates `len(input) ==
InputSize()`), and `InputSize()` / `OutputSize()` / `OpCounts()` for
diagnostics. `Model` is immutable after load, so `Run` is safe for concurrent
callers.

**Adapter.** `inference.ONNXModel` (`internal/inference/onnx_model.go`) wraps an
`*nn.Model` as a `Classifier`, so a trained model scores through the same
`Runtime` as the heuristic and its per-model output is recorded (§12). It takes
an optional `Normalizer` (`func(features.Vector) [48]float64`) supplied by the
caller from the bundle's `normalizer.json`; when nil the raw feature values are
fed, exactly as the heuristic path works today. `internal/nn` does **not** import
`inference` or `features` — the feature/score mapping lives only in the adapter.

**Test fixtures.** `internal/nn/onnxbuild` is a small ONNX `ModelProto` *writer*
(the mirror of the reader) used only by tests and by
`internal/nn/testdata/gen`, which regenerates the committed 48→8→7 fixture
`internal/nn/testdata/model.onnx` (`go run ./internal/nn/testdata/gen`).
Committing generator and output together follows the PCAP-fixture convention
(§25).

## Consequences

- No new dependency, no CGO; `make build-linux` (all four arches, including the
  32-bit `386`/`arm`) and the offline build are unaffected.
- The trainer must stay inside this envelope: plain feed-forward MLPs with the
  activations above. A future need for convolutions, recurrence, attention or an
  autoencoder anomaly head (§13, §30) is a **new executor capability with its own
  ADR and op list**, not a silent extension — the loader will reject the unknown
  op until then.
- The executor is straightforward `float32` triple loops. It is fast enough for
  per-flow scoring (a 48→64→32→7 net is ~14 µs/op on an x86-64 dev box) but is
  not vectorised; if profiling ever shows inference on the hot path, that is a
  contained optimisation behind the same API.
- `internal/nn` and the trainer now both encode the ONNX op semantics. The
  `onnxbuild` round-trip tests and the golden `model.onnx` fixture are what keep
  the reader honest; the trainer side is covered where it lives.
- `schema.ValidateBundle` remains the contract gate (feature schema, input size,
  output schema, output size). `NewONNXModel` re-checks input/output dimensions
  defensively at wiring time.

**Revisit when:** the model family needs an op outside the list (residual-heavy
architectures aside — `Add` already covers those), an anomaly/autoencoder model
lands, or per-flow inference latency shows up in a profile and a BLAS-style inner
loop or an optional accelerated path becomes worth the complexity.

---

⟦THUGS⟧ (c) 2026
