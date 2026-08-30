# 0001 — Go owns the data plane; Python only trains

**Status:** Accepted, 2026-08-31

## Context

SynapseIDS has to capture or replay traffic, decode packets, build bidirectional
flows, extract a fixed feature vector, run one or more classifiers, serve a REST
API, and push a live stream — continuously, without dropping packets
(PROJECT.md §5.1, §22). It also has to train neural-network models, which is a
batch, offline, GPU-friendly job with a mature ecosystem in exactly one language.

PROJECT.md is explicit: "Go owns the data plane" (§2.1), "Training may use
Python" (§2.2), "The Go daemon must not depend on Python for normal inference"
(§5.4), and the recommended stack is Go for the backend, Python + PyTorch for
training, ONNX as the hand-off format (§27).

Options considered: (a) everything in Python — the packet path fights the GIL and
the deployment story is a fat interpreter; (b) everything in Go including
training — immature ML tooling, no reason to fight it; (c) split along the
capture/serving vs. training line.

## Decision

Option (c). Every stage of the data plane is Go, in `internal/` packages with
explicit interfaces and strictly one-way dependencies (see
[architecture.md](../architecture.md)): `capture`, `packet`, `flow`, `features`,
`inference`, `events`, `storage`, `wshub`, `api`, `pipeline`. All three binaries
(`synapsed`, `synapse`, `synapse-sensor`) are Go.

Python (PyTorch) is confined to offline training in `trainer/` (Phase 2). It
consumes datasets and emits a self-describing bundle — `model.onnx` +
`normalizer.json` + `metadata.json` + `metrics.json` + `training-recipe.json`
(PROJECT.md §11). `synapsed` loads a bundle only after
`schema.ValidateBundle` accepts its feature/output contract, and runs it with a
Go ONNX runtime. The daemon never calls Python at inference time.

Phase 1 ships a pure-Go rule-based `inference.Heuristic` so the entire pipeline
runs and is testable with zero ML dependencies
([ADR 0003](0003-phase1-scope-in-memory-store-heuristic-classifier.md)).

## Consequences

- One static `CGO_ENABLED=0` binary per arch; the four Linux targets and the
  `.deb`s follow for free ([packaging.md](../packaging.md)).
- The hot packet path has no FFI boundary and no interpreter.
- Capture transports are Go adapters behind `capture.Source`; adding one does not
  touch anything downstream (PROJECT.md §2.10).
- A Go ONNX runtime must be found and maintained — the main Phase-2 risk.
- Feature extraction exists twice: `internal/features` for serving, and a
  matching implementation in the trainer. The frozen `flow-features-v1` schema
  plus golden vectors ([features-v1.md](../features-v1.md)) are what keep the two
  honest.
- Contributors need Go for anything on the data plane; Python knowledge is only
  needed for `trainer/`.

**Revisit when:** a Go ONNX runtime proves unviable for the architectures in
PROJECT.md §10, or profiling shows the Go feature path is the bottleneck and a
native/sidecar alternative would clearly win.

---

⟦THUGS⟧ (c) 2026
