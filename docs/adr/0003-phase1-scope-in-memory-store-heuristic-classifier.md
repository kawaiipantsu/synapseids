# 0003 — Phase 1 ships an in-memory store and a rule-based classifier

**Status:** Accepted, 2026-08-31

## Context

Phase 1 is the vertical slice: `PCAP file → packet decoder → flow engine →
flow-features-v1 → simple classifier → REST API → WebSocket → rolling live flow
log`, with the UI already showing live/replayed classifications
(PROJECT.md §26 Phase 1, §29, §31). Phase 2 is where real inference lands — the
Python trainer, ONNX export, a Go ONNX runtime, model bundles and a registry
(§26 Phase 2). Storage is meant to "start with SQLite" behind an interface that a
higher-volume backend can replace later (§20).

The goal for Phase 1 is to exercise the *entire* pipeline end to end before
committing to an ONNX runtime or an on-disk schema — both of which carry risk and
neither of which is needed to prove the path works.

## Decision

Phase 1 deliberately ships two throwaway-friendly implementations, each behind
the interface its Phase-2 replacement will use:

- **`storage.Mem`** — fixed-capacity ring buffers behind `storage.Store`
  (`PutFlow`, `PutClassification`, `Flow`, `RecentFlows`,
  `RecentClassifications`, `Stats`). Oldest records are overwritten and counted
  as evicted. `config` recognizes `driver: "sqlite"` but `validate()` rejects it
  with "not implemented yet"; `memory` is the only working driver.
- **`inference.Heuristic`** — a transparent, rule-based classifier that emits a
  real `traffic-classes-v1` softmax distribution, wired as `RolePrimary` in
  `inference.Runtime`. It is conservative by construction: no rule fires →
  `normal`; a weak signal → `suspicious`, never a forced attack class
  (PROJECT.md §13).

`inference.Runtime` already scores through every registered model, records each
`ModelOutput` (not just the combined verdict), and flags disagreement
(PROJECT.md §12) — so adding ONNX models in Phase 2 is additive, not a rewrite.

## Consequences

- The full path — `capture → flow → features → inference → events/storage →
  REST/WS → UI` — runs and is testable today (`internal/pipeline`, the golden
  tests, `api_test`).
- No data migration and no ONNX-runtime dependency block the slice.
- The heuristic's rules double as executable documentation of what each traffic
  class looks like, and as a baseline for the first trained model.
- Nothing survives a restart. History is bounded by `storage.max_flows`
  (default 50 000) and silently evicted — not a time-based retention policy.
- The heuristic is **not** an operational detector: it only fires on hand-tuned
  thresholds over a handful of features. Do not rely on its verdicts.
- Two `Store` / `Classifier` implementations to keep in sync once Phase 2 lands.

**Revisit when:** Phase 2 starts — a Go ONNX runtime and model bundles arrive
(the heuristic drops to `experimental` or a test-only default), and SQLite
becomes the default `storage.driver` with a real retention sweeper
(PROJECT.md §20, §23).

---

⟦THUGS⟧ (c) 2026
