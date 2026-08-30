# 0002 — Feature/output schemas are frozen contracts; Phase-1 config is JSON

**Status:** Accepted, 2026-08-31

## Context

"Version everything" and "never silently change the meaning or ordering of a
versioned feature schema" are core rules (PROJECT.md §4, §8, §28.5). A model is
trained against an exact input contract: if feature #12 silently changed
meaning, every deployed model would be quietly wrong with no error anywhere. The
output vector and the model family's input/output sizes are locked the same way
(§9, §10, §28.6).

Separately, PROJECT.md §23 asks for "one explicit configuration file plus
environment-variable overrides for secrets/deployment concerns", and its example
is written in YAML. Phase 1 also aims to stay dependency-free where it reasonably
can — a YAML parser is a third-party dependency and a supply-chain surface.

## Decision

**1. `flow-features-v1` (48 features) and `traffic-classes-v1` (7 classes) are
immutable contracts.** They live as embedded JSON under `schemas/` with
`"frozen": true`. `internal/schema` `init()` panics on any drift (feature count ≠
`input_size`, misordered `index`, class count ≠ `output_size`).
`internal/features` pins `Size = 48` and is guarded by golden PCAP→vector
fixtures in CI ([features-v1.md](../features-v1.md)). A new measurement need
creates `flow-features-v2` and a new model family `flow-classifier-v2`; the v1
files are never edited. `schema.ValidateBundle` rejects a model whose
`feature_schema` / `input_size` / `output_schema` / `output_size` does not match
this build, before inference (PROJECT.md §9, §11). The same JSON is served at
`/api/v1/schemas/*` so the trainer and any client read one machine-readable
contract.

**2. Phase-1 configuration is a single JSON file plus `SYNAPSE_*` env
overrides**, loaded by `config.Load` (`encoding/json` only, unknown fields
rejected). Not YAML — this keeps the Phase-1 build free of third-party
dependencies. PROJECT.md §23's YAML example is treated as illustrative; a native
YAML loader is tracked and will be added as an alternative, not a replacement.

## Consequences

- A trained model either loads against a contract it fits, or is refused — never
  silently mis-fed.
- Trainer and daemon share exactly one definition of the feature and output
  vectors.
- No YAML dependency, no parser CVE surface, for Phase 1.
- A schema mistake found after the freeze costs a full `v2` plus a model
  retrain — the freeze is a real commitment, not a label.
- JSON config has no comments; the mitigation is an annotated example
  (`contrib/config/synapse.json`, referenced by the `synapsed` man page — not in
  the tree yet).
- The `flow-features-v1` freeze deferred the cross-flow host-context features and
  `payload_entropy` from PROJECT.md §8 to a future `v2`
  ([features-v1.md](../features-v1.md)).

**Revisit when:** `flow-features-v2` is actually needed (a host-context tracker
lands), or operators find hand-editing JSON config painful enough to prioritize
the YAML loader.

---

⟦THUGS⟧ (c) 2026
