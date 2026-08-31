# 0015 — Versioned, immutable datasets as directories on disk

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §14 makes datasets **first-class versioned objects**, not a CSV an
operator exports and forgets. A dataset must record its id, name, description,
location, tags, creation time, source capture ids, time range, feature schema,
output schema, flow count, label counts, labeling source, parent datasets, and an
immutable content hash. §19.10 adds the operator surface: creation, metadata,
label distribution, merge/derive, class-imbalance warnings and duplicate
warnings. §21 requires dataset edits to be audited. Issue #33 is the Phase-4 work
item.

Two things already exist that this must fit between. Downstream,
`trainer/synapse_trainer/dataset.py` `load_csv` is the consumer: it reads a CSV
whose columns are the 48 `flow-features-v1` names, spelled exactly as the frozen
schema spells them, plus a `label` column holding a `traffic-classes-v1` class
name or id. Upstream, `internal/storage.Mem` is a **bounded ring that evicts** —
so a dataset cannot be a saved query or a live view; it has to be materialised
to disk the moment it is cut, or it decays.

Constraints carried from the rest of the repo: zero third-party dependencies,
`CGO_ENABLED=0`, four Linux architectures, the frozen `flow-features-v1` /
`traffic-classes-v1` / `event-envelope-v1` contracts, and the packet path must
not block on API or disk work (§22).

## Decision

### One directory per version; the layout is the index

```text
<datasets.directory>/<id>/<version>/dataset.csv
<datasets.directory>/<id>/<version>/manifest.json
```

An id may contain one `/` — §14's own examples are `thugs/lab-attacks-2026-08`
and `hq-copenhagen/baseline-2026-08` — so an id is one or two path segments and
the version is always the last one. `datasets.directory` defaults to
`./data/datasets`, overridable with `SYNAPSE_DATASETS_DIR`.

`dataset.Open` walks the tree at startup and loads every `manifest.json` it can
parse; a missing directory starts empty and a corrupt or unparseable manifest is
logged and skipped, never fatal — the same posture `registry.Open` takes so a bad
file cannot wedge the daemon (§21).

**Why no `datasets.json` index, when `registry.json` is the precedent?** The
registry's entries describe bundles that live *somewhere else*, so it needs a
list. Here the manifest lives inside the thing it describes, and a version
directory is self-contained: `ls` and `cat` tell you everything, and a
`scp -r` of one directory is a complete, valid dataset. A second index file could
only ever disagree with the manifests. Scanning is cheap because the tree is
bounded by the number of datasets an operator has cut, the walk is depth-capped
at the version level, and it happens once at startup, off every packet path.

Writes are atomic at the granularity that matters: the two files are staged in a
`.staging-*` directory under the root and the whole directory is `rename`d into
place, so a reader never sees a version with a manifest but no CSV, and a crash
mid-write leaves no half-built version. This is `registry.persistLocked`'s
temp-file+rename, widened to a directory because a version is two files that must
appear together.

**Why not SQLite?** Issue #53 (the SQLite store) is still open, and the
`registry.json` precedent already establishes that Phase-4 metadata lives in flat
files until it does. A dataset's *rows* would not go in SQLite in any case — the
trainer wants a CSV file it can point `load_csv` at, and a `.db` an operator
cannot `head` is a worse artifact for something whose whole purpose is to be
handed to another tool on another host. When #53 lands, the manifests become a
table and the CSVs stay files; the on-disk layout here is deliberately the shape
that migration wants.

### The CSV is the trainer contract, verbatim

The header is the 48 `flow-features-v1` names in frozen schema order, then
`label`. One row per flow, sorted by flow id. Values are Go's shortest
round-tripping float representation, which Python's `float()` parses unchanged.
No quoting is ever emitted because no value can ever need it. Because `load_csv`
also accepts a *directory* containing `dataset.csv`, a version directory can be
handed to the trainer as-is. `internal/dataset`'s round-trip test asserts the
header and row shape from the Go side always, and additionally runs the real
`load_csv` when `python3` + `numpy` are importable.

### The content hash covers the data, and only the data

```text
sha256( "synapseids-dataset-v1\n"
      + "feature_schema:flow-features-v1\n"
      + "output_schema:traffic-classes-v1\n"
      + <the exact dataset.csv bytes> )
```

recorded as `sha256:<lowercase hex>`. The CSV bytes carry the feature values, the
label column and the column header, so the digest covers the rows, the labels and
the column identity; the domain-separator lines bind it to this dataset format
and the frozen schema pair, so the same rows under a future
`flow-features-v2` could never collide. Nothing else is in scope: two datasets
built from the same rows and labels hash identically regardless of their id,
version, name, description, tags or creation time. That is the property that
makes the hash useful — it answers "is this the same data?", not "is this the
same file?".

Row order is therefore load-bearing, and it is fixed: sort by flow id. Where a
flow has been classified more than once (a long flow's periodic snapshots), the
newest verdict wins and the flow contributes exactly one row. A test builds the
same store twice into two different roots under two different names and asserts
the hashes match byte-for-byte.

### Immutability, and what Derive and Delete mean

A written version is never modified. `Create` refuses an existing `(id, version)`
— including a directory that exists on disk but failed to parse at `Open`, so a
manifest we could not read can never be clobbered. A correction is a **new
version** that names its predecessor in `parent_datasets`; `Derive` records the
parent and inherits its whole ancestor chain. An omitted version auto-assigns
`v<max+1>`.

`Derive` re-selects from the flow store rather than transforming the parent's
CSV. That covers the common case honestly — "same corpus, tighter filter" — and
stops short of dataset-to-dataset merge with weighting, which is the *training
recipe* work of §14 and belongs with the trainer, not here.

`Delete` is allowed and audited. Immutability protects a version's *contents*,
not its existence: an operator who cut a dataset from the wrong window must be
able to remove it, and refusing would push the only escape hatch outside the
product, where it would be an `rm -rf` with no audit line. The UI warns that a
model trained on the dataset keeps only the hash, not the rows.

### Ids are validated, not sanitised

An id is one or two segments of `[a-z0-9]`, `.`, `_`, `-`, each 1–64 characters,
each starting and ending with a letter or digit. Lowercase only, so two ids
cannot collide on a case-insensitive filesystem. No `@` (it separates id from
version in a reference), no `:`, no backslash, nothing else. Path traversal is
impossible **by construction rather than by filtering**: `..` cannot form because
a segment may not start with `.`, and the only surviving characters are slug
characters. `Delete` re-derives its path from the validated id rather than
trusting the `dir` in a manifest, so a hand-edited file cannot aim it elsewhere.

### A selection that cannot teach anything is an error, not a file

`Create` refuses a selection yielding zero rows, exactly one class, or fewer than
`MinRows` (20) rows, each with an error that says which and why. Datasets that
*are* built carry warnings in the manifest: class imbalance above 90 % for one
class, classes with no rows at all, exact duplicate rows, verdicts whose flow
record had already been evicted from the ring, and non-finite feature values
replaced by the schema's `default_missing`. These are §19.10's class-imbalance
and duplicate warnings, computed once at build time and surfaced on every row of
the UI rather than recomputed by each viewer.

### `labeling_source` is honest, and cannot be made to lie

**Phase 4 has no human review loop.** Issue #42 is open, so a dataset built today
is labelled by the daemon's own classifier — the heuristic, or whichever model
was active. The manifest records that literally, as
`model_prediction:<sorted model ids>`, and `internal/dataset` has **no code path
that can write `human_review`**: the value is computed from the model ids present
in the selected verdicts, never supplied by the caller. There is no override
field to argue with.

This matters because training on model-predicted labels is a real technique —
distillation, bootstrapping a location model — and also a very easy thing to
mistake for ground truth six months later when the only thing left is a CSV. The
SPA states it in a banner above the list and renders `labeling_source` as a
caution-coloured badge on every row. When #42 lands and an operator can confirm
or correct a label, a reviewed dataset will record `human_review` and the same
badge will render it as an accent; until then, nothing claims it.

### Audit, but no bus event

Create, derive and delete are written to the existing append-only audit log
(§21, §28.14). `audit.Record` gains a generic `subject_type` + `subject` pair;
`Log(event, actor, modelID, detail)` is unchanged for its existing callers and
now writes `subject_type:"model"` with `model_id` still populated, so anything
reading the log by `model_id` keeps working.

There is deliberately **no `DatasetCreated` envelope on the event bus**.
`event-envelope-v1`'s `event_types` enum is frozen and has no `Dataset*` member;
adding one is an `event-envelope-v2` decision, not a side effect of this issue
(§28.5). For datasets the audit log is the record.

### REST: one escaped `{ref}` segment

An id containing `/` would split `GET /api/v1/datasets/{id}/{version}` into an
ambiguous number of segments, so a version is addressed by one url-escaped
segment holding `<id>@<version>`:

```text
GET    /api/v1/datasets                      list every manifest, newest first
POST   /api/v1/datasets                      201 · 400 · 404 · 409 · 422
GET    /api/v1/datasets/{ref}                one manifest + its sibling versions
DELETE /api/v1/datasets/{ref}                audited
GET    /api/v1/datasets/{ref}/download       text/csv
```

`net/http`'s `ServeMux` matches wildcards against the *escaped* path and
unescapes each segment for `PathValue`, so `%2F` stays inside one segment and
arrives intact — verified by test. The one deployment caveat, documented in
`docs/api.md`, is that a reverse proxy which normalises `%2F` into `/` breaks
this; that only arises off loopback, which these routes are not ready for anyway
(issue #58).

The selection spec reuses the `GET /api/v1/classifications` filter vocabulary —
`class`, `model`, `min_confidence` (accepting a 0..100 percentage exactly as the
flow log's slider sends it), `disagreement` — with the same meanings, plus
`from`, `to`, `proto`, `initiator_ip`, `responder_ip` and `limit`. An operator
previews a cut in the Flow Log and then builds it with the same words.

## Consequences

**Good.** A dataset is inspectable with `ls` and `cat`, copyable with `scp -r`,
and loadable by the trainer with no adaptation. The content hash is reproducible
and means something. Immutability plus `parent_datasets` gives §14's lineage for
free. Nothing was added to the packet path, no dependency was added, and no
frozen schema was touched.

**Costs, accepted.** Startup scans the tree, so a pathological number of dataset
versions would slow boot — bounded by operator action, and the fix is #53's
database, not a cache. `created_at` has one-second resolution, so two versions
cut in the same second tie in `List`; the tiebreak is id ascending then version
descending, which keeps `Latest` right for the case that actually happens. A
dataset is a full copy of its rows, so overlapping datasets duplicate data on
disk — the alternative, a saved query, is exactly what the evicting ring makes
impossible. `Derive` cannot yet merge or weight; that is the training recipe.
