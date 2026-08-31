# 0021 — The human review loop, prediction preservation, and curated datasets

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §16 defines the human review loop: every classification is
reviewable, an operator may assign or correct a label, reviewed flows export into
a curated dataset, and the lifecycle runs
`capture → classification → human review → curated dataset → retraining →
evaluation → deployment`. Issue #42 tracks it. Issue #64 ("Idea:
active-learning review queue") asks that the queue prioritise uncertain and
high-disagreement samples; it is a ranking over the same store and ships here.

§16 ends with one sentence that constrains the whole design:

> Always retain the original model prediction separately from the human-reviewed
> label.

Everything else in §16 is a feature. That sentence is a safety property, and the
reason is practical: a curated dataset is the most expensive data in the system,
and its value depends entirely on knowing which labels are a person's judgement
and which are the daemon's own guess. If a review could overwrite a prediction,
that distinction would be silently destroyed the first time someone corrected a
verdict — and nothing downstream could tell.

What existed on `develop` and shapes the design:

- **`internal/dataset`** wrote immutable versioned datasets whose
  `labeling_source` was always `model_prediction:<ids>`. The package comment said
  in as many words that no code path could write `human_review`. That was
  deliberate honesty, and this ADR is what makes it false — carefully.
- **`internal/storage.Mem`** is a bounded ring that evicts. A flow's verdict does
  not live forever.
- **`event-envelope-v1` is frozen** and already contains `ReviewUpdated`, so no
  schema change was needed.
- **`internal/audit`** is the append-only record §21 asks for
  ("… and human label changes").

## Decision

### The prediction is preserved structurally, not by convention

`review.Review` holds the model's claim in an **unexported** `prediction` value:

```go
type prediction struct {
    class   string
    score   float64
    modelID string
}
```

Two independent locks follow from that:

1. **No exported way to build or mutate one.** `prediction` has unexported
   fields, no exported constructor and no setters. Outside `internal/review` the
   values are reachable only through `Review.PredictedClass()`,
   `PredictedScore()` and `ModelID()`, and through the flat
   `predicted_class` / `predicted_score` / `model_id` JSON keys that
   `Review.MarshalJSON` emits. Both are read-only. Because `Review` has no
   struct tags of its own, the JSON shape lives in exactly one place.

2. **The write API has nowhere to put one.** The only mutator is
   `Put(flowID, state, label, note)`. A caller has no prediction argument to
   pass, so no request body, no handler and no future caller can supply one. The
   store fetches the prediction itself — once, on the *first* review of a flow —
   from the classification store, via `capture(c)`, the sole constructor. Every
   later `Put` starts from `upd := *cur`, which copies the value forward; there
   is exactly one assignment to a `pred` field in the package and it is in the
   first-review branch.

The REST layer inherits this for free. `reviewWriteRequest` has three fields
(`state`, `human_label`, `note`) and the decoder uses `DisallowUnknownFields`, so
`{"state":"correct","predicted_class":"normal"}` is a `400`, not a silent no-op.
`UnmarshalJSON` does fill the prediction, but it exists solely so a restart does
not lose it, and it never sees request data — the API decodes its own struct.

`TestPredictionIsNeverOverwritten` is the proof. It reviews a flow, then stores a
*new and different* verdict for that same flow in the classification store (the
model was re-run and changed its mind — precisely the case §16 protects against),
then re-reviews. It asserts that `state`, `human_label`, `note` and `updated_at`
all moved and that history gained the superseded decision, while the three
`predicted_*` keys come back **byte-identical** — compared as marshalled JSON,
not as float equality — both immediately and after a reload from disk.
`TestNoExportedWayToSetThePrediction` additionally pins `Put`'s signature at
compile time.

### `Open` takes the classification store

`review.Open(dir, src, bus, aud, logf)` carries `src` because lock (2) requires
it: if the prediction arrived as a `Put` argument the invariant would be a
comment, not a property. This mirrors `dataset.Open(dir, src, …)`, the
established shape here for a store that reads the flow store. The cost is a
linear scan of the newest `PredictionScan` (50 000) verdicts per review — human
paced, far off the packet path (§22). A flow whose verdict has aged out of that
window can no longer be reviewed; `Put` returns `ErrNoFlow`, the API returns
`404`, and the message says which of the two reasons applies.

### The five states, and what each one is allowed to assert

The enum is §16's, unchanged: `unreviewed | correct | incorrect | unsure |
ignored_pattern`. The validation rules follow from taking "retain the prediction
separately" seriously — a state either asserts a class or it does not, and it may
never assert one that contradicts itself:

| state | `human_label` | effective label | terminal? |
| --- | --- | --- | --- |
| `unreviewed` | must be empty | — | no |
| `correct` | optional; if given, must equal the prediction | the prediction | yes |
| `incorrect` | **required**, and must differ from the prediction | the correction | yes |
| `unsure` | must be empty | — | no |
| `ignored_pattern` | must be empty | — | yes |

`correct` means "the prediction *is* the label", so the label is **derived** from
the prediction rather than copied into `human_label` — `EffectiveLabel()`
computes it on every read and therefore cannot drift. `incorrect` with a label
equal to the prediction is refused with a message pointing at `correct`;
agreeing and disagreeing are not the same decision. `unreviewed` is storable on
purpose: writing it is how an operator un-reviews a flow and returns it to the
queue without losing the history of what they thought before.

`ignored_pattern` is the interesting one. It means "stop showing me this" — a
judgement about the review queue, not the claim "this traffic is class X". So it
carries no label, it is terminal, and it is excluded from curated datasets by
default.

### Uncertainty ranking: smallest margin

The queue's `sort=uncertainty` (issue #64) ranks by **margin**, ascending:

```
margin  = p_top1 - p_top2      over the authoritative model's 7-class vector
uncert  = 1 - margin           reported so bigger always means "review sooner"
entropy = -Σ pᵢ ln pᵢ / ln 7   reported alongside, 0 (certain) .. 1 (uniform)
```

Margin over entropy, because margin measures the question a reviewer actually
answers: *which of these two is it?* A flow at `{normal 0.49, scan 0.48, …}` is a
genuine coin-flip a human settles at a glance. Entropy would rank
`{0.4, 0.3, 0.3}` — diffuse but not contested — above it, which is the less
useful question. Margin is also the standard smallest-margin acquisition
function, it is cheap, and it is explainable: the UI prints the two classes that
are fighting (`top1` / `top2`), so an operator can see why a row is near the top.
Entropy is computed anyway because it is the better summary of "the model has no
idea at all" and costs nothing.

The vector is normalised by its sum before the margin is taken, so the ranking
does not depend on an experimental classifier handing back an unnormalised
vector. Degenerate cases are explicit:

- **uniform** (all 1/7) → margin 0, entropy 1 → first. This is also what a
  broken or untrained model looks like, which is exactly what should reach a
  human.
- **no usable vector** (no model output, or the vector sums to zero) →
  `scores_available: false`, margin 0, entropy 1 → first. "We know nothing" is
  maximally uncertain; treating it as certain would let a silently-failing model
  keep its flows out of review.
- **one-hot** → margin 1, entropy 0 → last.

Ties break by newest first, then flow id, so every ordering is total and the
result is deterministic.

`sort=disagreement` leads with `Result.Disagreement` and falls back to the margin
order inside each group — multi-model disagreement is the other high-value review
signal (§12). `sort=recent` is plain newest-first and is the default, because it
is what an operator watching live traffic expects.

### Queue membership

A flow leaves the queue when its review state is **terminal**: `correct`,
`incorrect` or `ignored_pattern`. `unsure` **stays in**, deliberately: the
operator said "I don't know", which is a request to come back to it, not an
answer — and the note they left is carried forward so the next reviewer sees what
stumped the last one. A flow with no review at all, or an explicit `unreviewed`,
is in the queue. One entry per flow: a long flow is classified repeatedly by
periodic snapshots, and the newest verdict wins, matching `dataset.build`.

The queue reuses `parseClassFilters`, so `class`, `model`, `min_confidence` and
`disagreement` mean exactly what they mean on `GET /api/v1/classifications` and
on a dataset selection.

### The `human_review` labeling-source gate

`dataset.Selection` gains `reviewed` (and `include_ignored`). With `reviewed`,
the build reads the review store instead of the classification ring and writes
the **human's** label into the CSV `label` column. Only then may
`labeling_source` say `human_review`, and it says it because the labels genuinely
came from people — not because a caller asked for the string. There is no
`labeling_source` field anywhere in the request.

| review state | in a reviewed cut | label | counts as |
| --- | --- | --- | --- |
| `correct` | yes | the prediction the human confirmed | human |
| `incorrect` | yes | the human's correction | human |
| `ignored_pattern` | only with `include_ignored` | the model's *unconfirmed* prediction | model |
| `unsure` | no | — | — |
| `unreviewed` | no | — | — |

So there are three honest values, and the SPA badge renders all three:

- `human_review` — every label was asserted by a person.
- `human_review+model_prediction:<ids>` — a mixed cut. `include_ignored` was set,
  and those rows carry a prediction nobody confirmed. The manifest also warns
  about it in words.
- `model_prediction:<ids>` — the default cut, unchanged, keeping its caution
  badge.

In a reviewed cut the remaining predicates are evaluated against the review and
the stored flow record: `class` filters on the **human** label (the only reading
that makes sense), `model` and `min_confidence` on the captured prediction,
`from`/`to`/`proto`/`initiator_ip`/`responder_ip` on the flow record, and
`from`/`to` bound the flow's last-seen time because a review has no
classification timestamp. `disagreement` is **refused** with `reviewed`, rather
than silently ignored: a review record keeps the model's class, score and id, not
the ensemble's disagreement flag, so there is nothing to filter on.

Both paths share `finish()`, which is what guarantees a reviewed cut inherits
every existing promise: immutability, the content hash over the schema identity
plus the exact CSV bytes, deterministic row order by flow id, `parent_datasets`
lineage via `Derive`, and the zero-rows / one-class / `MinRows` refusals.

### Reviews are not capped, and that is a decision

Every other store here is bounded, because packets, flows and verdicts arrive at
wire speed. A review does not: it is created by a person clicking a button. A
busy operator might produce a few hundred a day — tens of kilobytes as one JSON
file per flow. Capping would silently discard the most expensive data in the
system, hand-labelled ground truth, to save nothing measurable. Reviews are
therefore retained until an operator removes the directory. This is stated
explicitly so it reads as a choice rather than an oversight; if a deployment ever
produces reviews at machine rate, that is a signal something is automating
labels, which is a different feature with different honesty requirements.

Persistence follows `internal/training`: one JSON file per reviewed flow under
`review.directory`, written atomically (temp file + rename), reloaded at start,
with a corrupt, unparsable or unknown-state file logged and skipped rather than
fatal (§21). An RWMutex fronts the memory index; records are replaced wholesale
so a reader holding a `Review` keeps a consistent snapshot.

### Events and audit

Each successful write publishes `events.ReviewUpdated` with
`{flow_id, state, human_label, predicted_class}` — the human label and the
prediction travelling together, as they do everywhere else — and appends one
`audit.LogSubject("ReviewUpdated", "local", "review", <flow id>, …)` line whose
detail carries both. `ReviewUpdated` was already a member of the frozen
`event-envelope-v1` enum, so nothing about the event schema changed. The bus
drops under backpressure by design, so the audit log remains the durable record
§21 asks for.

## Consequences

- **The §16 invariant cannot be violated by a code change that compiles.**
  Adding a prediction setter would mean adding exported surface to a type that
  deliberately has none, and adding a `Put` parameter breaks a test.
- **A curated dataset is now possible, and a model-labelled one is still
  honest.** The distinction is a field, a badge and a test, not a convention.
- **The queue is opinionated.** Margin ordering is a claim about what a reviewer
  should look at first. It is documented in the API response itself, so an
  operator can disagree and switch to `recent`.
- **A verdict can age out of reviewability.** With the in-memory ring, a flow
  older than the newest 50 000 verdicts cannot be reviewed, and a review whose
  flow record has been evicted cannot become a dataset row — the manifest warns
  when that happens, and suggests a larger `storage.max_flows`. The SQLite
  backend removes both limits.
- **Review writes are unauthenticated.** Same posture as the dataset, replay,
  capture and model-activation routes: loopback by default is the only control,
  marked `TODO(#58)`. A review is an assertion about ground truth, so it wants
  attribution more than most routes do; `reviewer` is already a field, fixed at
  `"local"` until #58 fills it in.
- **`internal/dataset` now imports `internal/review`.** One more edge in the
  layering, in the direction that already existed (dataset reads stores; nothing
  reads dataset).
