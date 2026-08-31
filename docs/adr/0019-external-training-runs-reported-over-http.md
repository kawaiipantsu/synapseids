# 0019 — External training runs, reported to the daemon over HTTP

**Status:** Accepted, 2026-08-31

## Context

PROJECT.md §19.8 specifies a live training view: status, epoch, batches,
training/validation loss, accuracy, precision, recall, F1, per-class metrics,
confusion matrix, learning rate, elapsed time, and CPU/GPU usage when available,
"updating live". Issue #35 (EPIC Phase 4) is the work item.

Two hard constraints frame the design.

**The Go daemon does not run Python.** CLAUDE.md and PROJECT.md §5.4 are explicit:
"The Go daemon must not depend on Python for normal inference", and more broadly
the daemon must not need a Python toolchain to function. `synapse-trainer` is a
separate process with heavy, optional dependencies (`torch`, `onnx`,
`onnxruntime`) that are not even installed in the normal dev/build environment
(ADR 0007). So the daemon cannot *launch* a training run, cannot import the
trainer, and cannot poll a Python process's memory. Whatever the dashboard shows
has to arrive from the outside.

**`event-envelope-v1` is frozen.** §28.5-6 forbid re-meaning or extending a
released schema. The envelope's `event_types` enum has members for the flow and
model lifecycles (`ClassificationCreated`, `ModelActivated`, `AlertCreated`,
`ReviewUpdated`, …) but nothing for training. Adding `TrainingStarted` /
`TrainingEpoch` / `TrainingCompleted` to that enum is an `event-envelope-v2`
decision, exactly as ADR 0015 concluded for `Dataset*`. It is out of scope here.

## Decision

### The daemon mirrors; it does not orchestrate

`synapse-trainer` owns the run. It **registers** the run with a running
`synapsed` over HTTP, then **POSTs one progress dict per epoch** and a terminal
`{"event": "done"}` dict; on an exception it POSTs `/fail`. The daemon keeps the
latest state plus a bounded history and serves it back. It never starts, stops,
schedules, or resumes a run, and it has no opinion about where the trainer runs
or what hardware it uses.

This keeps the Python dependency entirely on the trainer side and makes the
feature degrade gracefully: no trainer ever connects → the dashboard shows "no
runs" and nothing is broken.

### Live updates are a poll, not a push

The SPA polls `GET /api/v1/training/{id}` every ~1.5 s while the selected run is
`running`, and stops once it is terminal. A training epoch is seconds to minutes;
a 1–2 s poll is visually indistinguishable from a push and it keeps the
frozen-schema question closed — no new envelope type, no bus plumbing, no
WebSocket message the clients must learn.

A real push channel for training would be `event-envelope-v2` and is deliberately
not built now. If it ever is, the run store below is already the state it would
publish from; the poll endpoint stays regardless, because it is also how a
freshly opened tab loads history.

### The run store: one JSON file per run

`internal/training` follows the `registry.Open` / `dataset.Open` precedent:

```text
<training.directory>/<run id>.json
```

`training.directory` defaults to `./data/training`, overridable with
`SYNAPSE_TRAINING_DIR`. `training.Open` loads every `*.json` it can parse at
startup; a missing directory starts empty and a corrupt or unreadable file is
logged and skipped, never fatal (§21). Each file is rewritten atomically
(temp-file + `rename`) on every update. An RWMutex-guarded memory index fronts
the files — the trainer POSTs progress while the SPA polls.

**No `training.json` index.** Same reasoning as ADR 0015: a run's file is
self-contained, `ls` and `cat` tell the whole story, and a second index could
only ever disagree with the per-run files. The set of runs is bounded by
operator action.

A run id is `<UTC compact timestamp>-<8 hex random>`, e.g.
`20260831T123737Z-75549ac4` — sortable, filesystem-safe, collision-resistant,
and never taken from request input.

#### `Run` fields

`id`, `name`, `status` (`running` | `completed` | `failed` | `stale`),
`recipe` (the resolved recipe + mixture summary, **raw JSON pass-through**),
`started_at`, `updated_at`, `finished_at`, `trainer_version`, `epochs_total`,
`epoch` (current), `history`, `final`, `fail_reason`.

`recipe` and `final` are `json.RawMessage`: whatever the trainer sends is stored
and served verbatim. This is what lets the trainer add a field §19.8 gains
without a daemon change — the daemon is a mirror, and the SPA reads the keys it
knows.

#### `history` is capped at 1000 epochs

The newest 1000 per-epoch dicts are kept; older ones are dropped oldest-first, in
memory and on disk. A longer run still reports the correct current epoch and
latest metrics, and its `final` block is untouched — only the earliest tail of
the loss curve is truncated. At a few hundred bytes per dict this bounds a run
file under a megabyte. The cap is a documented constant (`training.HistoryCap`),
surfaced on `GET /api/v1/training` as `history_cap`.

#### `stale` is a read-time view

A `running` run whose last update is older than `training.StaleAfter`
(**15 minutes**) reads back as `stale` from `Get` and `List` — the trainer
process has most likely died. This is computed on read and **never written to
disk**: the file still says `running`, and the next progress POST (or a terminal
update) clears the stale view. `GET /api/v1/training` reports the threshold as
`stale_after_seconds`.

### REST surface

```text
GET  /api/v1/training                  list runs, newest first, ?limit (max 500)
POST /api/v1/training                  register: {name, recipe, epochs_total, trainer_version}
                                       → 201 {id, progress_url}
GET  /api/v1/training/{id}             one run: full history + final  ← the SPA polls this
POST /api/v1/training/{id}/progress    one JSON object per request → 202
                                       {"event":"done", "metrics":{…}} finishes the run
POST /api/v1/training/{id}/fail        {reason} → 202
```

Status codes on the write routes: `400` bad body, `404` unknown id, `409` the run
has already finished, `503` no training store wired. `progress_url` in the
register response is `scheme://host/api/v1/training/{id}/progress`, reconstructed
from the request (honouring `X-Forwarded-Proto`) — a convenience; the trainer
already knows the daemon base URL because it was given `--report-to`.

**One JSON object per request** (not a JSON-lines stream). A single trailing
newline is tolerated, so the trainer's existing JSON-line writer works unchanged.
The `done` dict's `metrics` object is stored as the run's `final` block; if a
`done` dict arrives without a `metrics` wrapper the whole dict is stored so
nothing is lost.

### Unauthenticated, loopback-only, for now

The three POST routes have no auth. They rely on the daemon binding to loopback
by default — the same posture as `POST /api/v1/datasets`, `POST /api/v1/captures`
and the model activate/deactivate routes. A trainer on another host would need a
bearer token or mTLS; that is issue #58 (RBAC), and every write route carries a
`TODO(#58)`.

### Audit, but no bus event

`TrainingStarted` / `TrainingCompleted` / `TrainingFailed` are written to the
existing append-only audit log (§21, §28.15) under a new subject type
`training`, alongside `model` and `dataset`. `internal/audit` already took a
subject type after issue #33, so this is one more constant, not a parallel log.

There is deliberately **no bus event**. `AlertCreated`, `ReviewUpdated`,
`ModelActivated` and friends *are* members of the frozen `event-envelope-v1`
enum and are published; `Training*` is not a member and the enum is frozen, so
publishing one is impossible without `event-envelope-v2`. For training runs the
audit log is the durable record and the poll endpoint is the live view.

### Trainer side

`synapse_trainer/progress.py` `ProgressReporter` is a stdlib-only
(`urllib.request`) client: `start()` registers and learns the progress URL,
`handle()` POSTs an epoch or `done` dict, `fail()` POSTs `/fail`. **Every network
call is best-effort** — wrapped in `try/except`, logged through the caller's
sink, and swallowed. A dashboard outage must never lose a model, so a failed
POST is a dropped dashboard frame, nothing more. Passing no URL makes every
method a no-op.

`synapse-trainer train` gains `--report-to <daemon-url>` (default
`$SYNAPSE_DAEMON_URL`). Without it the reporter is disabled and training behaves
exactly as before. The low-level `--progress-url` flag is unchanged.

`train_iter`'s per-epoch yield is extended — still JSON, still numpy/stdlib where
the value is torch-free — with `batches`/`batches_total`, `accuracy`, macro
`precision`/`recall`, `device` (`cpu`/`cuda`) and `status`. The `done` metrics
already carry the per-class precision/recall/F1 table, the confusion matrix and
the held-out `test` block (from `classification_metrics` / `confusion_and_prf`),
so §19.8's richer fields ride the terminal dict rather than every epoch.

## Consequences

**Good.** The Python dependency stays entirely on the trainer side; the daemon
needs no toolchain and no running trainer to serve the view. No frozen schema was
touched. The run store is inspectable with `ls`/`cat` and copyable with `scp`.
The reporter cannot take down a training run. The on-disk layout is the shape a
future SQLite migration (issue #53) wants: manifests become rows, nothing else
changes.

**Costs, accepted.** A ~1.5 s poll is not a true push — fine for a metric that
changes per epoch, and revisitable as `event-envelope-v2` if a sub-second
training feed is ever wanted. `stale` is heuristic: a genuinely slow epoch (a
huge model on a slow box) past 15 minutes shows `stale` until the next update
lands, then flips back. The write routes are loopback-only, so a trainer on a GPU
box elsewhere can't report until issue #58 adds auth — until then it runs on the
same host as the daemon, or over an SSH tunnel. `history` truncation past 1000
epochs loses the early loss-curve tail (not the metrics, not the final report);
runs that long are rare and the fix is a larger cap, not unbounded growth.
