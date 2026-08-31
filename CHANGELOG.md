# Changelog

All notable changes to SynapseIDS are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Live training dashboard** (issue #35, EPIC Phase 4;
  [ADR 0019](docs/adr/0019-external-training-runs-reported-over-http.md)). The
  daemon now mirrors external `synapse-trainer` runs and the SPA renders them
  live (PROJECT.md §19.8). The Go daemon never launches Python (§5.4): the
  trainer runs elsewhere and reports progress over HTTP; the daemon is a mirror
  and a history store, not an orchestrator. No `event-envelope-v1` change — the
  enum is frozen and has no `Training*` member (§28.5-6), so the dashboard
  updates by polling a training-job resource, not the event bus.
  - `internal/training` — the run store. One JSON file per run under
    `training.directory` (atomic temp-file+rename, corrupt-file tolerant, loaded
    on start) plus an RWMutex-guarded memory index. A `Run` records `id`, `name`,
    `status` (`running` | `completed` | `failed` | `stale`), the pass-through
    `recipe`/`final` blocks, timestamps, `trainer_version`, `epochs_total`,
    current `epoch`, and a `history` slice of per-epoch progress dicts capped at
    **1000** (oldest dropped). A `running` run with no update for **15 minutes**
    reads back as `stale` — a read-time view, never persisted; a later update
    clears it.
  - REST `internal/api/training.go`: `POST /api/v1/training` (register → `201`
    `{id, progress_url}`), `POST /api/v1/training/{id}/progress` (one JSON object
    per request → `202`; an `{"event":"done"}` dict finishes the run and stores
    its `metrics` as `final`), `POST /api/v1/training/{id}/fail` (`{reason}` →
    `202`), `GET /api/v1/training` (list, newest first, `limit`), and
    `GET /api/v1/training/{id}` (one run with full `history` + `final` — what the
    SPA polls). The three POST routes are unauthenticated and loopback-only for
    now (`TODO(#58)`). `TrainingStarted` / `TrainingCompleted` / `TrainingFailed`
    are written to the audit log under subject type `training`; nothing is
    published on the event bus.
  - `config.Training{Directory}` — `./data/training` by default, overridable
    with `SYNAPSE_TRAINING_DIR`.
  - Trainer: `synapse_trainer/progress.py` `ProgressReporter` is a real
    stdlib-only (`urllib.request`) client — it registers the run, POSTs each
    epoch dict and the `done` dict, and POSTs `/fail` on an exception. Every
    network operation is best-effort: a dashboard outage is logged and swallowed,
    never fatal to the run. `synapse-trainer train` gains `--report-to
    <daemon-url>` (defaulting to `$SYNAPSE_DAEMON_URL`); without it, training runs
    exactly as before with no reporting. `train_iter`'s per-epoch dict now also
    carries `batches`/`batches_total`, macro `precision`/`recall`, `accuracy`
    and `device` (cpu/cuda); the `done` metrics already carry the per-class
    table, confusion matrix and held-out `test` block.
  - SPA `ML ▸ Training` (`#/training`, previously a Phase-4 placeholder): a run
    list with status pills, and for the selected run — status, epoch N/total,
    elapsed, CPU/GPU (or "not reported"), train/val-loss curves, an accuracy/F1
    curve, a learning-rate curve, accuracy/precision/recall/F1 cards, and on
    completion the per-class metrics table and a 7×7 `traffic-classes-v1`
    confusion-matrix grid. Polls `GET /api/v1/training/{id}` every ~1.5 s while a
    run is `running`, then stops.

- **Training recipes with multi-dataset weighting** (issue #34, EPIC Phase 4;
  [ADR 0017](docs/adr/0017-multi-dataset-training-mixtures.md)). A recipe's
  `datasets[]` weights now actually shape the training data (PROJECT.md §14:
  "70% Copenhagen baseline / 20% attack corpus / 10% reviewed detections") —
  previously they were validated and then ignored, and `train` loaded a single
  CSV.
  - `synapse_trainer/mixture.py` — resolves every `datasets[]` entry under
    `--data ROOT` in a documented order: the entry's explicit `path` →
    `ROOT/<id>.csv` → `ROOT/<id>/dataset.csv` → `ROOT/<id>/<latest version
    dir>/dataset.csv` (numeric-aware, so `v10` beats `v9`) → any single
    `ROOT/<id>/*.csv`. Nothing found is a hard error listing every path tried;
    an id may be namespaced but never absolute and never contains `..`. A
    `manifest.json` beside the CSV (or `ROOT/<id>.manifest.json`) supplies the
    §14 metadata — its `content_hash` is recorded with the model.
  - **Schema-compatibility gate.** Every dataset must carry all 48
    `flow-features-v1` columns and agree with the others (and with any manifest)
    on `feature_schema` / `output_schema`. A mismatch is a named
    `DatasetIncompatible` / `MixtureError`; columns are never dropped, reordered
    or coerced (§5.4, §8, §28.5-6).
  - **Weighting = resampling the training mixture.** `target_n = Σ len(train_i)`;
    per-dataset quotas by largest-remainder apportionment (so they sum to
    `target_n` exactly); down-sample without replacement, or up-sample by taking
    every row once and drawing the remainder with replacement; one deterministic
    shuffle. Every draw is seeded by `sha256(recipe.seed, purpose, dataset id)`,
    so the mixture is reproducible from the recipe alone and adding a dataset
    does not reshuffle the others (§28.8).
  - **Split before mix — no test leakage.** Each dataset is split *first*, on its
    own; only the train portions are weighted and mixed, so an up-sampled
    duplicate can never straddle the train/test boundary (§14). Val and test are
    plain unions and are never resampled. Asserted by
    `test_no_leak_under_aggressive_upsampling` (pairwise-disjoint row-id sets
    under ~10× up-sampling) plus `test_naive_mix_then_split_would_leak`, which
    shows the naive order does leak.
  - `training-recipe.json` now records `split_result` (seed, fractions, sizes,
    stratified, per-split label counts, per-dataset detail) and a new `mixture`
    block: strategy name, seed, `split_before_mix`, `target_train_rows`, sizes,
    label counts, warnings, and per dataset the requested + effective weight,
    resolved path and rule, `content_hash`, source rows, split sizes, split and
    sample seeds, realised train rows and up/down-sampling counts (§14, §28.9).
    `metadata.json` is unchanged in shape — only `training_dataset_ids` content,
    which now lists **every** contributing dataset.
  - `synapse-trainer inspect-recipe --recipe R --data ROOT [--json]` and
    `train --dry-run` — resolve, split and weight the whole mixture and print the
    plan (per-dataset rows, effective weights, split sizes, label distribution,
    warnings) **without torch**, so an operator can validate a recipe before
    burning a run.
  - **Quality warnings** (§19.10): a dominant class (>90% of the mixture), a
    class absent from the mixture, a class under 10 training rows, a dataset
    contributing zero rows after weighting, heavy (≥3×) up-sampling, and an empty
    val/test split.
  - `trainer/examples/recipe.multi-dataset.json` + a `trainer/examples/data/`
    fixture tree exercising all three on-disk layouts.
- **FreeBSD BPF capture + the OPNsense WAN sensor plugin** (issue #98, EPIC
  Phase 6; [ADR 0014](docs/adr/0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md),
  [docs/opnsense-sensor.md](docs/opnsense-sensor.md)).
  **None of this has been run on FreeBSD or OPNsense — see the caveat at the
  end of this entry.**
  - `capture.BPFDevice` — a live capture source backed by FreeBSD `/dev/bpf`,
    stdlib-only (no `golang.org/x/sys`). Opens the cloning `/dev/bpf` or probes
    `/dev/bpfN`; `BIOCSBLEN`, `BIOCSETF`, `BIOCSETIF`, `BIOCPROMISC`,
    `BIOCIMMEDIATE`, `BIOCSRTIMEOUT`, `BIOCSDIRECTION`, `BIOCGDLT`,
    `BIOCFLUSH`; `Stats.Drops` from `BIOCGSTATS` `bs_drop`. `BPFConfig` adds
    `Device`, `Direction` (`in`/`out`/`inout` — `in` is what a WAN sensor
    wants) and `BufferLen` on top of the AF_PACKET options. The device is
    opened read-only, so it cannot transmit even in principle (§28.17), and an
    `EACCES` prints the exact `devfs.rules` fix instead of demanding root
    (§21).
  - The ioctl request numbers are **derived by hand** from the FreeBSD
    `sys/ioccom.h` encoding (`bpfioctl.go`, with the derivation written out),
    checked two ways: a Linux-runnable table test against the twelve published
    values, and paired compile-time constant assertions against `syscall.BIOC*`
    on `freebsd/{amd64,arm64}` — so `GOOS=freebsd go build` cannot succeed with
    a wrong number.
  - `parseBPFChunk` (`bpfchunk.go`, **no build tag**) splits one `read(2)` into
    its many `bpf_hdr`-prefixed, `BPF_WORDALIGN`-padded records. `bh_hdrlen` is
    read per record rather than assumed. Malformed input — short header,
    over-ceiling `bh_caplen`, a record past the end of the chunk, a corrupt
    sub-second field — is counted and the good records from the same chunk are
    still delivered; never a panic (§28.11). Table tests, a fuzz target and a
    random-mutation loop all run on Linux.
  - `capture.NewLive(LiveConfig)` — one platform-neutral entry point for live
    NIC capture (AF_PACKET on Linux, `/dev/bpf` on FreeBSD, a clear error
    elsewhere). Options a platform cannot honour are rejected, not ignored.
    Both sources gained `RawPackets()` for undecoded frames; the decoded path
    keeps its zero-copy decode.
  - `synapse-sensor pcap-over-ip --iface <nic>` streams a **live NIC** instead
    of a capture file, with `--promisc`, `--filter`, `--direction`, `--snaplen`
    and `--bpf-device`. Live capture requires `--authorized` (§28.18). Sensor
    keepalives now carry the real kernel drop counter
    (`pcapoverip.ServerConfig.Drops`).
  - `synapse-sensor pcap-over-ip --connect <daemon>` — the sensor **dials out**,
    so a firewall behind NAT needs no inbound hole, with capped exponential
    backoff and jitter. **The SYNPOIP roles do not invert with the transport:**
    the accepting daemon still sends the ClientHello and the sensor still
    answers and streams frames, so there is no wire change, no version bump and
    no role byte (`pcapoverip.ServeConn`, PROTOCOL.md §6).
    **`synapsed` has no collector endpoint yet**, so `--connect` has nothing to
    dial; it is exercised end to end against a test collector, and the
    daemon-side listener is a tracked follow-up.
  - Build matrix: `make build-freebsd` and `make opnsense-pkg` for
    `freebsd/{amd64,arm64}`. **The four Linux targets are untouched** (§28.16).
    `scripts/package-opnsense.sh` builds a real FreeBSD `.pkg` (a `.txz` with
    `+MANIFEST` / `+COMPACT_MANIFEST` and an absolute-path payload) directly
    with `tar`/`xz`/`jq`, one per ABI, and self-verifies member order, manifest
    keys, every per-file checksum against the archived bytes, modes and
    ownership. `make dist` and the release workflow publish them.
  - `contrib/opnsense/` — the plugin: an OPNsense MVC model, ACL, menu entry
    under **Services → SynapseIDS Sensor**, settings and service API
    controllers, a Volt page, configd actions, templates and an `rc.d` script,
    plus a FreeBSD port `Makefile`/`pkg-descr`/`pkg-plist`. The build fails if
    the staged tree and `pkg-plist` drift apart.
  - `contrib/opnsense/install.sh` — a POSIX-sh installer for the firewall.
    Refuses to run off OPNsense or as non-root (it never calls `sudo`), picks
    the package from `pkg config abi`, and **verifies the SHA256 before
    installing**. `--version`, `--url`, `--grant-bpf`, `--dry-run`,
    `--uninstall`, `--help`. It never asks for, transmits or logs the bearer
    token.
  - Least privilege: the sensor runs as the dedicated unprivileged
    `_synapseids` user in group `net`, never root, with the BPF device opened
    read-only. The token lives in the OPNsense config store and in
    `sensor.token` (`0400 _synapseids:_synapseids`), is passed with
    `--token-file` so it never enters `ps(1)`, and appears in no log line and in
    no world-readable file — `sensor.conf` is `0640 root:wheel` and carries
    flags only (§23). A `fixperms` configd action clamps the modes after every
    template render. The `authorized` assertion is enforced by the model *and*
    the CLI (§28.18). The devfs rule that grants BPF access is opt-in, not
    something `pkg add` does to your firewall behind your back. **Known gap:**
    the TLS PEM files are named by the config but not yet rendered from it, so
    an operator places them by hand; `rc.d` refuses to start when a referenced
    PEM is missing rather than silently downgrading the transport.
  - **Unverified surface.** This was written and tested on Linux. The BPF
    source is compile-verified only (the ioctl numbers are machine-checked, the
    runtime behaviour is not); the package has never been through `pkg add`;
    the plugin has never been loaded by an OPNsense MVC runtime; no real WAN
    traffic has been captured. `docs/opnsense-sensor.md` lists the exact
    commands a maintainer must run on real hardware.
- **Host profiles, Investigation mode and the classification timeline**
  (issues #39, #40, #41, EPIC Phase 5;
  [ADR 0016](docs/adr/0016-host-and-time-aggregation-for-investigation.md)).
  One backend serves all three: `internal/insight`, a bounded read model that the
  pipeline feeds with a single non-blocking send per flow record.
  - **`internal/insight`** — incrementally maintained observed-host profiles
    (§19.5) and fixed-width classification-timeline rings (§19.6). Fed through a
    new nil-safe `pipeline.Options.Observer` hook, so aggregation stays off the
    packet path: `Observe` costs **88 ns with zero allocations** and takes no
    lock, a single aggregator goroutine owns every map, and a bounded ingest
    queue drops-and-counts rather than stalling ingestion (§22). A test asserts
    the zero-allocation property so a regression fails the build.
  - **Everything is capped and every discard is counted**, and the counters are
    on `GET /api/v1/status` under `insight`: 2048 hosts (least-recently-active
    quarter evicted in batches → `hosts_evicted`), 128 distinct ports and peers
    per host (lowest-count half discarded → `keys_pruned`), 16 recent-flow
    references per host, 900×1s / 720×10s / 1440×1m timeline buckets
    (→ `timeline_late`), an 8192-deep ingest queue (→ `dropped`). Host maps are
    keyed by packet-derived, untrusted strings, so this is a §21 requirement, not
    tidiness.
  - `GET /api/v1/hosts` — host profiles, newest-active first. `limit` (default
    100, cap 2000), `q=` substring filter, `sort=last_seen|flows|bytes`
    (`400 bad sort` otherwise).
  - `GET /api/v1/hosts/{ip}` — one profile with its detail lists (up to 16 top
    ports, 16 top peers, 16 recent flow references). The path value is re-parsed
    with `net/netip` and canonicalised: a non-literal is `400`, an unobserved
    address `404`.
  - `GET /api/v1/hosts/{ip}/flows` and `.../classifications` — that host's
    records, honouring the **same** `class` / `model` / `min_confidence` /
    `disagreement` parameters as `GET /api/v1/classifications`, plus RFC3339
    `from` / `to`.
  - `GET /api/v1/timeline` — `{bucket_sec, buckets:[{ts, total, by_class{},
    disagreements}], anomaly_available}` with `bucket=1s|10s|1m`, `from` / `to`,
    `class` and `host`. The series is dense (a quiet interval is an explicit zero
    bucket). Unscoped queries come from the incremental ring; `class=` / `host=`
    scoped ones are bucketed on demand from the recent classification window,
    because a ring per host would be unbounded.
  - **SPA — three views.** `#/hosts` is a sortable, filterable host table (class
    mix as a stacked bar, click through to Investigate). `#/investigate?host=<ip>`
    pivots the whole page around one address: volume/packet tiles, first/last
    seen, disagreement count, top peers and service ports, class mix, protocols,
    a host-scoped timeline and filterable verdict + flow lists. `#/timeline` is
    the daemon-wide stacked timeline with a disagreement overlay. **Dragging a
    range on either chart filters the lists beneath it.** New `useHashQuery` /
    `navigateWith` router helpers carry `?host=` in the hash.
  - **Deliberately not built:** `#/detections` keeps its "Planned — Phase 5"
    placeholder — there is no detections store and nothing publishes
    `AlertCreated`, so half-building it would be worse than leaving it.
  - **Deliberately not faked:** behavioural baseline, anomaly trend and anomaly
    history (§19.4-6) are Phase 7. The API always reports
    `baseline_available: false` / `anomaly_available: false` and the SPA renders
    labelled stubs instead of an invented baseline or a fabricated zero line.
  - No event type was added — the `event-envelope-v1` enum stays frozen (§28.5-6);
    everything is derived from the records the pipeline already produces.
- **Dataset manager — versioned, immutable, content-hashed datasets** (issue #33,
  EPIC Phase 4; [ADR 0015](docs/adr/0015-versioned-datasets-on-disk.md)).
  An operator can now turn stored flow classifications into a labelled dataset
  the Python trainer consumes directly, and the `ML ▸ Datasets` view is live.
  - `internal/dataset` — a new package. A dataset version is a directory:
    `datasets.directory/<id>/<version>/{dataset.csv, manifest.json}`. An id may
    contain one `/` (PROJECT.md §14 writes `thugs/lab-attacks-2026-08`), so it is
    one or two path segments and the version is the last. The layout **is** the
    index — `Open` walks the tree and there is no second `registry.json`-style
    file that could drift from the manifests. A missing directory starts empty
    and a corrupt manifest is logged and skipped, never fatal (§21). Both files
    are staged in a temp directory and `rename`d into place together, so a reader
    never sees a half-written version.
  - `manifest.json` carries **every §14 field**: `id`, `name`, `description`,
    `location`, `tags[]`, `created_at` (RFC3339 UTC), `source_capture_ids[]`,
    `time_range{from,to}`, `feature_schema`, `output_schema`, `flow_count`,
    `label_counts{}`, `labeling_source`, `parent_datasets[]` and `content_hash`,
    plus the selection that produced it, any warnings, and the column list.
  - **The CSV is the trainer contract, verbatim.** The header is the 48
    `flow-features-v1` names in frozen schema order then `label`; one row per
    flow, sorted by flow id; values are Go's shortest round-tripping float form.
    `trainer/synapse_trainer/dataset.py` `load_csv` reads it with no adaptation,
    and because `load_csv` accepts a directory containing `dataset.csv`, a
    version directory can be handed to the trainer as-is. A round-trip test
    asserts the header and row shape from Go always, and additionally runs the
    real `load_csv` when `python3` + `numpy` are importable (it says so out loud
    rather than skipping silently when they are not).
  - **Content hash** — `sha256` over a domain separator, both schema names and
    the exact `dataset.csv` bytes, recorded as `sha256:<lowercase hex>`. It
    therefore covers the rows, the labels and the column identity and *nothing
    else*: two datasets built from the same rows and labels hash identically
    regardless of id, version, name, tags or creation time. A test builds the
    same store twice into two roots under two names and asserts the hashes match.
  - **Immutability.** A written version is never modified. `Create` refuses an
    existing `(id, version)` — including a directory on disk whose manifest
    failed to parse, so unreadable operator data can never be clobbered. A
    correction is a **new version** naming its predecessor in `parent_datasets`;
    an omitted version auto-assigns `v<max+1>`. `Derive` records the parent and
    inherits its whole ancestor chain. `Delete` is allowed and audited —
    immutability protects a version's contents, not its existence.
  - **Ids are validated, not sanitised.** One or two `/`-separated lowercase slug
    segments of `[a-z0-9._-]`, each 1–64 chars, each starting and ending with a
    letter or digit. Path traversal is impossible **by construction**: `..`
    cannot form because a segment may not start with `.`, and no other character
    survives. `Delete` re-derives its path from the validated id rather than
    trusting the manifest's `dir`.
  - **A useless selection is an error, not a file.** Zero rows, exactly one
    class, or fewer than 20 rows are each refused with a message saying which and
    why. Datasets that *are* built carry warnings for class imbalance above 90 %,
    classes with no rows, exact duplicate rows, verdicts whose flow record had
    already been evicted from the bounded ring, and non-finite feature values
    replaced by the schema's `default_missing` (§14, §19.10).
  - **`labeling_source` is honest and cannot be made to lie.** Phase 4 has no
    human review loop (issue #42), so every dataset built today is labelled by
    the daemon's **own model predictions** and records
    `model_prediction:<sorted model ids>`. There is no override field, and no
    code path in `internal/dataset` can write `human_review`. The SPA states this
    in a banner and renders the value as a caution badge on every row.
  - `GET /api/v1/datasets` — every manifest, newest first, plus the column list,
    the label column name and the row floor. Always `200`, empty array when
    nothing is cut.
  - `POST /api/v1/datasets` — body is the §14 metadata plus a selection (unknown
    fields rejected, 64 KiB cap). `201` with the manifest; `400` bad body / id /
    version / filter / timestamp; `404` unknown `derive_from`; `409` duplicate
    `(id, version)`; `422` an unusable selection; `503` no manager wired. The
    selection reuses the `GET /api/v1/classifications` vocabulary — `class`,
    `model`, `min_confidence` (a value `> 1` read as a 0..100 percentage, as the
    flow log's slider sends it) and `disagreement` mean exactly the same thing —
    plus `from`, `to`, `proto`, `initiator_ip`, `responder_ip`, `limit`, `scan`.
  - `GET /api/v1/datasets/{ref}` · `DELETE /api/v1/datasets/{ref}` ·
    `GET /api/v1/datasets/{ref}/download` (streams `text/csv` with
    `Content-Disposition` and the content hash in `X-Synapse-Dataset-Hash`).
    `{ref}` is a **url-escaped `<id>@<version>`**: an id containing `/` would
    otherwise make `{id}/{version}` ambiguous. `net/http`'s `ServeMux` matches
    wildcards against the escaped path, so `%2F` stays in one segment and arrives
    intact (verified by test). A reverse proxy that normalises `%2F` breaks this;
    documented in `docs/api.md`.
  - **`POST` and `DELETE` are state-changing and unauthenticated**, inheriting
    the repo's loopback-by-default posture (§21) and carrying
    `TODO(#58): gate behind auth/RBAC`, like replay, captures and model
    activation.
  - `internal/audit` — `Record` gains a generic `subject_type` + `subject` pair
    and a `LogSubject` entry point, so one append-only log carries model *and*
    dataset lifecycle (§21, §28.15). `Log(event, actor, modelID, detail)` is
    unchanged for existing callers and still writes `model_id`, so anything
    reading the log by `model_id` keeps working. New events:
    `DatasetCreated` / `DatasetDerived` / `DatasetDeleted`. There is deliberately
    **no bus event** — `event-envelope-v1`'s type enum is frozen and has no
    `Dataset*` member, so adding one is an `event-envelope-v2` decision (§28.5).
  - `config` — new `datasets.directory` (default `./data/datasets`) with a
    `SYNAPSE_DATASETS_DIR` override; an empty value is rejected by `validate()`.
  - **SPA `ML ▸ Datasets`** replaces the Phase-4 placeholder: the version list
    with flow counts, a stacked label-distribution bar, the labeling source, age,
    short content hash, parents and CSV size; per-row download, derive-prefill
    and delete; a create form driven by the same selection filters; per-dataset
    build warnings inline; and a banner stating plainly that these labels are
    model predictions, not ground truth. The Dataset **Explorer** (§19.11 —
    feature distributions, correlations, PCA) is issue #37 and is not built here.


- **Capture-source UI + runtime source management** (issue #32, EPIC Phase 3 —
  **this closes EPIC #3**; [ADR 0013](docs/adr/0013-runtime-capture-source-management.md)).
  Capture sources can now be started and stopped without restarting the daemon,
  and the `CAPTURE ▸ Sources` view is live.
  - `POST /api/v1/captures` — the body is one `capture.sources[]` entry (a
    `config.CaptureSource` JSON object, unknown fields rejected, 64 KiB cap).
    Validated by the **same** rules the config file gets, built by the **same**
    builder the startup loop uses, then handed to `capture.Manager`. `201` with
    the new `SourceStatus`; `400` bad body / failed per-kind validation / an
    inline `token` (the config error text verbatim); `409` duplicate name; `422`
    a local source (`nic`, `tcpdump`) that could not be opened; `502` a remote
    one (`ssh`, `pcap-over-ip`); `503` no capture manager. A source that fails to
    open is never registered and never crashes the daemon (§21).
  - `DELETE /api/v1/captures/{name}` — cancels, closes and joins the source
    (raw socket closed / subprocess killed / SSH or TLS session ended), drops the
    row, `200 {"removed": …}` or `404`. Config-loaded and API-added sources are
    both removable; both operations are logged and published as
    `CaptureSourceConnected` / `CaptureSourceDisconnected` with `"origin":"api"`.
  - **Both routes are powerful and unauthenticated.** They inherit the repo's
    loopback-by-default posture (§21) and carry `TODO(#58): gate behind
    auth/RBAC`; `authorized: true` is an operator assertion (§28.18), not access
    control.
  - `config.ValidateCaptureSource(cs)` — the per-source capture rules (required
    fields per kind, the `known_hosts` enum, the pcap-over-ip TLS/token posture
    and the §28.18 `authorized:true` gate) are now **one exported function**
    called by both `config.validate()` and the REST handler, so the file path and
    the runtime path cannot drift. A test asserts the two agree across all four
    kinds.
  - `internal/capturewire` — a new, small package holding the shared source
    builder (`Build`, `Meta`, `ResolvePOIPToken`), moved out of `cmd/synapsed`.
    `internal/api` cannot import a `package main`, and `internal/capture` is a
    data-plane leaf that must not import `config`, so the builder lives above
    both and is imported by `cmd/synapsed` and `internal/api` only — the import
    graph stays a DAG.
  - `capture.Manager` — dynamic fan-in is pinned by tests: `Add` after
    `Packets()` launches the forwarder against the live merged channel without
    disturbing existing sources or the single pipeline goroutine (§22), and
    `Remove` now joins that forwarder (each closes a `done` channel on exit)
    before returning, so a `DELETE` leaves no goroutine behind. Both `-race`
    clean. `SourceMeta`/`SourceStatus` gain `origin` (`config` | `api`), also
    exposed on `GET /api/v1/captures`.
  - `cmd/synapsed` always wires the Manager into the API and always runs the
    live-capture pipeline goroutine, even with zero configured sources —
    otherwise a runtime-added source would have no consumer.
  - **SPA `CAPTURE ▸ Sources`** (PROJECT.md §19.14) replaces the Phase-3
    placeholder: a 1 Hz table of every source with colour-coded state, packets,
    bytes, pps, bps, drops, decode errors, last packet (relative + absolute on
    hover), current filter, connection latency (`n/a` off `pcap-over-ip`), a
    `from config` / `runtime` badge, and the error string in a prominent row when
    a source is in `error`. The add form reveals only the fields for the selected
    kind, offers `token_file` and **never** an inline token, persists its draft to
    `localStorage`, and requires an explicit "I am authorised to monitor this
    target" checkbox — mirroring the server rule for `ssh` and for non-loopback /
    insecure / token-less `pcap-over-ip` — before submit is enabled. Removal asks
    for confirmation. Server rejections are shown verbatim.

- **PCAP-over-IP transport** (issue #31, EPIC Phase 3;
  [ADR 0012](docs/adr/0012-pcap-over-ip-transport.md),
  [PROTOCOL.md](internal/capture/pcapoverip/PROTOCOL.md)). A framed,
  authenticated, versioned capture transport over one TLS connection.
  - `internal/capture/pcapoverip` — the **SYNPOIP** wire protocol: a
    `magic + version + link-type + bearer-token + JSON-metadata` handshake, a
    typed accept/reject (`unsupported-version`, `unauthorized`, `bad-request`,
    `unavailable`, `link-type-unsupported`), and record frames
    (`0x01` packet = `uint64` unix-nanos + raw frame, `0x02` keepalive with an
    optional packet/drop counter, `0x03` goodbye). All big-endian, every length
    capped (token ≤ 512 B, metadata ≤ 64 KiB, **frame payload ≤ 262208 B**) and
    checked before the read (§21, §28.11). Server MAY accept a lower version;
    a higher-than-known version is rejected.
  - `capture.PCAPOverIP` — the client `Source`. `NewPCAPOverIP(POIPConfig)`
    builds the TLS client (1.2 min, `ca_file` or system roots, optional mutual
    TLS) but does not dial; `Packets(ctx)` dials, handshakes, then streams
    `packet.Decode`d packets. No auto-reconnect: a dial/auth/TLS/protocol/idle
    failure is one terminal error and the capture-sources row goes to `error`.
    `Close()` / ctx-cancel sends a goodbye and leaves no goroutine or fd behind.
    Surfaces the real TLS dial time as `connection_latency_ms` and the
    sensor-advertised filter in the capture-sources view.
  - `synapse-sensor pcap-over-ip --listen … --from capture.pcap --token-file …`
    — a minimal reference server that replays a classic-pcap file over the wire
    (optional `--speed`, `--cert`/`--key`, `--client-ca` for mutual TLS; a
    self-signed cert is generated and fingerprinted when none is given).
    `synapse-sensor` with no subcommand still just prints its version.
  - Config: `capture.sources[].kind` accepts `"pcap-over-ip"` with `addr`,
    `token_file` (inline `token` is refused — §23), `server_name`, `ca_file`,
    `client_cert_file`/`client_key_file`, `insecure_tls`, `authorized`.
    `validate()` requires `authorized: true` for a non-loopback `addr`,
    `insecure_tls`, or a token-less connection (§21, §28.18). `nic` is
    unchanged.
- **tcpdump-stream and SSH remote-tcpdump capture sources** (issues #29 + #30,
  EPIC Phase 3; [ADR 0011](docs/adr/0011-subprocess-capture-tcpdump-and-ssh.md)).
  - The classic/pcapng stream decoder is extracted from `PCAPFile` into a
    shared `capture.decodePCAPStream` engine (`internal/capture/pcapstream.go`).
    `PCAPFile` behaviour is unchanged (golden / pipeline / capture tests pass
    untouched); a new table test asserts the engine matches `PCAPFile`
    packet-for-packet on every committed fixture.
  - `capture.TcpdumpStream` runs
    `tcpdump -U --immediate-mode -w - -i <iface> -s <snaplen> <filter…>` and
    decodes its stdout through that engine. `capture.SSHTcpdump` runs
    `ssh -o BatchMode=yes -o StrictHostKeyChecking=<strict|accept-new> <dest>
    tcpdump -U -w - -i <iface> -s <snaplen> <filter…>`, the remote command
    shell-quoted per field. Both share an unexported `pcapSubprocess`
    lifecycle: argv slice (never a shell string, §28.18), own process group,
    kill-on-cancel with reaping, bounded stderr ring surfaced as
    `"<tool>: exit <code>: <stderr>"`, no auto-restart.
  - **§28.18 authorization gate:** a `kind:"ssh"` source requires
    `"authorized": true` in the config — otherwise it is a config error
    (`remote capture requires "authorized": true — you must be authorised to
    monitor <destination>`). Enforced again in `NewSSHTcpdump`.
  - `config.CaptureSource` gains `kind` values `"tcpdump"` / `"ssh"` and the
    fields `binary`, `extra_args`, `destination`, `port`, `identity_file`,
    `remote_binary`, `known_hosts`, `extra_ssh_args`, `authorized`. `filter`
    is now per-kind: a `capture.BuiltinFilters` preset name for `nic`, a raw
    tcpdump filter expression for `tcpdump` / `ssh`. `synapsed` builds these
    sources at startup and `manager.Add`s them like a NIC source; one that
    cannot start is logged and skipped (API keeps serving). `GET
    /api/v1/captures` reports their `kind` and filter expression.
- **Architecture Builder** (issue #22, PROJECT.md §19.9). New `POST
  /api/v1/architecture/estimate`: given a `schema.Architecture` body it returns
  `{valid, error?, parameter_count, approx_bytes, rough_flops, layers[]}`. The
  input/output layers are forced to the locked 48 / 7 regardless of the request
  (§10). The parameter/size/FLOP math is a new shared `schema.Architecture`
  method set — `ParameterCount`, `ApproxBytes`, `RoughFLOPs`, `LayerBreakdown` —
  ported line-for-line from `trainer/synapse_trainer/architecture.py` so a UI
  estimate agrees with what the trainer reports. `schema.ValidateArchitecture`
  now also checks the hidden stack (width, activation, dropout range, residual
  width match), mirroring the trainer.
- The operator SPA's **ML ▸ Architecture** route is now wired (was a
  "Planned — Phase 4" placeholder): locked `INPUT 48` / `OUTPUT 7` blocks, an
  editable hidden-layer stack (add / delete / reorder, per-layer width /
  activation / dropout / batchnorm / residual with the residual toggle disabled
  and explained unless the previous width matches), a live estimates panel with
  a per-layer parameter breakdown, a non-blocking "obviously excessive" warning
  banner (any width > 2048, or total params > 50× the baseline net), and
  copy / download / paste of the `schema.Architecture` JSON. The working draft
  persists to `localStorage`.
- **Model registry with lineage + explicit activation** (issue #26, EPIC Phase 2;
  [ADR 0009](docs/adr/0009-model-registry-lineage-and-explicit-activation.md)).
  - `internal/registry` records one entry per validated bundle — the §11
    metadata plus `content_hash`, `artifact_bytes`, `derived_from`, `status`
    (`registered` / `active` / `deactivated`), `registered_at`, `activated_at`
    and the on-disk `dir` — in `registry.json` under `models.directory` (atomic
    rewrite, corrupt-file tolerant). Rejects a bundle that fails the gate, a
    content hash already registered under another id, or an id already registered
    with another hash. `Lineage` / `Children` / `Tree` walk `derived_from` for
    the §15 / §19.12 lineage view. At most one entry is `active`; a persisted
    `active` is reconciled to `deactivated` on restart (activation never
    auto-restores, PROJECT.md §28.10).
  - `synapsed` startup now `Register`s every bundle `model.Scan` returns and logs
    `POST /api/v1/models/{id}/activate to make it live` for `models.primary` —
    it still activates nothing.
  - `inference.Runtime` gains `Activate` / `Deactivate` / `SetModels`, swapping
    the live model set atomically under an `RWMutex` (`Score` never sees a
    half-swap). `Deactivate` restores the heuristic; while a trained model is
    active it is the sole classifier.
  - `internal/modelrun.Build` compiles a registered bundle into a live
    `inference.Classifier` (`nn.LoadFile` + `normalizer.json` bridge +
    `inference.NewONNXModel`).
  - New REST routes: `GET /api/v1/models` (now `{ "models": [...], "runtime":
    [...] }` — registry entries with per-entry `runtime {loaded, role}`, plus the
    classifiers actually loaded), `GET /api/v1/models/{id}` (entry + `lineage` +
    `children`), `GET /api/v1/models/{id}/lineage` (chain + children + forest),
    `POST /api/v1/models/{id}/activate` (404 unknown / 409 no longer
    loads·validates·compiles / 200 with the updated entry), `POST
    /api/v1/models/{id}/deactivate` (restores the heuristic). State-changing and
    unauthenticated for now — same posture as `POST /api/v1/replay`; RBAC is
    issue #58.
  - `internal/audit` appends `ModelRegistered` / `ModelActivated` /
    `ModelDeactivated` to `models.directory/audit.log` (JSONL:
    `{ts,event,actor,model_id,detail}`, `actor: "local"`). The same envelopes are
    also published on the live event bus (already members of the frozen
    `event-envelope-v1` enum — no new type added).
  - `model.Metadata` gains an additive optional `derived_from` field (absent =
    lineage root); the validation contract is unchanged.
- **Live local-interface capture (Phase 3, GitHub issue #28).** `synapsed
  --capture <iface>` (repeatable), or `capture.sources[]` in the JSON config, or
  `SYNAPSE_CAPTURE_IFACE`, opens an `AF_PACKET` raw socket on a NIC and runs its
  traffic through the same `packet → flow → features → inference` pipeline a PCAP
  replay uses. Stdlib-only (`syscall`), `CGO_ENABLED=0`, cross-builds to all four
  Linux arches; a full pcap-filter-expression compiler is deliberately out of
  scope (see below). Needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for promiscuous
  mode); on `EPERM` the error names the capability and never demands root
  (PROJECT.md §21). A source that cannot open is logged and skipped — the daemon
  keeps serving the API in a degraded mode. See
  [ADR 0010](docs/adr/0010-live-capture-af_packet-and-the-source-manager.md).
- `capture.Manager` runs N capture sources concurrently and merges their packets
  into one channel, so the single-goroutine flow `Table` downstream is still fed
  from exactly one place (PROJECT.md §22). A source that errors is isolated
  (`state: "error"`), leaving the others and the pipeline running. It computes
  rolling `pps`/`bps` per source off the packet path.
- `GET /api/v1/captures` and `GET /api/v1/captures/{name}` — per-source live
  status: `state`, `pps`, `bps`, `drops`, `last_packet`, `filter`, `error`, plus
  `name`/`kind` and a `connection_latency_ms` (0 for a local NIC) (PROJECT.md
  §19.14). Returns an empty array when no live capture is configured.
- `capture.Stats` gains a `Drops` field — kernel packet drops from the
  `AF_PACKET` `PACKET_STATISTICS` `tp_drops` counter (`PCAPFile` leaves it 0), so
  capture loss is measurable (PROJECT.md §22, §24).
- Config: `capture.sources` — an array of `{ name, kind: "nic", interface,
  promiscuous, snaplen, filter }`. `filter` is `""` (everything) or a built-in
  cBPF preset (`ip`, `ip6`, `ip-any`, `not-arp`); tcpdump-style filter
  expressions are a follow-up (#29+).

- `/api/v1/status` now carries a `flow` object — the live flow table's `active`,
  `started`, `closed`, `snapshots` and `evicted` counters plus the configured
  `max` (`capture.max_flows` / `SYNAPSE_MAX_FLOWS`) — so oldest-idle eviction
  pressure is observable without attaching to the packet path (PROJECT.md §22,
  §24). It is sourced from the running replay pipeline's flow table via a new
  `pipeline.Options.OnStats` hook that fires on the flow-table tick cadence,
  never per packet.
- The pipeline logs a throttled warning (the first eviction of a run, then every
  1000th) when the flow table is full and starts evicting, pointing at
  `capture.max_flows`.
- `internal/capture` now reads **minimal pcapng** as well as classic pcap
  (GitHub issue #73). The hand-rolled reader handles a single Section Header
  Block (either byte order), Interface Description Blocks (link type, snap
  length, `if_tsresol` timestamp resolution), Enhanced Packet Blocks and Simple
  Packet Blocks, for Ethernet or RAW link types. Every declared block length is
  bounded before allocation and the trailing length is verified. Multi-section
  files, mid-file endianness changes and non-Ethernet/RAW link types are still
  refused with the existing `editcap -F pcap` hint.
- `testdata/pcap/http.pcapng` — a hand-encoded pcapng twin of `http.pcap`,
  produced by `testdata/gen` and covered by a test that asserts it decodes to
  the same packets, flows and `flow-features-v1` vectors as the classic file.
- `/api/v1/status` `live` object now also reports `ws_clients`,
  `ws_client_drops` and `ws_frames_batched` — the last being the count of
  batched WebSocket frames produced by the pump (one per flush, independent of
  the connected-client count). The existing `clients`, `frames_out` and
  `client_drops` keys are unchanged (issue #70).
- `internal/features/interarrival_test.go` — regression tests that pin the
  `interarrival_*` missing-value sentinels (flow-features-v1 indices 15–20)
  through `features.Extract`: a 1-packet flow reads `0` for mean/min/max/stddev,
  a 2-packet flow reports the single gap with stddev still `0`, a 3-packet flow
  with unequal gaps has a non-zero stddev, and `forward_interarrival_mean` stays
  `0` until a direction has two packets (#72).
- **Operator SPA** (`web/ui/`) — a TypeScript + React 18 single-page app built
  with Vite 5, replacing the vanilla-JS rolling-log shell (PROJECT.md §19, §27;
  issue #20, EPIC #1). Hash-routed (`/#/flow-log`), so `internal/api` is
  unchanged. The dark-terminal palette, per-class colours and `⟦THUGS⟧ · (c)
  2026` mark are carried over. Wired Phase-1 views:
  - **Flow Log** — the vanilla rolling log ported to React and extended:
    pause/resume that buffers backend events instead of dropping them,
    resume-to-latest, configurable max retained rows, compact/comfortable
    density, class / min-confidence / protocol / text-search filters, suspicious
    / low-confidence / disagreement row highlighting, kiosk full-screen
    (Fullscreen API), keyboard nav (↑/↓ select, Enter inspect, Space pause), and
    click-to-open Flow Inspector.
  - **Flow Inspector** — a drawer over `GET /api/v1/flows/{id}` +
    `GET /api/v1/schemas/features`: full 5-tuple and direction, timing,
    packet/byte and TCP metadata, all 48 raw feature values joined to the schema,
    the full class-probability vector, per-model outputs and the disagreement
    flag. Normalized inputs, snapshot history and human-review status are labelled
    Phase-2 stubs.
  - **Dashboard** — live counters from `/api/v1/status` plus client-side
    aggregation of the classification stream: classifications/sec and flow-event/sec
    uPlot sparklines, class and protocol breakdowns, rolling-window top talkers and
    destination ports, hosts seen, and the loaded-model list. Cards with no data
    source yet are greyed and marked "needs API".
  - **Replay control** — the footer path / speed / start / stop / status bar
    (same endpoints as before) plus a CAPTURE ▸ Replay page with a live
    ReplayStarted/Progress/Finished event feed.
  - App shell with the full §19 navigation tree; every non-Phase-1 route renders
    a "Planned — Phase N" placeholder naming its tracking epic.
- New Make targets: `web` (build the SPA into `web/dist/`), `web-dev` (Vite dev
  server proxying `/api` + `/api/v1/stream` to `127.0.0.1:8080`), `web-check`
  (`tsc --noEmit`).
- [ADR 0008](docs/adr/0008-react-spa-and-committed-build-output.md) — records the
  TS + React + Vite 5 stack, uPlot, hash routing and the committed-`web/dist/`
  decision.

- **`internal/nn`** — a dependency-free, CGO-free executor for the feed-forward
  neural networks the trainer produces (PROJECT.md §10, EPIC Phase 2). A
  hand-rolled reader for the ONNX protobuf-wire subset (`ModelProto` /
  `GraphProto` / `NodeProto`, `float32` and little-endian `raw_data`
  `TensorProto` initializers, `ValueInfoProto` shapes — no protobuf library)
  feeds a deterministic, batch-1, all-`float32` graph executor. Supported ops:
  `Gemm` (α/β, transA/transB), `MatMul`, `Add` (broadcast — residual blocks
  work), `Relu`, `LeakyRelu`, `Sigmoid`, `Tanh`, `BatchNormalization`
  (inference-time affine fold), `Dropout` (identity), `Softmax`, `Identity`,
  `Flatten`, `Reshape` (constant shape) and `Constant` (folded to an
  initializer). Any other op is a hard load-time error (`nn: unsupported op
  %q`); a malformed model returns an error, never a panic. Public API: `Load`,
  `LoadFile`, `Model.Run`, `Model.InputSize` / `OutputSize` / `OpCounts`. See
  [ADR 0005](docs/adr/0005-go-onnx-inference-runtime.md).
- **`inference.ONNXModel`** — adapts a loaded `nn.Model` to the `Classifier`
  interface, so trained models score through the same `Runtime` as the heuristic
  and each model's output is recorded (PROJECT.md §12). Takes an optional
  per-model `Normalizer` (`func(features.Vector) [48]float64`) supplied from the
  bundle's `normalizer.json`; with none, raw feature values are fed, matching
  the heuristic path. The distribution is defensively clamped and renormalised.
- **`internal/nn/onnxbuild`** — a small ONNX `ModelProto` writer used only by
  tests and by `internal/nn/testdata/gen`, which regenerates the committed
  `internal/nn/testdata/model.onnx` fixture (`go run
  ./internal/nn/testdata/gen`).

- **Model bundle validation gate** (`internal/model`, issue #25) — the daemon
  now reads a self-describing model bundle and refuses an incompatible one
  before it could ever be activated (PROJECT.md §11, §28.6, §28.10):
  - `model.Load(dir)` parses the five-file bundle (`model.onnx`, `metadata.json`,
    `normalizer.json`, `metrics.json`, `training-recipe.json`) and returns an
    **inactive** `*Bundle` — loading never activates anything.
  - `Bundle.Validate()` rejects, naming the offending field: a missing or
    non-JSON file; a `feature_schema` / `input_size` / `output_schema` /
    `output_size` that is not `flow-features-v1` (48) / `traffic-classes-v1` (7);
    an absent or wrong-sized `architecture`; an empty `family`,
    non-positive `parameter_count`, or non-RFC3339 `created_at`; a `model_hash`
    without the `sha256:` prefix or that does not match the SHA-256 recomputed
    over the `model.onnx` bytes; a `normalizer.json` with the wrong feature
    schema, an unknown method, or (for `standard` / `minmax`) not exactly 48
    ascending in-order entries with `std > 0` / `min < max`.
  - `schema.Architecture` / `schema.HiddenLayer` types and
    `schema.ValidateArchitecture` keep the frozen input/output-layer contract
    checks alongside `schema.ValidateBundle`.
  - `features.Affine` (`NewStandardNormalizer` / `NewMinMaxNormalizer`) — a
    fitted per-feature z-score / min-max transform implementing the existing
    `features.Normalizer` interface; `internal/model` builds it from
    `normalizer.json` (`identity` → `features.Identity`). It is a per-model
    concern applied on the trained-model path only; the pipeline never installs
    it.
  - `cmd/synapsed` scans `models.directory` at startup, logging
    `loaded model "<dir>" … — INACTIVE` or `rejected model bundle "<dir>": …`
    per subdirectory. No model is added to the inference runtime and
    `models.primary` is not activated — activation remains a separate explicit
    step, still to be wired.
  - `model.Executor` interface + `Bundle.Bind` are defined (unused) as the seam
    the Phase 2 ONNX runtime (issue #24) will implement.

- **Model roles and multi-model scoring persistence** (issue #27, Phase 2):
  - `internal/inference` `Runtime.Score` now locks the role contract: an
    `experimental` model is a shadow — its prediction is still recorded in
    `result.models[]` but never drives `result.class` / `class_id` / `score` and
    never contributes to `result.disagreement`. The disagreement set is now
    "every role except `experimental` and `anomaly`" (was: every role except
    `anomaly`). Verdict driver = first `primary` model, else the first
    non-`experimental` model, else (all-experimental ensemble) the first model.
    The rule is documented in the `Score` doc comment.
  - `GET /api/v1/classifications` accepts optional, combinable filters —
    `disagreement=true`, `class=<name>` (validated against `traffic-classes-v1`,
    unknown → `400`), `model=<id>`, and `min_confidence=<n>` (fraction or
    `0..100` percentage). No new route; the default (no params) is unchanged.
  - `storage.Stats` gains a cumulative `disagreements` counter, incremented in
    `PutClassification` and surfaced under `storage` in `GET /api/v1/status`.
  - `ModelDisagreementDetected` events already carry the full per-model
    breakdown (`result.models[]`); a pipeline test now guards it.

- **`trainer/` — the Phase 2 Python training service** (`synapse-trainer`,
  issues #21 + #23). A standalone PEP 621 package, separate from the Go tree, that
  turns a labelled `flow-features-v1` dataset into a deployable model bundle:
  - `synapse_trainer.schema` re-reads the frozen `schemas/features/flow-features-v1.json`
    and `schemas/outputs/traffic-classes-v1.json` (or `$SYNAPSE_SCHEMA_DIR`) —
    `INPUT_SIZE` 48, `OUTPUT_SIZE` 7, `FEATURE_NAMES`, `CLASS_NAMES`,
    `check_compatible` (rejects a dataset whose schema name or column count
    disagrees).
  - `architecture` — `HiddenLayer` / `Architecture` with a **locked** 48-in /
    7-out contract and an editable hidden stack; `parameter_count`,
    `estimated_size_bytes`, `rough_flops`, JSON round-trip (the compute half of
    issue #22).
  - `normalize` — pure-numpy `standard` / `minmax` / `identity` scaler emitting
    the exact `normalizer.json` (48 ordered per-feature entries; `std` floored at
    `1e-9`, never `min >= max`).
  - `dataset` — CSV loader (48 schema-named feature columns + `label`) and a
    reproducible, stratified-when-scikit-learn-is-present split that never leaks
    the test set into training.
  - `recipe` — parse + validate `training-recipe.json` (dataset weights and
    train/val/test fractions must each sum to ~1.0; all fields but `datasets`
    default).
  - `train` — builds the PyTorch MLP, trains with the recipe's
    optimizer/scheduler/early-stopping/class-weighting/seed, yields per-epoch
    progress dicts (with an optional `progress_url` POST), and computes accuracy,
    macro P/R/F1, per-class metrics and confusion matrix. `torch` is imported
    behind a guard.
  - `export` (**issue #23**) — `export_bundle` writes `model.onnx`
    (`torch.onnx.export`, opset 17, fixed batch 1, input `features` `[1,48]`,
    output `scores` `[1,7]`, softmax included), `metadata.json` (the contract the
    Go bundle-gate validates; `model_hash` is a sha256 of the written ONNX bytes),
    `normalizer.json`, `metrics.json` and `training-recipe.json`. The JSON
    builders are torch-free.
  - `synapse-trainer` CLI: `train --recipe --data --out [--name]` and
    `inspect-arch --recipe` (parameter count / size / FLOPs, no torch).
  - `trainer/tests/` — pytest suite that passes with only `numpy` installed
    (torch/onnx asserts self-skip); `trainer/examples/` with a sample recipe and
    dataset header.
- CI: `.github/workflows/trainer-ci.yml` (issue #61) — a `trainer/**`-scoped
  workflow, separate from the Go `ci.yml`: a fast job on numpy + pytest, and a
  slower job that installs the CPU PyTorch/ONNX wheels and runs the export tests.
- `docs/adr/0007-python-trainer-and-bundle-export.md` — records Python + PyTorch
  per §27, the guarded-import approach, opset 17 / fixed batch 1, and the exact
  five-file bundle contract as the trainer↔daemon interface.
- `assets/screenshots/` — real screenshots of SynapseIDS running: the Flow Log
  (unfiltered, and filtered to `scan` / `brute_force`), the Flow Inspector
  (verdict panel and the 48 raw `flow-features-v1` values), the Dashboard, the
  Capture Sources view, Replay, the Architecture builder, and rendered
  transcripts of the `synapse` / `synapsed` CLI. `assets/screenshots/README.md`
  indexes them and documents how to regenerate them. The capture tooling stays
  outside the repository — it needs a browser and a Node install, neither of
  which belongs in a tree whose Go build is deliberately dependency-free
  (§28.16).

### Changed

- `api.New` takes a tenth parameter, `*insight.Index`. It may be nil, in which
  case `/api/v1/hosts` returns `[]` and `/api/v1/timeline` an empty series.
- `internal/api`'s `limitParam` helper dropped its always-`100` `def` argument in
  favour of a `defaultLimit` constant (behaviour unchanged; `unparam` flagged it
  once the new routes became callers).
- `README.md`'s "What it looks like" section now shows those screenshots instead
  of the ASCII box-art mock-ups it carried while the SPA was still a placeholder;
  the "Illustrative" disclaimers are gone because the images are real output.
- `GET /api/v1/models` returns an object (`{ "models": [...], "runtime": [...] }`)
  instead of a bare array; the registry entries are the `models` list and the
  previously-returned `{id, family, role}` triples are now `runtime` (with an
  added `registered` flag). `/api/v1/status` keeps its lightweight `models` list.
- `api.New` takes two new parameters — `*registry.Registry` and `*audit.Logger`,
  both nil-tolerant (a nil registry makes the `/api/v1/models*` reads runtime-only
  and the state-changing routes `503`).
- `capture.ErrNotPCAP` now reads "not a pcap file (need a classic pcap or pcapng
  capture)"; the replay-start `409` and the capture docs describe the wider
  accepted set.
- `docs/features-v1.md` now spells out the inter-arrival missing-value contract:
  a flow with fewer than two packets in the relevant direction has no defined
  inter-arrival distribution, so `0` is the deliberate `default_missing`
  sentinel, not a measured value. Documentation only — matches the
  already-frozen `schemas/features/flow-features-v1.json`; no schema or code
  change.
- `web/` now embeds the committed Vite build output (`web/dist/`, `//go:embed
  all:dist`) instead of a single hand-written `index.html`. The Go build stays
  Node-free, offline and cross-compilable; rebuild the bundle with `make web`
  and commit `web/dist/` after editing anything under `web/ui/`. `web.FS()` keeps
  its signature, so `internal/api` is untouched.
- `make clean` also removes `web/ui/node_modules`, `web/ui/.vite` and
  `*.tsbuildinfo` (it leaves the committed `web/dist/` in place).

- `result.class` / `class_id` / `score` in a classification are the
  verdict-driving model's top class (first `primary`, else first
  non-`experimental`) — previously the first model unconditionally, which let an
  `experimental` model listed first override the verdict.

### Removed

- `web/index.html` — the vanilla-JS placeholder shell; its behaviour is ported
  into the SPA's Flow Log and Replay control.

### Fixed

- `capture.Replay` at `--speed max` now yields the scheduler (`runtime.Gosched`)
  every 256 packets. The unpaced emit loop previously had no blocking point, so
  on a single-CPU host a long replay could monopolise the Go scheduler and delay
  `/api/v1` responses. The paced speeds are unchanged — they already block on a
  timer. (#71)

## [0.1.0] - 2026-08-31

First tagged release: the Phase 1 vertical slice plus the full build, packaging
and CI foundation. It classifies replayed PCAP traffic end to end with a
transparent rule-based model — real trained models, live capture and persistence
land in later phases.

### Added

- Repository foundation: MIT licence, Git Flow layout, `PROJECT.md` specification,
  `CLAUDE.md` engineering guide, community-health files.
- **Phase 1 vertical slice** — one working path from a capture file to a live
  classification, with no third-party Go dependencies:
  - `internal/packet`: bounds-checked Ethernet / 802.1Q / IPv4 / IPv6 (bounded
    extension-header chain) / TCP / UDP / ICMPv4 / ICMPv6 decoders producing a
    small normalized `packet.Packet`. Malformed input is counted, never a panic.
  - `internal/capture`: the `Source` interface plus a hand-rolled classic-`pcap`
    reader (µs and ns magic, LE/BE, `EN10MB` and `RAW` link types; `pcapng` is
    refused with a conversion hint) and a `replay` adapter that paces any Source
    to wall-clock × {0.5, 1, 2, 10, max}.
  - `internal/flow`: direction-normalized 5-tuple `Key`; a `Table` that owns flow
    lifetime — close on FIN-both / RST / idle timeout / max lifetime / capture
    end, periodic `snapshot` records for long-lived flows, a bounded flow cap
    with oldest-idle eviction, and a grace window that absorbs the TIME_WAIT
    tail.
  - Frozen contracts under `schemas/`: `flow-features-v1` (48 per-flow features,
    each with unit / calculation / missing-value / normalization metadata),
    `traffic-classes-v1` (7 classes), `event-envelope-v1`. `internal/schema`
    embeds them and provides `ValidateBundle` — the compatibility gate a trained
    model must pass before it can run.
  - `internal/features`: `flow-features-v1` extraction from a flow record, using
    only derived behavioural/context values — no raw IP addresses. `Normalizer`
    interface (identity + log1p) kept as a per-model concern.
  - `internal/inference`: `Classifier` interface, model `Role`s
    (primary/location/global/experimental/anomaly), and a `Runtime` that scores a
    vector with every loaded model and records each model's output plus a
    disagreement flag. A transparent rule-based `Heuristic` model stands in until
    Phase 2 brings trained ONNX models.
  - `internal/events`: an in-process fan-out bus with bounded per-subscriber
    queues and a drop counter; publishing never blocks ingestion.
  - `internal/storage`: the `Store` interface and an in-memory bounded-ring
    implementation with eviction counters. SQLite is tracked separately.
  - `internal/api`: the versioned REST surface (`/api/v1/status`, `flows`,
    `flows/{id}`, `classifications`, `models`, `schemas/*`, `replay`) plus a
    request logger. Binds to loopback by default; a non-loopback listener is
    logged as a warning.
  - `internal/wshub`: a dependency-free RFC 6455 server and a fan-out `Hub` that
    gives every client a bounded send queue and drops — never blocks on — a slow
    client. The daemon batches event envelopes into one frame per interval.
  - `internal/pipeline`: the single wiring `capture → flow → features → inference
    → events + storage` that both live capture and replay run through.
  - `web/index.html`: a dependency-free single-page rolling flow-classification
    log — live WebSocket feed, pause/resume, class / min-confidence filters,
    retained-row cap, replay controls. A React SPA is tracked separately.
  - `cmd/synapsed` (daemon), `cmd/synapse` (admin CLI — every verb is an HTTP
    call to `synapsed`), `cmd/synapse-sensor` (Phase 6 placeholder).
  - `testdata/gen` builds the committed `http.pcap` / `portscan.pcap` /
    `udp.pcap` fixtures; golden feature vectors under
    `internal/features/testdata/` guard the frozen schema. An end-to-end test
    asserts `portscan.pcap` classifies as `scan` and `http`/`udp` as `normal`.
- Build system: a `Makefile` with the development loop and a Linux-only
  cross-compile matrix — `linux/amd64`, `linux/386`, `linux/arm64`, `linux/arm`
  (v7) — building all three binaries, `CGO_ENABLED=0`, `-trimpath`,
  version-stamped. `make dist` produces a per-arch `.tar.gz` (all three binaries
  + man pages) plus `SHA256SUMS`; `make deb` produces four `.deb` packages
  (`amd64`, `i386`, `arm64`, `armhf`) via `dpkg-deb` with DEP-5 copyright and a
  Debian changelog, no `Depends`. `make release-check` verifies a clean tree, a
  matching changelog heading, a free tag and cross-compilation to all four
  targets.
- CI: `Test` (fmt-check, vet, test, race), `Cross-build` (+ a stale-fixture
  check), `Lint` (golangci-lint) and `Vulnerability scan` (govulncheck) on every
  push and PR; a `Branch flow` check that fails a PR opened against the wrong
  base. A `Release` workflow builds every archive and package and publishes a
  GitHub release with `SHA256SUMS` attached on a `v*` tag.
- `install.sh`: an arch-detecting installer that verifies the download against
  `SHA256SUMS` and never calls `sudo`.
- `contrib/`: hardened systemd units, sysusers/tmpfiles, an annotated example
  config, an nginx TLS reverse-proxy sample, logrotate and AppArmor profiles, and
  backup / retention / authorized-remote-capture helper scripts.
- `docs/`: architecture, the REST + WebSocket API, the frozen `flow-features-v1`
  reference, packaging, and three ADRs.
- `README.md` with the project overview, box-art views of the rolling log and
  flow inspector, install and usage, and the phase roadmap; `assets/` logo and
  pipeline diagram.
- GitHub issue templates (bug / feature / idea), a pull-request template, and
  `dependabot.yml` (gomod + github-actions, and pip reserved for the trainer).

### Changed

- `synapse` now accepts flags on either side of the subcommand, so
  `synapse classifications --limit 50` and `synapse replay f.pcap --speed max`
  work as written (Go's `flag` package otherwise stops at the first bare word).
- `flow-features-v1` `bytes_forward` / `bytes_backward` `calc` text corrected to
  "IP datagram lengths (IP header included)" — the values were always the full
  datagram length; only the description was wrong.

### Known limitations

- The classifier is a hand-written heuristic, not a trained model; treat its
  verdicts as a demonstration of the pipeline, not detection quality.
- Storage is in-memory only — history is lost on restart and bounded by
  `storage.max_flows`.
- Only classic `pcap` files are read (not `pcapng`); only file replay, no live
  capture.
- Configuration is JSON, not the YAML shown in `PROJECT.md` §23.
- `.deb` packages are unsigned; integrity is via `SHA256SUMS`.
