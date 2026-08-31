# Changelog

All notable changes to SynapseIDS are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **OPNsense plugin: one sensor process per interface** (issue #124,
  [ADR 0030](docs/adr/0030-opnsense-one-sensor-process-per-interface.md)). The
  plugin ran exactly one sensor on exactly one interface. On a live gateway an
  operator selected WAN, IoT, DMZ and MGMT in what was then a multi-select and
  got a single VLAN captured: three segments believed monitored, none of them
  reporting the difference. PR #132 made the field honest; this makes the plugin
  able to do what was asked of it.
  - **Services → SynapseIDS Sensor now holds a list of sensor instances**, one
    per interface, as a grid with an edit dialog — the core `ArrayField` idiom,
    copied from `System > Settings > Cron`. Each instance has its own interface,
    **its own sensor identity**, its own location, its own capture settings
    (`filter`, `direction`, promiscuous, snaplen, **`send_mode`**), its own listen
    port, its own rendered configuration, its own pidfile and its own log.
  - **One process per interface was chosen over merging interfaces into one
    process** because it gives correct attribution with no protocol change: a
    packet routed between two monitored segments is legitimately reported twice,
    by two *named* sensors, instead of two observations silently merging into one
    flow. The daemon, SYNPOIP and every schema are unchanged.
  - **Authorisation is per instance and is never inherited** (PROJECT.md §28.18).
    Being authorised to monitor the WAN uplink is not being authorised to monitor
    a tenant VLAN, so the assertion is required per instance, is never copied when
    an instance is added, and is not set by the grid's enable toggle.
  - **`service synapseids_sensor <verb> [instance]`** — the FreeBSD profile-list
    idiom (`openvpn`, `nginx`), so every verb works for all instances or one
    named one, and so does `configctl synapseidssensor <action> [instance]`.
    Stopping or restarting also sweeps the pidfile of an instance that has been
    deleted, which would otherwise keep capturing a segment the operator believes
    they stopped monitoring.
  - **The selftest is per instance**: the same one-line-per-check output, with the
    instance name in its own column, so `selftest | grep FAIL` on a firewall with
    four sensors says *which* one is broken. `synapse-sensor doctor` itself is
    unchanged — each instance's rendered configuration deliberately carries the
    same variable names the single-sensor file did.
  - **An existing configuration is migrated, not lost.** Model 1.0.0 → 1.0.1 with
    a real OPNsense model migration, run from the package's `post-install`: the
    interface that was being captured comes back as an enabled, authorised
    instance with all of its settings; any further interfaces that the old
    multi-select accepted but never actually captured come back **disabled and
    unauthorised**, named and visible, for the operator to review.

- **LIVE ▸ Detections — the deduplicated alert feed in the SPA** (the UI half of
  issue #117, built alongside #118). A real filterable view where `#/detections`
  used to be a placeholder: severity, class, occurrence **count**, the 5-tuple,
  confidence, first-seen → last-seen, the daemon's `reason`, the per-model outputs
  and the disagreement flag, with click-through to the Flow Inspector and to
  Investigate. Class, severity, minimum confidence and a `since` window are
  applied by the daemon; the control bar and the "showing N / M" idiom are the
  Flow Log's.
  - **`count` is its own column, and loud.** A deduplicated detection standing for
    412 scanned ports and one standing for a single probe would otherwise render
    identically, which understates the first and overstates the second.
  - **It degrades honestly against a daemon that has no such route.** A 404 from
    `GET /api/v1/detections` — an older binary, which the SPA cannot detect any
    other way — is mapped to a *state*: "not available in this build", naming
    #117. Not an error banner, not a spinner that never resolves, and not a
    console error; the polling stops rather than logging a 404 a second forever.
    The same is true of the Dashboard's *Recent detections* card. A **current**
    daemon with no alert store answers `200` with an empty page, and that is a
    deliberately different, equally honest render. The view was written against
    the contract while the endpoint was still on a sibling branch and needed no
    change when it landed.
  - Unit-tested without any backend against `web/ui/test/fixtures/detections.json`,
    a byte-for-byte instance of the response contract, and verified end to end
    against the real endpoint (a replayed MySQL credential-stuffing run comes back
    as one `brute_force` detection with `count: 182`, not 182 rows).
- **SPA unit tests** — `npm test` / `make web-test`, using node's built-in test
  runner over the framework-free modules (`web/ui/test/`,
  `web/ui/tsconfig.test.json`). No test framework was added; the only new
  dependency is `@types/node`, which ships types and no runtime code.
- **Detections — `/api/v1/detections` and a real `AlertCreated`** (issue #117;
  [ADR 0027](docs/adr/0027-detection-dedup-and-derived-severity.md)).
  `AlertCreated` had been in the frozen `event-envelope-v1` list since Phase 1
  with nothing emitting it, and there was no detection resource at all. There is
  now.
  - **`internal/alert`** — an alert `Policy` (per-class confidence thresholds plus
    optional alert-on-disagreement) and a bounded, **deduplicating** store of
    recent detections. A verdict becomes a detection when its class is not
    `normal` and it clears the threshold for that class, or when the ensemble
    disagreed and `alert_on_disagreement` is set (PROJECT.md §12). Each detection
    carries `count`, the first and most recent timestamps, the max confidence
    seen, the flow ids, the tuple, the per-model breakdown and a `reason` built
    from measured values only.
  - **A 1000-port sweep is one detection, and one event.** Dedup is on
    `(src_ip, dst_ip, class)` — the ports are deliberately *not* in the key,
    because a port sweep varies precisely the field that would be in it. A repeat
    increments `count`, advances `last_ts`, raises `confidence` and appends the
    flow id, and **publishes nothing**: `AlertCreated` fires once per *new*
    detection, so the WebSocket stays quiet under a scan (§22). The window is
    anchored at the first occurrence rather than sliding, so a sustained attack
    re-alerts once per window instead of going permanently silent, and the clock
    is the record's own timestamp — a `--speed max` replay dedups exactly as live
    capture would (§26).
  - **`GET /api/v1/detections`** — `limit` (default 100, max 1000), `class`,
    `severity`, `min_confidence` (0..1 or a 0..100 percentage), `since` (RFC3339,
    matched against `last_ts`, so an ongoing detection that started earlier is
    still reported). Reports `total` (matches before `limit`), `returned` and
    `evicted`. `GET /api/v1/detections/{id}` is the single object, with the same
    400/404 contract as `/api/v1/flows/{id}`. This route is **stricter** than the
    older collection routes on purpose: an unknown parameter name or an
    unparseable value is a `400`, because on a route whose job is "show me what
    matters", a typo that silently widens the result to everything is worse than
    an error.
  - **Severity is derived from the class, never added to the frozen schema.**
    `normal` never alerts; `suspicious`→`low`, `scan`→`medium`,
    `brute_force`/`web_attack`→`high`, `dos_ddos`/`botnet_c2`→`critical`. The
    table is code, not config — a per-deployment override could produce a class
    with an empty severity that no filter can select — and `alert.init()` panics
    at startup if the table and `traffic-classes-v1` disagree in *either*
    direction, so a future class cannot ship a silent `"severity": ""`.
  - **Nothing was added to the packet path.** `pipeline` publishes
    `ClassificationCreated` / `ModelDisagreementDetected` as before and
    deliberately does **not** publish `AlertCreated`: dedup needs mutable state
    the packet path must not own or lock. `Options.Alerts` gets one non-blocking,
    **zero-allocation** send per verdict (pinned by
    `TestObserveDoesNotAllocate`), and the alert store's own goroutine applies the
    policy, folds the detection and publishes — the same bounded-queue /
    single-aggregator pattern `internal/insight` established, not a third one. A
    full queue drops and counts.
  - **Bounded, and it says so.** `alerts.max_recent` (default 1000) with
    oldest-first eviction and an `evicted` counter, mirroring `storage.Mem`;
    `evicted` appears on both `/api/v1/status` and every `/api/v1/detections`
    response so a client can tell a window from a history. Evicting a detection
    also drops its dedup entry, so an evicted key can alert again instead of
    being silently muted. `flow_ids` holds the 20 most recent *distinct* flows
    while `count` reports every occurrence.
  - **New `alerts` config block** — `enabled` (true), `min_confidence` (0.70),
    `per_class_min_confidence` (`{"suspicious": 0.85}`), `alert_on_disagreement`
    (true), `max_recent` (1000), `dedup_window_sec` (60). Ranges and per-class
    keys are validated at load and nonsense is *rejected*, not clamped: a
    threshold of `7` or an override for a class that does not exist is a typo, and
    silently correcting it would leave the operator believing something is being
    alerted on. Counters on `/api/v1/status` under `alerts`: `created`, `deduped`,
    `suppressed`, `evicted`, plus `retained` / `max_recent` / `observed` /
    `dropped` / `queue_size` / `dedup_window_sec` and `enabled`.
  - **Measured on a real capture** (68 810 packets, 1 176 flows — browsing + an
    nmap scan + a MySQL brute force against `10.10.10.21:3306`): **6 detections
    from 1 176 verdicts, with 302 folded into them**. The brute force is three
    `high` detections of counts 126 / 121 / 57, one per 60s window. **There is no
    `scan` detection at all** — the Phase 1 heuristic does not recognise the recon
    on this capture (#90). The thresholds were not tuned to manufacture a nicer
    number: a detection feed that reports what the model actually said is the
    honest input to fixing the model.
  - **Not done, deliberately:** notification delivery (email/webhook/syslog),
    anomaly-driven detections (#47), acknowledge/close state per detection, and
    persistence — detections live in a ring and do not survive a restart. The
    `#/detections` SPA view is separate work.

- **OPNsense plugin: TLS material is rendered, and there is a selftest**
  (issues #104 and #102;
  [ADR 0028](docs/adr/0028-opnsense-tls-material-and-selftest.md)). The plugin was
  built and packaged but had never been near a firewall; this is the pass that
  makes the parts that *can* be made correct correct, and makes the rest fail
  loudly on the box instead of half-working.
  - **Three new configd template targets (#104).** `sensor-ca.pem` and
    `sensor-cert.pem` (`0444 root:wheel`) and `sensor-key.pem`
    (**`0400 _synapseids:_synapseids`**) are now rendered from the OPNsense
    configuration store. An operator no longer copies PEM files to the firewall by
    hand. The CA file is renamed `peer-ca.pem` → `sensor-ca.pem`; no released
    package installed the old name.
  - **The private key is clamped exactly like the bearer token.** The `fixperms`
    configd action now covers all five rendered files and runs immediately after
    every `template reload`, closing configd's umask window.
    `Api\ServiceController::reconfigureAction` is overridden to run it too —
    previously a `reconfigure` that left the service stopped could leave a fresh
    private key mode `0644` indefinitely.
  - **The fail-safe property is kept and widened.** `rc.d` still refuses to start
    and names the path when a referenced PEM is missing — now also when it is
    *empty* or has no `-----BEGIN` line. Nothing anywhere downgrades to
    `--insecure-tls`.
  - **PEM validation moved to save time.** `Sensor::performValidation` rejects
    truncated or mismatched-label blocks, undecodable base64, a private key pasted
    into a certificate or CA field (and vice versa), a chain where a single
    certificate belongs, an encrypted key (Go's `crypto/tls` cannot use one and an
    unattended firewall has nowhere to type a passphrase), and **a key that does
    not match its certificate**.
  - **`synapse-sensor doctor` — an on-box selftest (#102).** Nine checks, one
    `[ OK ]`/`[WARN]`/`[FAIL]`/`[SKIP]` line each, remedies inlined on failure:
    binary, rendered config, service account, `/dev/bpf*` access, capture device,
    token mode, TLS identity, TLS trust, log sink, collector reachability (TCP
    connect only — no handshake, no credentials). Reachable as
    `service synapseids_sensor selftest`, `configctl synapseidssensor selftest`,
    and a **Run selftest** button on the settings page. Read-only; prints no
    secrets.
  - **Interface resolution hardened — the highest-value fix.** The template used
    to fall back to emitting the bare OPNsense identifier, so a sensor could report
    *running* while bound to nothing and capturing zero packets. It now tries
    `interfaces.<id>.if` then `helpers.physical_interface(<id>)`, records which
    won, and on failure emits an **empty** device plus a diagnostic that `rc.d`
    refuses to start on. `rc.d` additionally runs `ifconfig` and refuses if the
    resolved device does not exist, printing the attempted lookup and the devices
    that do.
  - **Eight of nine `TODO(verify)` markers resolved**, four by removing the
    dependency rather than confirming it. The one kept — whether `daemon(8)`'s
    `-f` defeats `-S -T` — now has `-o <logdir>/sensor.log` as a second sink and a
    `log-sink` selftest line that reports it; if the assumption is wrong the sensor
    still captures and only its log is empty.

- **Traffic matrix and sensor topology** (issues #68 and #46 — **the last two open
  children of EPIC Phase 5 and EPIC Phase 6**;
  [ADR 0026](docs/adr/0026-traffic-matrix-and-sensor-topology.md)). Two
  relationship views over data that already existed, feeding one "scope everything
  to this thing" interaction.
  - **`GET /api/v1/matrix`** — who talks to whom. Per ordered
    `(initiator, responder)` pair: flow count, byte volume (both directions),
    packets, the class mix, and `threat_class` — the highest-count class that is
    **not** `normal`, so a pair with 400 benign and 3 `brute_force` verdicts is
    still visibly the cell worth looking at. `flow.Key` is direction-normalized, so
    `A→B` and `B→A` are separate cells and are never merged. Accepts `limit`,
    `sort` (`flows` \| `bytes` \| `last_seen`), `from`/`to`, and the full
    `parseClassFilters` vocabulary (`class`, `model`, `min_confidence`,
    `disagreement`), so it speaks the same dialect as everything else.
  - **It is a bounded top-N, not a matrix, and it says so.** The host map is capped
    at 2048, which permits ~4.2 million pairs; `internal/insight` tracks at most
    **4096**, discarding the lighter half by `(flows, bytes)` on overflow and
    counting it. Every response carries `partial` (the cap bit, or a filtered scan
    hit its window), `truncated` (`limit` cut the list — deliberately a *different*
    flag), `pairs_evicted`, `tracked_pairs` and `source` (`incremental` vs `scan`).
    A pair evicted and later seen again restarts from zero; the flow log and host
    profiles stay the systems of record. `pairs` / `pair_cap` / `pairs_evicted` are
    on `/api/v1/status` under `insight`.
  - **Nothing was added to the packet path.** `insight.Observe` still copies one
    ~120-byte observation and does one non-blocking send: **77 ns/op, 0 allocs**.
    The matrix fold runs on the aggregator goroutine at **38 ns/op, 0 allocs** on
    an existing cell, taking the whole per-record fold from 226 → **245 ns/op**.
    `TestMatrixObserveDoesNotAllocate` pins the zero. Worst case — every record a
    new pair, pruning every 512 inserts — is 602 ns/op.
  - **`GET /api/v1/sensors/topology`** — the connected sensors grouped by the
    location each one reported, with per-location aggregates (sensor and running
    counts, summed pps/bps/packets/bytes/drops/records, the modes in use, newest
    `last_packet`) and a `down`/`degraded`/`ok` health verdict, where *degraded*
    includes "a sensor is running but dropping". Sensors that reported no location
    group under an explicit `unassigned` bucket, sorted last; **no location is
    invented for them.** Locations differing only in case stay distinct, because
    merging them would mean choosing a spelling no sensor sent. With no collector
    wired it returns an empty grouping with `collector: false` rather than a `503`,
    which is deliberately distinguishable from a collector nobody has connected to.
  - **`sensor=` and `location=` scope the flow and classification lists** — the
    §19.15 interaction. They join `classFilters`, so every route already speaking
    that dialect gains them, including `GET /api/v1/flows`, which previously took
    no filters. An unresolvable `location=` is a **`400`**, never a silently empty
    `200`.
  - **Flow-to-sensor attribution is only partly possible, and the API says which
    part.** `flow`- and `feature`-mode sensors ship pre-tagged records, so scoping
    genuinely filters their traffic. `raw`-mode sensors' packets merge into one
    channel and one flow table before a flow record exists, so their rows are
    labelled `"local"` like a local NIC or a PCAP replay, and a `sensor=` scope
    would match nothing. Every topology sensor row therefore carries
    `flow_attribution: "records" | "none"`, each location reports
    `attributable_sensors`, and the SPA offers the scope links **only** where they
    work — a `counters only` affordance with the reason beats a filter that
    silently returns an empty list. Fixing the raw case needs sensor identity on
    `packet.Packet` *and* in `flow.Key` (or two sensors' identical 5-tuples merge
    into one flow); that is a data-plane change and is deferred, not faked.
  - **SPA:** `CAPTURE ▸ Sensors` (`#/sensors`) replaces its "Planned — Phase 6"
    placeholder with the grouped topology, and a new `LIVE ▸ Matrix`
    (`#/matrix`) draws the matrix as a canvas heat grid — cells tinted by the
    pair's worst class, shaded by `sqrt(share)` of the heaviest cell, hollow
    outline for model disagreement — with the pair list beneath it and
    click-through to Investigate for either endpoint. The scoped Flow Log shows a
    "scoped to X" strip with a clear button. Verified against
    `nmap_scan.pcap`: `10.10.10.22 → 10.10.10.21` is the hot cell at 426 flows /
    9.4 MB / 304 `brute_force` verdicts, every one to `:3306`.
- **The Flow Inspector explains the verdict, and shows a flow's history** (issue
  #38, EPIC Phase 5;
  [ADR 0025](docs/adr/0025-flow-inspector-explanation-and-snapshots.md)). The last
  four §19.3 items that were still labelled stubs in the drawer — normalized model
  inputs, historical snapshots, the anomaly score, and the explanation panel —
  are now either built or honestly labelled.
  - **`GET /api/v1/flows/{id}/explain`** — why this flow got this verdict.
    `models[]` is built from the **stored** classification, i.e. the models that
    actually scored it, not whatever is loaded now; a model since swapped out is
    reported `loaded: false` with its verdict intact and its rationale not
    reconstructed.
  - **The heuristic explanation is exact, not an approximation.**
    `Heuristic.Classify` and the new `Heuristic.Explain` share one private
    `evaluate(v, explain bool)`, so the fired-rule list is produced by the *same*
    evaluation that produced the verdict and cannot drift from it. Each
    `FiredRule` carries a stable id (`scan.unanswered_syn`,
    `brute_force.auth_port_rounds`, …), a human sentence, and **the feature values
    its condition compared**, each with its `flow-features-v1` name and unit. This
    turns `SCAN 99.3%` into "because `tcp_syn_count=1`, `packets_backward=0`,
    `flow_duration=0s`". `class_weights` reports the real pre-softmax weights, and
    a test asserts they soft-max back to `Classify`'s scores bit-for-bit.
  - **No per-feature attribution for trained models, stated plainly.**
    `*ONNXModel` deliberately does not implement the new `inference.Explainer`:
    exact attribution needs gradients or SHAP, `internal/nn` exposes no weights,
    and a first-layer linear proxy rendered in a panel captioned "explanation"
    reads as an explanation regardless of the caption. The API returns
    `kind: "unavailable"` with the reason, pointing at the full class-probability
    vector as that model's complete output. A test asserts `*ONNXModel` is *not*
    an `Explainer`, so it cannot acquire a fake one by accident.
  - **Normalized inputs are per model, from that model's own bundle** — because
    normalization is a per-model concern and the pipeline scores the *raw* vector
    (PROJECT.md §8). `kind: "raw"` for the heuristic says "this model reads raw
    values" in words rather than rendering an identity table that would imply a
    step which does not happen; `kind: "normalized"` carries raw→normalized pairs
    for all 48 features, resolved through `registry.Active()` → `model.Load` →
    `Bundle.Normalizer()` and cached per `<model id>@<content hash>` (a registered
    bundle is immutable, and `model.Load` hashes `model.onnx`); `kind: "unknown"`
    shows nothing and says why.
  - **`GET /api/v1/flows/{id}/snapshots`** — the retained version history of one
    flow, oldest first, each version paired with the verdict computed from it via
    an exact `Classification.TS` ↔ `FlowRecord.LastSeen` join. A version whose
    verdict aged out reports `verdict: null` and the response calls it a retention
    gap, never "not classified".
  - **`storage.Store` gains `FlowHistory(id)`, and `Mem` stops discarding
    snapshots.** `flow.Table` has always emitted a `ReasonSnapshot` record per
    interval for a long-lived flow and `pipeline` has always stored every one, but
    `Mem.byID` was one entry per flow id — last write wins — so nothing could
    address earlier versions. History is now bounded twice: globally by the flow
    ring (each retained version owns exactly one live ring slot, so total versions
    can never exceed `max_flows` and memory is unchanged) and per flow by
    `storage.FlowHistoryCap` (**64**, oldest dropped first, counted in the new
    `status.storage.flow_versions_dropped`). On a 28 MB real capture that is 1176
    addressable flow versions where it was 1124.
  - **No baseline column, and no anomaly number.** §19.3's example shows a
    "Current vs Baseline" table, but behavioural baselines and anomaly scoring are
    Phase 7 (§13). Both are reported as `{available: false, note}` — two keys and
    **no value field** — matching how `insight` and the reports already label the
    gap. A fabricated expected range would turn "never checked" into "checked and
    clean". A test asserts on the raw JSON that neither object carries anything
    else and that `anomaly_score` / `baseline_value` / `baseline_range` /
    `training_baseline` appear nowhere in the response. The anomaly score also
    gets its own labelled section in the drawer, which it previously lacked
    entirely — it had been folded into the explanation stub.
  - **SPA** — the three stubs in the Flow Inspector drawer are replaced by a
    per-model normalized-inputs view, a snapshot timeline with a verdict per row,
    and the explanation panel; the long tables collapse behind `<details>` since
    the drawer was already dense, while the fired rules stay open. "No rule fired"
    is boxed as a finding rather than left as dim text that reads like a failed
    load. Own commented blocks at the end of `types.ts` and `styles.css`.

### Changed

- **Dashboard cards that claimed "needs API" for endpoints that already exist are
  wired** (issue #118). Five cards were greyed out and citing development phases
  that had since closed, so correct "not built yet" notices read as broken
  promises while real data sat one fetch away.
  - **Active flows** → `status.flow.active`, with started / closed / evicted and
    the flow-table cap beneath it.
  - **Packets / sec** and **Throughput** → rates derived from the cumulative
    counters on `/api/v1/captures` and `/api/v1/sensors/topology`, plus a running
    replay's packet counter (PROJECT.md §6 lists Replay as a capture source), each
    with a uPlot sparkline built the same way the classifications/sec card's is.
    `lib/rates.ts` divides the delta by the **real** elapsed time between
    readings, the way `capture.Manager.sample` does server-side: one reading is
    not a rate (the card says "measuring…"), and a counter moving backwards is a
    reset rather than negative traffic. Throughput deliberately **excludes** the
    replay, because `status.replay` carries no byte counter — the card says so
    instead of multiplying packets by a guessed frame size (§16).
  - **Sensor health** → `/api/v1/sensors/topology`, distinguishing
    `collector: false` ("off — no collector configured") from a collector with
    nobody connected, and listing each location's health, running count and
    pps/bps.
  - **Loaded models** footer → `/api/v1/models`: registered count, the active
    model, and a pointer to ML ▸ Models for per-model metrics and lineage.
  - **A working endpoint with nothing to show is an idle state, not a greyed
    "needs API".** The three cases — no endpoint, endpoint broken, endpoint fine
    but idle — now look different.
- **No placeholder in the SPA cites a development phase any more** (issue #118).
  Every "not built yet" notice names the **open** issue tracking it, which stays
  checkable after an epic closes: Storage #53, Settings #54/#59, Model Comparison
  #48, Drift #49, System Performance #55, the anomaly stubs on Flow Inspector /
  Timeline / Hosts / Investigate #47, per-host baselines #63. The sidebar tag for
  a stub is now its issue number rather than `P{n}`. Phase framing is kept only
  where it is still accurate — EPIC: Phase 7 (#7) is open, so Model Comparison and
  Drift still name it *alongside* their leaf issues. The gaps themselves stay:
  §16 makes a labelled gap correct and a fabricated number a defect.
- **`StreamProvider` polls `/api/v1/status`, `/api/v1/captures` and
  `/api/v1/sensors/topology` in one 1 Hz `Promise.allSettled`**, so the ingest
  counters behind the two rate cards are sampled in lock-step and one broken
  endpoint cannot blank the others.

### Fixed

- **OPNsense plugin: `helpers.physical_interface()` was trusted to signal
  failure, and does not.** The core helper is
  `getNodeByTag('interfaces.'+name+'.if') or name`, so an unresolvable interface
  identifier comes back *unchanged* — the configd template would have emitted
  `--iface wan`, a plausible-looking device name that binds to nothing. The
  fallback lookup now treats a result equal to the identifier as "not found", and
  the template harness models the helper's real behaviour rather than an imagined
  empty return. (The `rc.d` `ifconfig` check already refused to start in that
  state, so this was a wrong diagnosis rather than a silent mis-capture.)
- **OPNsense plugin: the template harness was not rendering the way configd
  does.** It used `lstrip_blocks`, `keep_trailing_newline` and `StrictUndefined`,
  none of which configd sets, and lacked the `do`/`loopcontrols` extensions and
  the filters configd registers. It now uses configd's `Environment` verbatim,
  reproduces its trailing-newline fixup, reimplements its `+TARGETS` per-item
  expansion, and asserts the render for 0, 1 and 4 instances — the single-instance
  case matters because `config.xml` stores one repeating element as a dict and
  several as a list.
- **A `raw`-mode sensor lost 63% of frames to BPF kernel drops because it wrote
  one TLS record — and one syscall — per captured packet** (issue #127;
  [ADR 0029](docs/adr/0029-synpoip-batched-sensor-writes.md)). On an OPNsense WAN
  sensor a single 5 GB download produced `netstat -B` `Recv 1455970 / Drop 916190`
  with both BPF buffers full and `synapse-sensor` at 81% CPU. The kernel was
  batching correctly; the consumer could not drain. `pcapoverip`'s server loop
  armed a write deadline and called `WriteFrame` — itself two `Write`s — per
  frame, and crypto/tls emits a record per `Write`, so 1.45 M packets became
  ~2.9 M TLS records, ~2.9 M syscalls, 1.45 M deadline updates and 1.45 M
  ~1.5 KB allocations. AES was never the cost; the box has AES-NI.
  - Outbound frames now coalesce into a 64 KiB `bufio.Writer` per connection and
    flush as a unit. **The bytes on the wire are byte-for-byte identical** — only
    the TLS record and syscall boundaries move. No wire format, protocol version
    or schema changed, and the existing transport tests pass unmodified.
  - **A quiet link still never sits on a packet.** After each frame the loop does
    a non-blocking check for another; with nothing ready it flushes immediately
    (PROJECT.md §17, §22). Proved end to end over real TLS with the keepalive and
    write timeout set to 10 minutes, so nothing else *can* deliver the frame:
    measured 29–55 µs from sensor to daemon on an idle link. A batch is bounded
    by age (`WriteTimeout/2`) and by frame count as well, so no traffic shape can
    leave data in the buffer or starve the keepalive.
  - Control frames flush, and so does every return path including the error ones:
    a lost goodbye or a truncated final frame would be a correctness bug.
  - **10 000 × 1514-byte frames: 20 000 `Write` calls and 10 000 deadline updates
    become 235 and 10; 20 002 allocations become 4; the wire bytes are asserted
    unchanged at 15 270 000.** Through a real `*tls.Conn` on loopback the same
    frames take 7.0 ms instead of 74.3 ms — **10.6× the sensor throughput per
    CPU-second** (`BenchmarkSensorWrites*`).
  - The collector's **read** side was checked and deliberately left unbuffered:
    crypto/tls already batches reads into a 16 KiB record buffer, so a
    `bufio.Reader` there cuts `Read` calls 20 000 → 234 and changes wall clock by
    nothing (6.9 ms vs 7.7 ms) while adding a copy of every packet byte. The
    measurements are kept as tests so the next person gets numbers, not
    intuition.
  - This makes `raw` mode cost what it should; it does not make `raw` the right
    mode for a saturated uplink, which still re-streams every captured byte.
    `--mode flow` / `--mode feature` remain the structural answer.
- **`install.sh` rejected valid `SHA256SUMS` files** and aborted with "no entry in
  SHA256SUMS". The pattern `\./\{0,1\}` requires a literal dot and makes only the
  *slash* optional, so a `<hash>  <name>` line — what a hand-rolled LAN mirror
  produces — never matched. It is now three plain `-e` expressions, because every
  BRE interval (`\{0,1\}`, `\{1,\}`) contains a comma and comma was the `s,,,`
  delimiter, which silently truncated the combined pattern. The package name is
  escaped so version dots cannot act as wildcards, and the digest is length-checked.
- **`install.sh --url` needed internet access.** With a mirror but no `--version`
  it still called `api.github.com` to resolve "latest", which fails on a firewall
  served from a LAN host. The version now comes from the mirror's own `SHA256SUMS`.
- **The configd template's `sh()` escaping macro was one barrier short.** It
  stripped `'`, `"`, `` ` `` and `$` but not `;` `|` `&` `<` `>` `\`, so a config
  value containing a shell metacharacter reached the file `rc.d` sources as root.
  Not exploitable — the same macro removes the quoting needed to break out of the
  word, and each field's `Mask` already excluded those characters — but it is now
  actually the two independent barriers the header claimed. `synapse-sensor doctor`
  refuses to parse a `sensor.conf` containing any of them.
- **`install.sh --uninstall` left the rendered TLS private key on disk.** It now
  removes all five rendered files.

- `GET /api/v1/sensors` and `/api/v1/sensors/topology` panicked and returned an
  empty reply on a daemon with no `capture.collector` block configured — which is
  the default. `cmd/synapsed` handed `api.New` a **typed-nil** `*capture.Collector`
  as the `SensorStatusProvider`, so the interface value was non-nil (it carries a
  type), every `if sp != nil` guard passed, and the first method call dereferenced
  a nil receiver. Fixed at both layers: the daemon only assigns the provider when a
  collector exists, and `(*Collector).Sensors`/`Sensor` are nil-receiver safe.
- **A spurious `404` from `GET /api/v1/flows/{id}` for a long-lived flow that was
  still retained** (found while building #38). `flow.Table` increments
  `SnapshotIndex` on the *live* entry, so a flow's terminal record inherits the
  last snapshot's index. `storage.Mem` identified a stored version by
  `(flow id, SnapshotIndex)` and deleted its `byID` entry when an *older*
  duplicate-index snapshot was overwritten in the ring — dropping a flow whose
  terminal record was still present. Versions are now keyed by an internal
  monotonic sequence number, which cannot collide. Regression-tested.
  - Note that `SnapshotIndex` still does not reset to `0` on close, contrary to
    the frozen schema text for feature 47. Nothing depends on its uniqueness any
    more and `/snapshots` surfaces the duplicate in a note, but feature 47 feeds
    the golden vectors and every dataset CSV, so correcting it is a separate
    reviewed change rather than a side effect of this one.
- **Sensor modes `raw` / `flow` / `feature`, and SYNPOIP v2 record frames**
  (issue #45, EPIC Phase 6;
  [ADR 0024](docs/adr/0024-sensor-modes-and-synpoip-record-frames.md)).
  `synapse-sensor` can now aggregate flows — and even extract features — on the
  sensor itself, so a box on a constrained WAN link no longer has to ship every
  frame for the daemon to rebuild what the sensor already knows.
  - **`--mode raw|flow|feature`** (default `raw`, or `$SYNAPSE_SENSOR_MODE`).
    `raw` is unchanged in every respect. `flow` runs `internal/flow` on the
    sensor and ships `flow-record-v1` records; `feature` runs `internal/flow`
    **and** `internal/features` and ships only the 48 computed
    `flow-features-v1` values plus the flow's endpoints, timing and close reason.
    New `--flow-idle-timeout`, `--flow-max-lifetime`,
    `--flow-snapshot-interval` and `--flow-max` mirror the daemon's own
    lifecycle defaults.
  - **`feature` mode ships no packet content at all.** Frames are decoded, folded
    into counters, reduced to the 48 derived numbers and discarded inside the
    sensor process — the encoder is never handed a frame. It is the mode for a
    link whose traffic is sensitive, or a site that will permit flow telemetry
    off-box but not payloads.
  - **Measured**, end to end at the loopback interface (TLS and TCP overhead
    included), for a 68 814-packet / 1 176-flow nmap capture: `raw` ~39 MB,
    `flow` ~600 KB (**~1.4 %**, ~70× less), `feature` ~740 KB (**~1.8 %**, ~55×
    less); the exact SYNPOIP payload is a fixed 295 / 437 bytes per record.
    The cost is per *flow*, so the break-even is 4-5 packets/flow for `flow` and
    6-7 for `feature`; a scan of one-packet flows is the worst case and the
    record modes can lose there. Note `feature` records are *larger* than `flow`
    records (432 vs 290 payload bytes) — 48 `float64`s cost more than the
    accumulators they came from, so `flow` is the bandwidth mode and `feature`
    the privacy mode.
  - **All three modes classify identically.** The mode is a transport
    optimisation, not a behaviour change, and it is tested as such: a local
    replay and `raw`/`flow`/`feature` sensors over a real loopback TLS collector
    must produce the same ordered set of verdicts. The manual run agrees — 1 176
    flows and 1 176 classifications in every mode.
  - **SYNPOIP v2**: new frame types `0x04` flow record and `0x05` feature record,
    a mode + payload-schema tail on the `ServerAccept`, and a new typed reject
    `0x06 mode-unsupported`. Byte layouts in
    `internal/capture/pcapoverip/PROTOCOL.md` §3.4-3.6.
  - **v1 peers keep working, byte for byte.** The ClientHello's fixed `version`
    field stays at `1` forever; the v2 ceiling rides as `max_version` in the hello
    metadata, which a v1 sensor decodes and drops as an unknown key. (Bumping the
    fixed field cannot work: a v1 server rejects it outright and closes, and
    there is no in-session retry — a v2 daemon would loop forever against a v1
    sensor that keeps reconnecting.) The accept's v2 tail is written **only** when
    the negotiated version is 2, because a v1 client would read those bytes as a
    frame header. Full compatibility matrix in PROTOCOL.md §2.4, asserted in both
    directions by `TestNegotiationMatrix`.
  - **A `flow`/`feature` sensor is never silently downgraded to `raw`.** Talking
    to a v1 daemon (or a daemon with no record channel wired) it is refused with
    `0x06`, naming the mode — a `feature` sensor quietly shipping packet content
    would destroy the property the operator selected the mode for.
  - **Payloads are schema-bound twice**: the session carries the frozen schema id
    (`flow-record-v1` / `flow-features-v1`) in the accept and the daemon
    **refuses** anything it does not implement before reading a frame, so a future
    `flow-features-v2` sensor is rejected rather than misread (§28.5-6); and every
    record opens with a one-byte layout version. Every length is bounds-checked
    before allocation and a malformed record is counted and skipped, never a
    panic (§28.11).
  - **Flow ids are remapped.** A sensor's ids are its own counter and collide
    across sensors and restarts, so every arriving record is reallocated through
    the daemon's shared `IDGen`; the original is kept as
    `sensor_flow_id` alongside a new `sensor_mode` on the stored flow record. A
    `feature`-mode row reads its counters back out of the vector rather than
    defaulting them to zero, so it never implies a measurement that did not cross
    the wire.
  - **Operator visibility**: `mode`, `protocol_version`, `payload_schema`,
    `records` and `record_bytes` on `GET /api/v1/sensors`, and `mode` / `records`
    / `record_bytes` on `GET /api/v1/captures`. In a record mode `packets`,
    `bytes`, `pps` and `bps` are `0` by construction — no frames crossed the wire
    — and `mode` is what explains it.
  - **`internal/flow` and `internal/features` are reused, not reimplemented.** Two
    small supporting changes: `flow.Accumulators` / `WithAccumulators` /
    `WithDerivedKey` (`internal/flow/wire.go`) make a `Record`'s private
    accumulators serialisable so `features.Extract` is bit-identical on either
    side, and the new `flow.Pacer` extracts the `Table.Tick` cadence that was
    inline in `pipeline.Run` so a sensor and the daemon cannot drift on where
    flow boundaries fall.
  - Not yet: the dialled (`--listen`) posture does not accept records — it
    advertises `max_version: 1` and a record-mode sensor it dials is cleanly
    rejected — and records are one per frame rather than batched. Both tracked
    for #46.


- **The daemon-side SYNPOIP collector, and real sensor identity** (issues #43 and
  #103, EPIC Phase 6;
  [ADR 0018](docs/adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)).
  `synapse-sensor pcap-over-ip --connect <daemon>` — the reverse/outbound posture
  #98 built for a sensor behind NAT — is **usable end to end** for the first time:
  `synapsed` now has something to dial.
  - **`capture.Collector`** (`internal/capture/collector.go`) — a long-lived TLS
    listener that accepts sensor connections. It is a *listener*, not a dialled
    target, so it is a distinct `capture.collector` config block rather than a
    `capture.sources[]` kind; all four existing kinds are untouched. Off by
    default (`listen: ""` = no new listening socket).
  - **No wire change.** Per PROTOCOL.md §6 the accepting daemon still sends the
    ClientHello and the sensor answers with a ServerAccept and streams frames, so
    the collector runs the SYNPOIP **client** half (`pcapoverip.ClientHandshake`
    + a frame loop) on each accepted connection. `protocol.go` is byte-for-byte
    unchanged and there is no version bump.
  - **One `capture.Manager` source per accepted peer**, via the new internal
    `sessionSource` adapter: `kind: "pcap-over-ip-listen"`, `origin: "collector"`,
    named after the sensor id (de-duplicated with a short session suffix if two
    sensors claim the same id, falling back to the remote address). Packets join
    the one merged channel the single pipeline goroutine drains. When the stream
    ends — goodbye, EOF, read-idle or shutdown — the row is **removed**, not left
    as `stopped`. The sensor-advertised filter and the accept-time handshake
    latency surface in the existing capture row.
  - **Bounded accept** (PROJECT.md §21): `max_sensors` (default 32) caps
    *registered* sensors, and a looser `max_sensors + 16` caps connections still
    handshaking, so a stream of probes cannot starve real sensors. An over-cap
    peer is closed before any TLS or SYNPOIP work; rejections are counted
    (capacity / TLS / auth / protocol) and logged.
  - **Auth posture.** Because the SYNPOIP roles do not invert with the TCP
    direction, the bearer token proves the *daemon* to the sensor (which verifies
    it with `crypto/subtle`), and `client_ca_file` →
    `RequireAndVerifyClientCert` is what authenticates the *sensor* to the
    daemon. An inline `token` is refused (§23; use `token_file` or
    `SYNAPSE_COLLECTOR_TOKEN`), and `authorized: true` is required to enable the
    collector at all (§28.18). A missing or unreadable certificate is logged once
    and the daemon keeps serving the API, degraded — like a NIC that cannot open.
  - **Sensor identity** (#43). `synapse-sensor` resolves `--sensor-id` /
    `SYNAPSE_SENSOR_ID` / the hostname and `--location` /
    `SYNAPSE_SENSOR_LOCATION`, and announces id + location + agent version +
    `os/arch` in the accept's `session_id` as
    `<sensor_id>|<location>|<agent_version>|<os/arch>` before the random suffix
    (`pcapoverip.FormatSessionPrefix` / `ParseSensorIdentity`). Not a wire change:
    `session_id` was already free-form and capped. Fields are sanitised of the
    separator and of control bytes and individually clipped, and a prefix with no
    separator still parses as a bare sensor id, so session ids from older sensors
    keep working.
  - **`GET /api/v1/sensors` and `GET /api/v1/sensors/{id}`** — the connected
    sensors: `sensor_id`, `location`, `remote_addr`, `link_type`, `filter`,
    `connected_at`, `packets`, `bytes`, `drops`, `pps`, `bps`, `last_packet`,
    `state`, plus `agent_version` / `os_arch` / `session_id` / `source_name`. The
    collector's own view of its peers, joined with the live counters of the
    matching Manager row. Read-only (a sensor is added and removed by connecting
    and disconnecting) and loopback-only like the rest of the state surface
    (§21, `TODO(#58)`). Wired through a new `api.SensorStatusProvider` — a
    twelfth `api.New` parameter, appended so existing arguments do not move;
    `nil` yields `[]` / `404`, never `503`.
  - **`events.SensorConnected` / `events.SensorDisconnected`** are now actually
    published, from `Collector.OnConnect` / `OnDisconnect` hooks in
    `cmd/synapsed` (the hooks keep `internal/capture` off the event bus). Both
    were already in the frozen `event-envelope-v1` enum — nothing was added.
  - **`synapse-sensor gen-cert`** writes a self-signed ECDSA P-256 pair (cert
    `0644`, key `0600`) and prints its SHA-256, so a testing collector can be
    stood up without an `openssl` incantation; the certificate is its own CA, so
    the `.crt` doubles as the sensor's `--ca`. No certificate-management
    subsystem was added — production provisions from its own PKI, and
    `docs/api.md` documents the equivalent `openssl req`.
  - `synapse-sensor` with no subcommand now prints its build stamp and exits 0
    instead of exiting 1 with a "not implemented" notice.
  - Config: `capture.collector` with `listen` / `cert_file` / `key_file` /
    `token_file` / `client_ca_file` / `max_sensors` / `authorized`, validated by
    `config.ValidateCollector`; `SYNAPSE_COLLECTOR_LISTEN` and
    `SYNAPSE_COLLECTOR_TOKEN` env overrides; `capturewire.BuildCollector` /
    `ResolveCollectorToken`; sample `contrib/config/synapse.collector.json`.
  - Tests: collector registration / streaming / goodbye-removal, a rejected
    token, mTLS required (negative **and** positive), the `max_sensors` cap,
    five concurrent sensors under `-race`, the identity codec round trip and its
    legacy form, the config rules, the API routes, a `synapse-sensor` hello-meta
    assertion and a goroutine-leak check, and a full
    sensor → collector → pipeline → classification end-to-end test.
  - Docs: ADR 0018, `docs/api.md`, `docs/architecture.md`, `README.md`,
    `docs/opnsense-sensor.md`, `contrib/opnsense/README.md`,
    `contrib/config/synapse.annotated.md`, and PROTOCOL.md §6's "not wired yet"
    paragraph retired. Still open: sensor `flow` / `feature` modes (#45) and the
    sensor-topology view (#46).
- **Model activation workflow + audit log** (issue #36, EPIC Phase 4;
  [ADR 0022](docs/adr/0022-auditable-model-activation-workflow.md)). The audit
  log was write-only and `ML ▸ Models` was a placeholder, so the one action
  PROJECT.md §28.10 singles out as requiring a deliberate human step had no
  operator surface and left no inspectable trail. Both are now real.
  - **`internal/audit` gained a read path.** `Tail(n, Filter)` returns records
    **newest first**, seeking to EOF and scanning backwards in 64 KiB chunks.
    Bounded twice: `MaxTail` caps the result at 1000 records (`DefaultTail` 100),
    and `MaxScanBytes` stops the scan 8 MiB back from EOF, so the whole file is
    never read and request cost does not grow with the log. A torn trailing line
    from a crash mid-append is skipped, not fatal; a log file that does not exist
    yet reads as empty, not an error.
  - `GET /api/v1/audit` — read-only, `limit` (default 100, max 1000),
    `subject_type=`, `subject=`, `event=`, `from=`/`to=` (RFC3339, inclusive),
    reusing the existing `limitParam` / `parseTimeRange` helpers. The response
    echoes `limit`, `max_limit` and `scan_bytes_cap` so a client can say what it
    is not showing.
  - **Append-only forever.** `GET` is the only method routed at `/api/v1/audit`;
    `POST`/`PATCH`/`DELETE` return `404` and always will. An audit trail an
    operator can curate after the fact records nothing worth reading (§21). The
    trail is sensitive operational history and inherits the loopback-by-default,
    unauthenticated posture of the rest of the API until issue #58.
  - **`Filter` is generic over subject types.** `subject_type` is compared as an
    opaque string and never validated against an enum, so §21's fourth category
    — human label changes, arriving as a `review` subject type with issue #42 —
    becomes readable and filterable the moment it is first written, with no
    change to the reader, the route or the UI's filter chips (which derive
    themselves from the records).
  - **SPA:** `ML ▸ Models` replaces the "Planned — Phase 2" placeholder with the
    §19.12 field set — registry table (status pill, parameter count, artifact
    size, short content hash, live-in-runtime), detail pane with schemas and I/O
    sizes, a read-only architecture breakdown, training dataset ids, metrics, the
    confusion matrix, lineage as a tree (§15), the per-model audit trail, and a
    global audit view with a chip per subject type. `architecture` and `metrics`
    are bundle pass-throughs and are parsed defensively — an unreported metric
    reads as missing, never as zero.
  - **Activation is confirmation-gated (§28.10).** **Activate** opens a
    confirmation that names the model, states plainly that it will become the
    primary classifier for *all live traffic*, names what it replaces, lists the
    content hash / parameter count / artifact size / provenance, and warns that
    the action is audited and does not survive a restart. **Deactivate** confirms
    the heuristic will be restored. A `409` (bundle no longer loads, no longer
    validates, or cannot be compiled) is surfaced **verbatim**. There is
    deliberately no "auto-activate on register", no "activate newest" and no bulk
    activate — §28.10 forbids the mechanism, so the UI offers no switch that
    could become one.

- **Human review queue and curated datasets** (issues #42 and #64, EPIC Phase 5;
  [ADR 0021](docs/adr/0021-human-review-loop-and-curated-datasets.md)). The
  `capture → classification → human review → curated dataset` half of
  PROJECT.md §16's lifecycle now exists end to end. #64's "active-learning review
  queue" is folded in and closed here as the queue's `uncertainty` ranking. No
  `event-envelope-v1` change — `ReviewUpdated` was already a member of the frozen
  enum (§28.5-6).
  - **The §16 invariant is enforced structurally, not by convention.** "Always
    retain the original model prediction separately from the human-reviewed
    label" is a safety property, so the prediction lives in an *unexported*
    `prediction` value inside `review.Review` with no exported constructor and no
    setter, and the only mutator — `Put(flowID, state, label, note)` — has no
    prediction parameter for a caller to fill. The store captures the verdict
    itself, once, on a flow's first review, and copies it forward untouched
    afterwards. On the wire, `predicted_class` / `predicted_score` / `model_id`
    are read-only and the write body rejects them as unknown fields (`400`). A
    correction can add information; it can never destroy the model's claim.
  - `internal/review` — the review store. One JSON file per reviewed flow under
    the new `review.directory` (atomic temp-file+rename, corrupt-file tolerant,
    loaded on start), fronted by an RWMutex-guarded memory index, mirroring
    `internal/training`. A record carries the five §16 states
    (`unreviewed` | `correct` | `incorrect` | `unsure` | `ignored_pattern`), the
    human label, the frozen prediction, `reviewer` (`"local"` until #58), a note,
    timestamps and a `history` of superseded decisions so a correction is
    traceable. Deliberately **not capped**: reviews are human-paced, and
    hand-labelled ground truth is the most expensive data in the system.
  - **Per-state rules,** because a state either asserts a class or it does not.
    `correct` derives its label from the prediction (a differing `human_label` is
    a `400` pointing at `incorrect`); `incorrect` **requires** a
    `traffic-classes-v1` class and it must differ from the prediction;
    `unsure`, `ignored_pattern` and `unreviewed` must carry no label —
    `ignored_pattern` means "stop showing me this", not "this is class X".
    Writing `unreviewed` un-reviews a flow and returns it to the queue with its
    history intact.
  - **Active-learning ranking (#64).** `GET /api/v1/review/queue?sort=uncertainty`
    orders by **smallest margin** (`p_top1 - p_top2` over the authoritative
    model's 7-class vector, normalised by its sum first), reported as
    `uncertainty = 1 - margin` with normalised Shannon entropy and the two
    contending class names alongside — so the flows the model is least able to
    settle reach a human first, and the UI can say why. A uniform vector ranks
    first (margin 0, entropy 1); a verdict with no usable vector is flagged
    `scores_available: false` and treated as maximally uncertain rather than
    hidden. `sort=disagreement` leads with ensemble disagreements;
    `sort=recent` is the default. A flow leaves the queue on a terminal decision
    (`correct` / `incorrect` / `ignored_pattern`); **`unsure` stays in**, with its
    note carried forward.
  - REST `internal/api/review.go`: `GET /api/v1/review/queue`,
    `GET /api/v1/review` (filter by `state`), `GET /api/v1/review/stats` (counts
    per state), `GET /api/v1/review/{flow_id}`, and
    `PUT`/`POST /api/v1/review/{flow_id}` (`201` first review, `200` correction).
    `400` on an unknown state or a non-class label — the error echoes the valid
    set; `404` when the flow has no stored classification, because you cannot
    review a verdict the bounded ring has already evicted. The queue reuses the
    shared `parseClassFilters`, so `class` / `model` / `min_confidence` /
    `disagreement` mean exactly what they mean on `/api/v1/classifications`. The
    write routes are loopback-only and unauthenticated for now (`TODO(#58)`).
  - **Curated datasets — the `human_review` gate is open.** `dataset.Selection`
    gains `reviewed`: the rows come from the review store and the CSV `label`
    column carries the **operator's** label, so `labeling_source` becomes
    `human_review`. Only terminal, class-asserting reviews are eligible
    (`correct` → the confirmed prediction, `incorrect` → the correction);
    `unsure` and `ignored_pattern` are excluded, the latter opt-in-able via
    `include_ignored`, which labels those rows with the model's *unconfirmed*
    prediction and honestly records the cut as
    `human_review+model_prediction:<ids>` with a warning. Both build paths share
    one tail, so a curated cut keeps every existing guarantee: immutability, the
    content hash over the CSV bytes, deterministic row order, `parent_datasets`
    lineage, and the zero-rows / one-class / 20-row refusals. `disagreement`
    combined with `reviewed` is refused rather than silently ignored.
  - **Config:** `review.directory` (default `./data/review`), overridable with
    `SYNAPSE_REVIEW_DIR`; an empty value is rejected at load.
  - **Audit and events:** every write appends one
    `{subject_type:"review", subject:"<flow id>", event:"ReviewUpdated"}` line to
    `audit.log` — the "human label changes" record PROJECT.md §21 asks for —
    carrying both the human label and the prediction, and publishes a
    `ReviewUpdated` envelope on the live bus.
  - **SPA:** a new `LIVE ▸ Review` view (`#/review`) with the sort selector, a
    per-state stats strip, and one row per queued flow showing the tuple, the
    model's prediction with its confidence, the margin/entropy read-out when
    sorting by uncertainty, and controls for all five states plus a class picker
    and a note field. The model's prediction sits **next to** the human label at
    all times and never replaces it — the invariant made visible. A
    "create curated dataset" action prefills the ML ▸ Datasets form with a
    `reviewed` selection, and that form gained `reviewed` / `include_ignored`
    checkboxes. The dataset honesty banner and the `labeling_source` badge now
    tell the truth for all three cases, and the **Flow Inspector**'s
    human-review section (§19.3) is live instead of a Phase-2 stub.
    `#/detections` is untouched — it remains a "Planned — Phase 5" placeholder,
    since nothing emits `AlertCreated` yet.

- **Downloadable investigation reports** (issue #66, EPIC Phase 5;
  [ADR 0023](docs/adr/0023-downloadable-investigation-reports.md)). An operator
  can now hand an investigation to someone else as one self-contained artefact —
  a ticket attachment, an e-mail to a peer team, the record next to an incident
  write-up (PROJECT.md §19.3, §19.4).
  - `GET /api/v1/reports/host/{ip}?format=json|html&from=&to=` — a host
    investigation report. `{ip}` is re-parsed with `net/netip` (`400` on a
    non-literal, `404` on an unobserved address).
  - `GET /api/v1/reports/range?from=&to=&format=&class=…` — the same artefact for
    a time window. Both routes reuse the `/api/v1/classifications` filter dialect
    (`class`, `model`, `min_confidence`, `disagreement`) verbatim and echo the
    applied predicates back in the report.
  - Both formats are downloads: `Content-Disposition: attachment; filename=…`,
    plus `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. The
    filename's scope segment is reduced to `[a-z0-9._-]`, so a packet-derived
    address can neither escape the quoted header parameter nor produce a
    traversal when the browser writes the file.
  - **New package `internal/report`.** Builds the artefact from live state
    (`storage.Store`, `internal/insight`, `inference.Runtime`) and renders it.
    Deterministic given the same state, so its content is unit-testable. It
    carries the generation time and the exact daemon version/commit/build date,
    the scope, the host profile, the in-scope class breakdown, the timeline, top
    peers/ports/protocols, the active model set, and the **notable flows** —
    every verdict that disagreed across models or was not `normal` — each with
    its tuple, timing, volume, **per-model outputs** and the named raw
    `flow-features-v1` values behind it, plus a legend so those values are
    interpretable offline.
  - **Honesty rules, enforced structurally.** `coverage` (machine-readable) and
    `notes` (prose) come before the findings.
    - Behavioural baselines and anomaly scores are Phase 7: the report always
      carries an explicit "not available in this build" warning stating that the
      absence of an anomaly finding does **not** mean the traffic was checked
      against a baseline and found normal. No empty chart that reads as clean.
    - `storage.Mem` evicts and `insight`'s host map and top-N lists are capped, so
      the report reads their eviction/prune counters and says **"PARTIAL VIEW"**
      naming the limit whenever one bit: store eviction, the 5000-verdict scan
      budget filling, a window starting before retention, host eviction, a pruned
      top-N, dropped observations, late timeline samples, or a verdict that
      outlived its flow record (marked per flow, never zeroed).
    - The notable-flow table is capped at **500** (`limit=`, max 2000) and says
      **"TRUNCATED"** with both counts when the cap bites.
  - **HTML output is one standalone file** rendered with `html/template`: a single
    inline `<style>` in the project's dark palette plus a `@media print` block, no
    external stylesheet, no CDN, no `<script>`, no `<img>`, no webfont — it opens
    from `file://` with no network access. `html/template` is the injection
    control, not a style choice: every value in a report is packet- or
    request-derived and therefore untrusted (§21, §28.11). A test feeds eleven
    hostile payloads (`<script>alert(1)</script>`,
    `"><img src=x onerror=alert(1)>`, CSS/CRLF/`<title>` breakouts and more)
    through the host address, peer address, protocol, sensor, close reason, model
    ID, class name and filter echo, and asserts a tag-level scan of the output
    finds no element or attribute outside an allowlist; a negative control renders
    the same template through `text/template` and asserts the payload *does*
    survive there.
  - **SPA:** a **Download report** control (HTML / JSON) on
    `#/investigate?host=<ip>` that carries the currently-brushed timeline range
    and the active class/disagreement filters, and a per-row `report` link on
    `#/hosts`. Rendering stays server-side; both are plain `<a href>`
    navigations, so the browser's own download path is used. The client grows
    ~0.35 KB gzip.

- **Dataset Explorer** (issues #37 and #67, EPIC Phase 4;
  [ADR 0020](docs/adr/0020-dataset-explorer-and-in-tree-pca.md)). Visualises a
  materialised dataset's structure (PROJECT.md §19.11): per-feature
  distributions and 24-bucket histograms, the label distribution cross-checked
  against the manifest, the 48×48 Pearson correlation matrix, protocol and
  destination-port splits, a bounded outlier list, and a PCA projection. #67's
  "PCA / UMAP feature-space views" is folded in and closed here; UMAP is
  deferred.
  - `GET /api/v1/datasets/{ref}/stats` — the whole bundle as JSON, read-only.
    Computed from the immutable `dataset.csv` on disk and cached by the
    version's `content_hash`, so repeated calls are cheap and byte-identical.
    `pca.projection` is capped at 5000 rows (`projection_sampled` flags a
    fixed-stride sample); the correlation matrix is a fixed 48×48.
  - **In-tree PCA, stdlib `math` only.** The standardised covariance is the
    correlation matrix, decomposed by a bounded, deterministic cyclic Jacobi
    eigensolve; the top 3 sign-fixed eigenvectors, their explained-variance
    ratios and every row's projection are returned. No BLAS/LAPACK, no new
    dependency (PROJECT.md §27, §28.16).
  - **Outlier rule:** a row whose largest per-feature `|z-score|` exceeds 6.0,
    reported worst-first with its top offending features, list capped at 100.
  - **SPA:** a new `ML ▸ Dataset Explorer` view
    (`#/dataset-explorer?ref=<id>@<version>`, reachable from each row's
    **explore** link on ML ▸ Datasets): label bar, canvas correlation heatmap,
    a grid of 48 expandable mini-histograms with quartile markers, an SVG PCA
    scatter with a PC-axis selector, protocol/port bars and the outlier table.
    All PCA maths is server-side; the client grows ~4 KB gzip.
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

- `make test` now covers the OPNsense packaging contract: the `.pkg` file name and
  the pkg-ABI→GOARCH mapping are lifted out of both `install.sh` and
  `scripts/package-opnsense.sh`, run under `/bin/sh` and asserted equal, and the
  `SHA256SUMS` parser is exercised against every line form. Previously only
  `make opnsense-pkg` checked any of this.
- New development harnesses under `contrib/opnsense/tools/` (not packaged):
  `check-plugin.sh` (php -l, XML, `sh -n`, and the two below),
  `render-templates.py` (renders every configd template with Jinja2 against a mock
  context — 17 scenarios, including the interface lookup in all four states),
  `test-sensor-model.php` (25 model-validation cases against real key material),
  and `check-install-derivation.sh` (`install.sh` versus the real `dist/*.pkg`).

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

- **Three audit-coverage gaps in the model lifecycle** (issue #36). Each made the
  log disagree with reality, and each was only visible once the log could be read
  back as a sequence of state changes:
  - Activating B while A was active demoted A in the registry but wrote no record
    under A, so A's most recent audit line still said *activated* while it was
    not live. `POST /api/v1/models/{id}/activate` now writes A's implicit
    `ModelDeactivated` under A's own subject, ordered before B's activation.
  - A model active at shutdown is reconciled to `deactivated` on restart — a real
    state change that was never audited. `registry.Reconciled()` now reports the
    demoted IDs and `cmd/synapsed` audits each; the reconciliation is persisted,
    so this is written once rather than on every boot.
  - `ModelRegistered` was appended on every boot for bundles the registry already
    knew (`Register` is idempotent), burying real changes in duplicates. The
    startup sweep now audits only a genuinely new registration.
  - Smaller honesty fix: deactivating an entry that was never the live primary is
    a legal no-op, and its record no longer claims it "restored the heuristic".
- The stale `getModels()` client helper claimed `Promise<ModelInfo[]>` while
  `GET /api/v1/models` returns `{models, runtime}`. It had no call sites; it is
  now correctly typed and used by `ML ▸ Models`.
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
