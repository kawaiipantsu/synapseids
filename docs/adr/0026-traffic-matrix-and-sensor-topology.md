# 0026 — The traffic matrix is a bounded top-N, and sensor scoping is only as real as flow attribution

**Status:** Accepted, 2026-08-31

## Context

Two Phase 5/6 issues close together because they are the same shape of problem —
a relationship view over data that already exists, feeding one "scope everything
to this thing" interaction.

- **Traffic matrix** (issue #68, PROJECT.md §19.4-5) — a who-talks-to-whom matrix
  over observed hosts: per ordered pair, the flow count, the byte count and the
  class mix, so an attack pair is visible as a hot cell.
- **Sensor topology** (issue #46, PROJECT.md §19.15) — sensors grouped by
  location/environment, where *"clicking a location or sensor should be able to
  scope other UI views"*.

Each ran into one hard question, and in both cases the honest answer is narrower
than the issue title suggests. This ADR records both answers.

## Decision 1 — the matrix is a bounded top-N of pairs, and says so

### Why not a matrix

The literal reading of "traffic matrix" is a hosts × hosts grid. `internal/insight`
already caps its host map at 2048 (ADR 0016), and 2048 hosts is up to **~4.2
million ordered pairs**. At the ~200 bytes of state and key each pair needs, that
is hundreds of megabytes of packet-derived, attacker-influenceable state (§21,
§28.11) — and a single `/16` sweep would create it deliberately. A full matrix is
not a thing this process can hold.

So `internal/insight/matrix.go` maintains a **bounded table of the heaviest
ordered `(initiator, responder)` pairs**, and every response states that it is one.

| structure | default cap | policy on overflow | counter |
|---|---|---|---|
| pair table | **4096 pairs** | drop the lighter **half**, ranked by `(flows, bytes)` | `pairs_evicted` |

4096 is two orders of magnitude below what the host cap permits, and costs well
under a megabyte. Direction is the flow's own: `flow.Key` is direction-normalized,
so the initiator is the side that opened the conversation, and `(A,B)` and `(B,A)`
are separate cells that are never merged.

Pruning the lighter half in one pass every `max/2` inserts is amortised, the same
trade-off `pruneHosts` makes. Two consequences are deliberate and documented
rather than hidden:

- **A pair that is evicted and later seen again restarts from zero**, so a light
  pair's counters can undercount. Heavy hitters — the reason a matrix exists — are
  never evicted while they stay heavy. The flow log and the host profiles remain
  the systems of record for anything this derived view drops.
- **Eviction ranks by flow count first, bytes second.** A conversation-count
  matrix is what answers "who talks to whom", and it is also the default list
  order, so the retained set and the default view agree. The cost is that a single
  multi-gigabyte one-flow transfer sits in the prunable tail; `sort=bytes` still
  surfaces it while it is retained.

### The honesty flags

A top-N drawn as a grid invites the reader to believe it is complete, so the
response carries four separate signals and the SPA renders all of them:

- `partial` — the cap evicted at least one pair (or a filtered query's scan window
  was itself capped). **These are the heaviest pairs, not all of them.**
- `truncated` — `limit=` cut the list. Independent of `partial`: a limited view of
  a complete table is truncated but not partial.
- `pairs_evicted`, `tracked_pairs`, `total_flows` / `total_bytes` — so a client can
  size what it is *not* seeing.
- `source` — `incremental` or `scan` (below).

### Two sources, like the timeline

`GET /api/v1/matrix` is answered from the incremental table when unfiltered, and
folded on demand from the newest window of stored records when filtered
(`class`, `model`, `min_confidence`, `disagreement`, `sensor`, `location`,
`from`/`to`). This is exactly the split `GET /api/v1/timeline` already makes, for
the same reason: a table per filter combination would be unbounded. Both paths run
the *same* fold through the same `observationOf` projection, so a filtered matrix
and the incremental one are comparable rather than two different calculations.

### Measured cost

`Index.Observe` — the packet-path side — is **untouched** by this change: the
matrix reads fields the observation already carried, so nothing new is copied and
no new send happens. The fold runs on the aggregator goroutine.

Measured on this machine (13th-gen i9, `go test -bench`, `-benchtime 2s`):

| operation | cost | allocations |
|---|---|---|
| `Observe` (packet path) | **77 ns/op** | **0** |
| `apply` (full aggregator fold, host profiles + timeline + matrix) | 245 ns/op | 0 |
| `pairTable.observe` alone, existing cell | **38 ns/op** | **0** |
| `pairTable.observe`, every record a new pair (pessimal, prunes every 512) | 602 ns/op | ~0 (one slice per prune, ≈210 B/op amortised) |
| `Index.Matrix(200)` over 4000 tracked pairs | 1.33 ms/op | 659 |

So the matrix adds **~19 ns to the per-record fold** (226 ns in ADR 0016 → 245 ns
here) and nothing at all to the packet path.
`TestMatrixObserveDoesNotAllocate` pins the zero so a regression fails the build.

The read is the expensive side, and it holds the read lock — which blocks the
aggregator's write lock, not the packet path (`Observe` takes no lock). At 1.33 ms
worst case and an aggregator that drains at ~4 M records/s, a poll stalls the
queue by well under its 8192 depth. The 4096-pair cap is what bounds this;
`sort=`/`limit=` do not widen it.

### Deliberately not done

`MaxPairs` is not configurable, exactly like `MaxHosts` and `MaxKeys` before it —
the daemon constructs `insight.New(insight.Options{})`. Making the read-model caps
tunable is one coherent change for later, not three ad-hoc knobs.

## Decision 2 — sensor scoping is wired where attribution is real, and refused where it is not

### Can a flow be attributed to a sensor today? Only partly.

This had to be answered before any filter was written, and the answer is:

- **`flow`- and `feature`-mode sensors: yes.** The collector tags their record
  frames with the sensor id (`internal/capture/records.go`), and
  `internal/pipeline` copies it onto `storage.Classification.Sensor`.
- **`raw`-mode sensors: no.** Their packets are merged into `capture.Manager`'s
  single output channel, and neither `packet.Packet` nor `flow.Record` has a sensor
  field. By the time a flow record exists the origin is gone, and the row is
  labelled `"local"` — the same label a local NIC or a PCAP replay gets.
- **`storage.FlowRecord` has no sensor id at all** — only `sensor_mode` and
  `sensor_flow_id` (issue #45), which are provenance *class*, not identity.
- **Location is never stored.** `pcapoverip.SensorRecord` carries it and the
  pipeline drops it.

Making raw-mode attribution work is a **data-plane** change, not an API one: it
needs sensor identity on the packet path *and* in `flow.Key`, because otherwise
two sensors observing the same 5-tuple merge into one flow record. That is a
deliberate change to a core type's semantics and it is not being done as a side
effect of a view (§28.4). **Deferred, and stated in the API rather than papered
over.**

### What was wired

One filter vocabulary, not two. `sensor=` and `location=` join `classFilters`, so
every route that already speaks the `class`/`model`/`min_confidence`/`disagreement`
dialect gains them: `/classifications`, `/hosts/{ip}/flows`,
`/hosts/{ip}/classifications`, `/review/queue`, `/reports/*`, `/matrix`, and
`/flows` (which previously took no filters at all, and now applies the scope via
the same flow→verdict join `/hosts/{ip}/flows` uses).

- `sensor=<id>` matches `Classification.Sensor` verbatim, and is deliberately
  **not** validated against the connected set: a disconnected sensor still owns its
  stored rows, and `sensor=local` is a legitimate scope for all locally-built
  traffic.
- `location=<name>` resolves through the *currently connected* sensors, because a
  location lives on the live session and is not stored on a row. It matches the
  exact string the topology response spelled — no case folding, because the
  response hands the client the value to send back, so there is nothing to guess.

**A location no sensor reports is a `400`, not an empty `200`.** An empty result
would be indistinguishable from "that location is quiet", and this is the class of
bug the issue asked to avoid.

### The topology response tells the client what it can scope

`GET /api/v1/sensors/topology` is a sibling of `/sensors` rather than a shape
change to it — `/sensors` is a flat list several views consume, and grouping is a
different question asked of the same facts. It carries per sensor:

```json
"flow_attribution": "records" | "none"
```

`records` means `sensor=`/`location=` really do filter that sensor's flows.
`none` means they would match nothing. The SPA reads this field and offers the
scope links only where they work; for a raw-mode sensor it renders a
`counters only` affordance with the reason. Each location also reports
`attributable_sensors`, and the document carries a one-sentence `scope_note` so a
UI can show the caveat rather than reinvent it.

Sensors reporting no location group under an explicit bucket:
`"location": "unassigned", "unassigned": true`. **No location is invented for the
sensor itself** — its own `location` stays `""`. Locations differing only in case
stay distinct groups, because merging them would mean choosing a spelling no
sensor sent. Named groups sort by sensor count then name; the unassigned bucket is
always last, so it reads as an exception rather than a peer.

Per-location aggregates are sensor count, running count, summed
pps/bps/packets/bytes/drops/records, newest `last_packet`, the distinct modes in
use, and a health verdict: `down` when nothing is running, `degraded` when a
sensor is not running **or any sensor is dropping** (§19.14 makes drops a
first-class signal), `ok` otherwise.

With no collector wired the route returns an empty grouping with
`"collector": false` — never a `503`, and deliberately distinguishable from a
collector nobody has connected to, which saves an operator debugging the wrong
thing.

`GET /api/v1/sensors/topology` is registered next to `GET /api/v1/sensors/{id}`;
Go's `ServeMux` prefers the more specific pattern, so the literal wins. A sensor
whose id were literally `topology` is unreachable by the by-id route and must be
read from the list — noted rather than worked around, because renaming the route
to dodge a pathological id is worse than documenting it.

## Consequences

- `internal/insight` grows one file, one `Options` field (`MaxPairs`), one map on
  the aggregator, three `Stats` counters (`pairs`, `pair_cap`, `pairs_evicted`,
  surfaced on `/api/v1/status` under `insight`), and one exported
  `MatrixAccumulator` for the on-demand path.
- `parseClassFilters` became a method on `*Server` so it can resolve `location=`
  through the sensor provider. Five call sites, mechanical.
- `#/sensors` replaces its Phase-6 placeholder; `#/matrix` is a new LIVE route.
  The heat grid is drawn on a canvas, like the Dataset Explorer's correlation
  matrix — 48 × 48 DOM cells re-rendering on a 2 s poll is a worse problem than one
  `fillRect` loop. Cells are tinted by the pair's *worst* (non-`normal`) class and
  shaded by `sqrt(share)` of the heaviest cell, so a mostly-benign pair with a few
  attack verdicts is still visible.
- The scoped Flow Log filters the live stream client-side on the verdict's own
  `sensor` field; a `location=` scope resolves once through the topology document.

## Verified against real traffic

`/var/www/projects/pcaps/nmap_scan.pcap` (68 810 packets, 1 176 flows) replayed
through the daemon, 90 tracked pairs, no evictions. The hottest cell is the one it
should be:

```
10.10.10.22 → 10.10.10.21   426 flows   9.4 MB   304 brute_force / 151 normal
```

and `class=brute_force` isolates it to 304 flows, every one to `10.10.10.21:3306`
— the MySQL brute-force run. Two live sensors (`edge-wan-1` at `wan` in `flow`
mode, `edge-dmz-1` at `dmz` in `raw` mode) group correctly, and the attribution
distinction holds end to end: `sensor=edge-wan-1` returns that sensor's own 36
flows, `location=dmz` returns an empty matrix — which is exactly why its
`flow_attribution` is `none` and the UI does not offer the link.

## Deliberately deferred

- **Raw-mode sensor attribution** — needs sensor identity on `packet.Packet` and
  in `flow.Key` (see above). Until then `sensor=`/`location=` are honest about
  covering record-mode sensors and `local` only.
- **Storing location on a row**, which would let `location=` resolve for a
  disconnected sensor. Needs the same data-plane work.
- **A drawn topology diagram.** §19.15 asks for grouping and scoping; the
  scoping interaction is the point, and a force-directed graph of two boxes would
  be decoration. Grouped panels carry the same information at a fraction of the
  code.
- **Configurable read-model caps** (see Decision 1).
- **Port-level cells.** A matrix cell is a host pair, not a host:port pair — the
  port dimension would multiply the cap pressure by the port space, which is the
  exact tail the bound exists to shed. Per-pair ports remain available through the
  host profiles and the flow list.
