# 0039 — A hand-crafted per-host behavioural fingerprint and similarity search

**Status:** Accepted, 2026-09-02

## Context

PROJECT.md §30 lists "per-host behavioral embeddings" as a future idea — *"learned
per-host embeddings as features or for similarity search"* (issue #63, EPIC Phase
7). The operator value is concrete: given one suspicious host, surface the other
observed hosts that *behave the same way* — a lateral-movement or botnet-peer
lead that a per-flow classifier cannot give, because it never looks across a
host's whole activity.

A **learned** embedding needs a trained model, a training corpus of host
activity, and an `internal/nn` path that can run it — none of which exist yet.
But the *similarity-search* half is deliverable now: `internal/insight` already
maintains bounded per-host aggregates (flow direction, volume, the port/peer
counters, protocol mix, the 7-class mix, the disagreement and anomaly rates), and
those are enough to build a useful behavioural summary without training anything.

This mirrors how the anomaly model shipped (ADR 0037): a transparent stand-in
first (`Heuristic` / here, a hand-crafted vector), the learned version as a
drop-in replacement later.

## Decision

### A frozen, hand-crafted fingerprint vector

`(*host).fingerprint()` produces a fixed-length `[]float64` of **scale-free
ratios** — every dimension is in a bounded range and independent of how many
flows the host has, so two hosts of very different volume are still comparable:

| group | dimensions |
|-------|------------|
| evidence weight | `flow_volume` = `log1p(flows)` squashed (not behaviour; lets a UI de-emphasise thin fingerprints) |
| direction | `initiator_bias`, `upload_bias`, `packet_out_bias` |
| packet shape | `avg_pkt_in`, `avg_pkt_out` (÷ MTU, squashed) |
| spread | `peer_fanout`, `port_fanout` (÷ flows, squashed), `port_entropy`, `peer_entropy` (normalised Shannon entropy of the counters — a scanner's flat spread → ~1, a server's one port → ~0) |
| protocol | `proto_tcp`, `proto_udp`, `proto_icmp` (share of flows) |
| verdict mix | `class_<name>` for each frozen `traffic-classes-v1` class (7) |
| model signals | `disagreement_rate`, `anomaly_rate` (= exceeded / scored, 0 with no anomaly model) |

The dimension list is **frozen and ordered** like a feature vector: a new
dimension is a `fingerprint-v2`, not an edit, so a fingerprint stored or compared
later stays meaningful. The class dimensions are read from the frozen schema so a
new class cannot silently shift the layout.

It is **not normalised across hosts** (no fitted mean/std): the ratios are
already comparable, and a fitted normaliser would make a fingerprint depend on
which other hosts happened to be in the map.

### Cosine similarity over the live host set

`Index.SimilarHosts(ip, limit, minFlows)` computes `ip`'s fingerprint, then the
cosine similarity to every other tracked host with at least `minFlows` terminal
flows (default 5 — below that a fingerprint is mostly noise), sorted nearest
first. It is an O(hosts × dims) scan under the read lock — a few thousand hosts ×
22 dims per request, on an operator-facing low-QPS route, so no index or cache is
warranted (the same reasoning as `GET /api/v1/drift`).

`GET /api/v1/hosts/{ip}/similar` returns the fingerprint (named dims + raw
vector), the `min_flows` used, the neighbour list (`ip`, `cosine`, `flow_count`),
and a `method` string stating plainly that this is a hand-crafted fingerprint and
a cosine lead, **not a learned embedding and not a verdict**. Auto-covered as
`RoleViewer` by the method+path role table.

### What this is not

- Not a detection. A high cosine to a known-bad host is a *lead*; the response
  says so and the SPA frames it as one.
- Not a feature fed back into the classifier (§30's other use). That needs the
  fingerprint to be stable across restarts and versions; this one is recomputed
  from the live, lossy aggregates.
- Not learned. The upgrade path is a trained encoder whose output replaces
  `(*host).fingerprint()` — the `Fingerprint` / `Similarity` types and the route
  do not change.

## Consequences

- The Investigate host view gains a "Similar hosts" panel; an analyst pivoting
  from one compromised host can see its behavioural cohort in one call.
- The fingerprint reuses existing aggregates, so it costs nothing on the packet
  path and nothing in memory beyond the request.
- When a learned per-host embedding is built (its own issue), it slots in behind
  the same API; a `fingerprint-v2` covers any dimension change.
- `counter` gained `distinct()` and `entropyNorm()`, both useful beyond this.
