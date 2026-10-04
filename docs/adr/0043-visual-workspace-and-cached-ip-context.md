# 0043 — Visual workspace and cached IP context

**Status:** Accepted, 2026-10-04.

## Context

Operators need to see relationships between flows/assets, understand model
results, prepare reproducible training, and monitor operations in Grafana.
Unbounded external lookups must not delay capture or scoring. Existing schemas,
model activation gates and the external-worker training boundary remain fixed.

## Decision

Use native React/SVG/CSS against existing versioned endpoints for the graph,
inference schematic, charts and guided recipe preparation. Bound the graph and
label its sampled coverage. Actual observations accompany schematic topology;
unmeasured neuron activations, firewall decisions and DNS packet semantics are
explicit gaps. No graphing dependency or Go dependency is added.

Add an opt-in `internal/enrichment` service owned by the daemon, attached to the
API through a setter and closed at shutdown. The read-only batch endpoint accepts
only IP literals already present in the investigation index. The service uses a
bounded cache, bounded queue, four workers, timeouts and a shared start-rate limit.
It supplies PTR, geolocation and network-registration context without touching
flow features or inference. Private/special-use addresses never go to external
geo/registration services; private PTR queries use the configured DNS resolver.

Geography uses an operator-configurable Country-compatible service, supporting
self-hosting. Registration uses RDAP bootstrap over HTTPS with a restricted
regional-registry redirect allowlist. Responses are size-bounded and reduced to
specific non-contact fields. TTLs cache successes and failures; expired data is
marked stale during refresh. HTTP 429 starts a shared provider cooldown and
honors longer bounded Retry-After values. The cache is in memory, not durable.

Extend `/metrics` with a fixed allowlist of reported training values, bounded
per-run/per-model series, aggregate dataset/model state and sensor transport
counters. Do not turn arbitrary recipe keys, progress strings or host addresses
into metric labels. Training metrics remain latest-value gauges, while packet,
record and delivery counters retain their distinct units. Two portable Grafana
dashboards consume these metrics without requiring plugins.

## Consequences

- Capture and scoring never wait on DNS, geolocation, registry services or UI.
- Deployment must explicitly enable external context, and may self-host geo or
  disable providers independently. Enrichment configuration requires restart.
- Names, flags and registration data are advisory context, never verdicts or
  physical-location guarantees. Lookup failures remain visible.
- Provider limits can delay registration results; negative caching/cooldown
  protects both the service and external providers.
- Prometheus retains sampled wall-clock training history; the console retains
  full reported epoch history. Missing training metrics are not synthesized.
- Newest-100 per-run/model detail bounds instantaneous cardinality; run IDs
  still accumulate historical series under Prometheus retention.
