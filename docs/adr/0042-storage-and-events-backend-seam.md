# 0042 — A backend seam for storage and events

**Status:** Accepted, 2026-09-02 — a shared `storage.Store` conformance suite
(`internal/storage/storagetest`) and an `events.Sink` interface + documented
relay pattern. No new backend and no new dependency (EPIC Phase 8, #8).

## Context

Phase 8 (#8) lists a ClickHouse history backend (#51) and a NATS/Kafka message
bus (#52), each qualified in PROJECT.md §20/§17/§26 as "only when measurements
require it". Neither measurement exists yet, and both clients would be the first
third-party Go dependencies (CLAUDE.md — a spec-level decision).

What can be done now, without a dependency or a premature backend, is to make
the two extension points explicit and *testable*, so that when #51/#52 land they
are drop-ins against a fixed contract rather than a re-derivation.

## Decision

### Storage: a shared conformance suite, not a second implementation

`internal/storage/storagetest` exports `RunConformance(t, Factory)` where
`Factory = func(flowCap, classCap int) storage.Store`. It exercises the whole
`Store` contract: put/get round-trip and unknown-id miss; `FlowHistory`
oldest-first ordering and returned-slice independence; `RecentFlows`/
`RecentClassifications` newest-first and `limit<=0`/over-limit semantics;
bounded capacity with `FlowsEvicted`/`ClassEvicted` counted and the newest
record surviving; a non-empty `Stats().Driver`; idempotent `Close`.

`internal/storage` runs it against `Mem` from an external `storage_test` package
(the suite imports `storage`, so the runner cannot live in `package storage`).
A future `internal/storage/sqlite` or `internal/storage/clickhouse` adds exactly
one test — `storagetest.RunConformance(t, newThatStore)` — and inherits the bar.

`config.Storage.driver` already selects the backend at startup and already
rejects unknown values; this ADR does not change it. The `Store` package doc now
names the conformance suite as the encoded contract.

### Events: a `Sink` interface and a documented relay, no bus rewrite

`events.Sink` is the write side — `Publish(Type, any)` — which `*Bus` already
satisfies. Producers that might later target more than the in-process bus depend
on `Sink`; today the only implementation is `*Bus`.

A message bus (#52) attaches as an **ordinary subscriber**: a relay goroutine
calls `Bus.Subscribe`, serialises each `Event` (already the frozen
`event-envelope-v1` shape) and forwards it to the external transport. The
existing bounded-queue backpressure applies to the relay like any other slow
consumer, so a stalled broker drops relayed events and never touches ingestion
(§17, §22). The only new in-tree code at that point is a fan-out `Sink` over
`{*Bus, relay}`, which lives with the relay, not in this package. A test
(`TestSubscriptionRelaysIntoAnotherSink`) pins the pattern.

## Alternatives considered

- **Add the ClickHouse / NATS clients now, gated off by config.** Rejected:
  §26 says not before a measurement, and it spends the zero-dependency budget
  ahead of need. The seam here makes that a later, smaller change.
- **A `MultiSink` / fan-out type in `internal/events` now.** Rejected as
  speculative: there is nothing to fan out to. `Sink` alone is enough to keep
  the seam cheap.
- **Put `RunConformance` in `package storage`.** Impossible — import cycle
  (`storagetest` → `storage`). Hence the sub-package.

## Consequences

- No behaviour change and no dependency. `make test` gains the conformance run
  against `Mem`.
- #51 and #52 each become: implement the interface, add one conformance/relay
  test, register the driver/transport in config. The design questions
  (dependency approval, when the measurement justifies it) are unchanged and
  still theirs to answer.
