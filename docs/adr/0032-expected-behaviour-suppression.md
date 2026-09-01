# 0032 — Expected-behaviour suppression between classification and detection

**Status:** Accepted, 2026-09-01

## Context

Validating on a live gateway (#102) surfaced a class of "false" alert that is not
a misclassification. The box under test runs a DarkWeb monitoring service: it
deliberately connects to known-malicious infrastructure all day, as its job.
`botnet_c2` and `scan` verdicts on that outbound traffic are *correct* — the
traffic genuinely has the shape the rules describe, and a trained model would
very likely agree. What is missing is the context that this host is authorised to
behave that way (issue #133).

The same problem hits any host that does vulnerability scanning, uptime probing,
backup replication or CDN health-checking. Without a way to express "expected",
the tool trains its operator to ignore it.

This is distinct from:

- **The threshold** (`min_confidence`, ADR 0027). That suppresses *low-confidence*
  verdicts. Here the verdicts are high-confidence and right.
- **A wrong rule.** Where a heuristic rule is simply bad it should be fixed or
  removed (as the `web_attack` byte-asymmetry rule was, #135), not papered over.
- **Behavioural baselines** (#47, #63). Those *learn* what is normal per host.
  This *states* it, declaratively.

## Decision

A declarative suppression layer in `internal/alert`, between the policy that
turns a verdict into a detection and the detection store.

1. **Suppress the detection, keep the classification.** A matched verdict is
   still scored by the runtime and still stored as a classification by the
   pipeline — `Store.Observe` runs *after* the pipeline has stored the row, so
   suppression cannot touch it. It stays visible in `/api/v1/flows`,
   `/api/v1/classifications` and the flow log. Only the detection is skipped: no
   `/api/v1/detections` row, no `AlertCreated`. An operator never loses the
   ability to audit what was hidden.

2. **Match on stable attributes only.** Source / destination address or prefix,
   destination port, traffic class. A rule that had to name the ephemeral port
   would be useless. Direction is expressed by *which* side you pin: `src` in a
   prefix suppresses outbound, `dst` suppresses inbound. Carrying an explicit
   capture-direction flag is a SYNPOIP change (#129) and not needed here.

3. **Never a silent no-op.** A rule with no matchers (it would suppress every
   detection), an unparseable address, an unknown or `normal` class, an
   out-of-range port, or a missing `note` is a **load error** — `config.Load`
   refuses to start. A rule that is well-formed but has matched nothing is
   reported per-rule on `/api/v1/status` (`alerts.suppress_rules[].matched == 0`)
   so it can be found and removed. `note` is required precisely so that report is
   legible.

4. **Not an allowlist for the classifier.** The runtime never sees the rules;
   it keeps scoring honestly. Suppression is a reporting decision. "Expected" is
   never fed back into a model.

5. **First match wins**, rules evaluated in config order, and the suppression is
   counted against that first rule. Aggregate count is
   `alerts.suppressed_by_rule`, kept separate from the threshold `suppressed`.

### Where the parsing lives

`internal/config` is a leaf package (docs/architecture.md) and must not import
`internal/alert` or `internal/schema`. So the CIDR / class / port validation is
implemented twice: `config.validateSuppressRule` at load, and
`alert.CompileSuppress` when the matcher is built (an embedder can construct a
`Policy` without going through config). `TestSuppressRuleParsingMatchesConfig`
pins the two to accept and reject exactly the same rules — a drift there is the
silent behaviour this ADR forbids.

## Consequences

- The tool is usable on a host that does security research: the operator writes
  a rule with a `note`, the verdict still shows in the flow log, and the
  detection feed stays signal.
- `alerts.suppress` is new config surface, defaulting to no rules — a fresh
  install is unchanged.
- `Stats` gained a slice (`suppress_rules`), so it is no longer a comparable
  struct; one test that compared it to the zero value now checks fields.
- Suppression runs on the alert aggregator goroutine, off the packet path, like
  every other part of `internal/alert`. Per-occurrence address parsing is done
  there, not in `Observe`.

## Alternatives rejected

- **A `suppressed: true` flag on the detection**, filtered out of the default
  list. Keeps the detection in memory and in the ring for no benefit, and a
  client that forgets the filter sees the noise the operator asked to hide.
- **Suppressing the classification too.** Loses the audit trail — the whole
  point of keeping it (requirement 1).
- **Learning it.** A different feature with a different failure mode (#47, #63);
  conflating "I declare this expected" with "the model learned this is normal"
  would make both harder to reason about.
