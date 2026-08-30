<!--
Thanks for contributing to SynapseIDS.

Read CONTRIBUTING.md. PROJECT.md is the authoritative spec — if this change
contradicts it, say so explicitly below. Changing the spec is allowed; doing it
by accident is not.
-->

## What this changes

<!-- One or two sentences. What is different after this is merged? -->

## Why

<!-- The reasoning, not the diff. What was missing or broken, and which
alternatives you rejected. -->

Closes #

## How to verify

```bash

```

<!-- The commands a reviewer runs, and what they should see. For a pipeline
change, include the manual replay check. -->

## Definition of done

- [ ] Implementation is complete — no reachable stubs
- [ ] Tests exist where appropriate
- [ ] `make fmt vet test build` passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] User-facing behaviour documented in `docs/`
- [ ] Malformed input yields a counted skip or a populated result, not a panic
- [ ] Commits are small, cohesive and conventionally prefixed

## Checks that apply

<!-- Tick what is relevant; delete the rest. -->

- [ ] **Cross-compilation** still works — `make build-linux`, or at least
      `CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build ./...`
- [ ] **No cgo dependency** added
- [ ] **No new third-party dependency** — or it is justified here and pure Go
- [ ] **Pipeline boundaries kept** — measurement stays in `flow`/`features`; the
      API and renderers consume results, they don't compute them
- [ ] **No released schema reordered** — `flow-features-v1` / `traffic-classes-v1`
      order and meaning are frozen; a new need is a new version
- [ ] **Golden fixtures** regenerated deliberately (`-update`) and reviewed, if
      feature extraction changed
- [ ] **Hot path stays off the slow path** — storage / WebSocket work does not
      block the packet loop
- [ ] **Defensive only** — no exploitation, counter-attack, or traffic modification
- [ ] **Branch** is `feature/…` / `fix/…` off `develop` (or `hotfix/…` off `main`)

## Anything a reviewer should know

<!-- Known gaps, follow-up work, decisions you want a second opinion on. -->
