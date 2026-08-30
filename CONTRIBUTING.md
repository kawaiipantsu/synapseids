# Contributing to SynapseIDS

Thanks for looking. SynapseIDS is a Go network-intrusion-detection platform: a
capture/flow/feature/inference data plane, a versioned API, and a live web UI.

Read [`PROJECT.md`](PROJECT.md) first — it is the authoritative specification and
the engineering contract, and it carries a numbered "Coding Rules for Claude"
(§28) that applies to every contributor, human or agent. When the spec and the
code disagree, the spec wins; changing it is a deliberate act, not a side effect
of an implementation.

## Getting set up

Go 1.27 or newer and Git. That is the whole list — `CGO_ENABLED=0` throughout, no
C toolchain, and no third-party Go dependencies (see "House rules").

```bash
git clone https://github.com/kawaiipantsu/synapseids.git
cd synapseids
make build
./synapsed --version
```

`make help` lists every target.

## The pre-commit loop

```bash
make fmt vet test build
```

Run all four, every time, before you commit. CI runs the same plus the race
detector, the linter, a vulnerability scan, a stale-fixture check and the
*Branch flow* base check.

Narrower runs while you work:

```bash
go test ./internal/flow/ -run TestSnapshots -v
go test ./internal/pipeline/ -run TestPortScanEndToEnd
make race
make coverage        # writes coverage.html
```

For pipeline changes, also do the manual check — it is the fastest way to catch a
regression the unit tests miss:

```bash
make build && ./synapsed --listen 127.0.0.1:8080 &
./synapse replay testdata/pcap/portscan.pcap --speed max && ./synapse classifications
```

Cross-compilation is a hard requirement; if you touch anything build-affecting,
verify it:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build ./...
make build-linux
```

## Branches

Git Flow, from day one.

| Branch | From | Merges to |
|---|---|---|
| `feature/<short-name>` | `develop` | `develop` |
| `fix/<short-name>` | `develop` | `develop` |
| `release/<version>` | `develop` | `main` **and** `develop` |
| `hotfix/<version-or-desc>` | `main` | `main` **and** `develop` |

- `main` is release history only. The *Branch flow* check and the `main` ruleset
  reject any PR to `main` that is not from `release/*` or `hotfix/*`.
- `develop` is the integration branch and the base for feature branches.
- Feature PRs are squash-merged; release PRs merge with `--no-ff`.
- Releases are annotated `v`-prefixed tags on `main`.

## Commit messages

Conventional-commit prefixes: `feat: fix: test: docs: refactor: build: chore: ci:`.
Keep commits small and cohesive — one logical change each. Write the body when the
*why* is not obvious from the diff.

## House rules

**The pipeline is one-way.** `capture → packet → flow → features → inference →
(events, storage, api)`. Measurement lives in `flow` and `features`; the API and
any renderer consume results and never compute features. A capture implementation
never reaches into inference.

**Never change a released schema.** `flow-features-v1` and `traffic-classes-v1`
are frozen — order and meaning do not change. A new need is `flow-features-v2` or
a new model family, not an edit (§8, §9, §28.5-6). The golden test
(`internal/features/testdata/*.golden.json`) will stop you; regenerate it with
`-update` only when the change is intentional and reviewed, and say so in the PR.

**Never change a model family's input/output contract.** Create a new
family/version instead (§28.6).

**Treat all packet-derived data as untrusted.** Decoders are bounds-checked and
must not panic on hostile bytes; a malformed packet is counted and skipped.

**Keep the hot path off the slow path.** Storage and WebSocket work must not block
the packet loop. Use bounded queues; drop and count rather than stall (§22).

**Defensive only.** No exploitation, no automated counter-attack, no traffic
modification. SynapseIDS observes, classifies, explains and alerts (§28.17).

**Dependency minimalism.** The standard library only. The pcap reader, the packet
decoders and the WebSocket server are hand-rolled on purpose. A new third-party
dependency needs justification in the PR, must be pure Go, and must not break
`CGO_ENABLED=0` cross-compilation to the four Linux targets.

**Do not claim it works without running it.** Applies to humans and agents alike.

## Definition of done

- [ ] Implementation is complete — no reachable stubs.
- [ ] Tests exist where appropriate and pass; `make fmt vet test build` is green.
- [ ] Cross-build passes if you touched anything build-affecting.
- [ ] User-facing behaviour is documented in `docs/` and in `CHANGELOG.md` under
      `[Unreleased]`.
- [ ] Errors are handled — a malformed input yields a counted skip or a populated
      result, not a panic and not a bare `return err` up the packet path.
- [ ] No new dependency (or it is justified and pure Go).
- [ ] Significant architecture decisions are recorded in `docs/adr/`.

## Reporting bugs

Use the issue templates. For a classification problem, attach the smallest PCAP
that reproduces it and say what you expected. For an API problem, include the
request and the full response.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Contributions are accepted under the MIT Licence ([LICENSE](LICENSE)).
