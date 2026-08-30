# Packaging

SynapseIDS ships as static Go binaries for four Linux targets. No cgo, no runtime
dependencies (`CGO_ENABLED=0`, `-trimpath`). Every build produces **three
binaries** — `synapsed` (daemon), `synapse` (admin CLI), `synapse-sensor`
(Phase 6 placeholder) — and every `.deb` carries all three.

Two distribution formats: per-arch `.tar.gz` archives and per-arch `.deb`
packages. See PROJECT.md §27 for the toolchain rationale and
[ADR 0001](adr/0001-go-owns-the-data-plane.md) for why a single static binary is
the target.

## Targets

| GOOS/GOARCH | GOARM | `.deb` arch | `uname -m` |
|---|---|---|---|
| `linux/amd64` | — | `amd64` | `x86_64` (`amd64`) |
| `linux/386` | — | `i386` | `i686` (`i386`) |
| `linux/arm64` | — | `arm64` | `aarch64` (`arm64`) |
| `linux/arm` | `7` | `armhf` | `armv7l` (`armv7`, `armhf`) |

The Makefile's `LINUX_ARCHES := amd64 386 arm64 arm` drives every release target;
`GOARM=7` is set only for `linux/arm`. `install.sh` maps `uname -m` to the
archive name with the same table.

## Make targets

`VERSION` is the first `## [x.y.z]` heading in `CHANGELOG.md`, falling back to
`0.1.0-dev`. Override with `make dist VERSION=1.2.3`. `SOURCE_DATE_EPOCH`, when
set, is honoured (the build date is then left out of `-ldflags` for
reproducibility). `-ldflags` stamps `internal/version` with `Version`, `Commit`,
`Dirty` (and `Date` unless `SOURCE_DATE_EPOCH` is set).

| Target | Produces |
|---|---|
| `make build` | The three binaries in the repo root (host `GOOS/GOARCH`). |
| `make build-linux` (alias `build-all`) | `dist/synapseids_<ver>_linux_<arch>/{synapsed,synapse,synapse-sensor}` for all four arches. |
| `make man` | `dist/{synapsed,synapse,synapse-sensor}.1.gz` — `gzip -9 -n` of `packaging/man/*.1`. |
| `make dist` | Depends on `build-linux` + `man`. Runs `scripts/package.sh`: one `dist/synapseids_<ver>_linux_<arch>.tar.gz` per arch (each holds all three binaries, plus `LICENSE` and — when present — `README.md`, `CHANGELOG.md` and the three `*.1.gz`) and writes `dist/SHA256SUMS`. |
| `make deb` | Depends on `build-linux` + `man`. Runs `scripts/package-deb.sh`: `dist/synapseids_<debver>_<debarch>.deb` for `amd64`, `i386`, `arm64`, `armhf`. Appends the `.deb` checksums to `dist/SHA256SUMS` **if it already exists** — so run `make dist` before `make deb` (the release workflow does). |
| `make snapshot` | `dist` + `deb` with `VERSION=<ver>-snapshot.<commit>`. |
| `make release-check` | `fmt-check`, `vet`, `lint`, `test`, `build-linux`, then `scripts/release-check.sh` (clean tree, changelog heading present, tag free, no `TODO(release)`/`XXX(release)`, all four cross-builds green). |

> [!NOTE]
> `CHANGELOG.md` is **not in the tree yet**. Until it is added with a
> `## [x.y.z]` heading, `VERSION` resolves to `0.1.0-dev`, and both
> `make release-check` and the release workflow's tag/changelog check will fail.
> Tracked.

## `.deb` layout

`scripts/package-deb.sh` builds each package with
`dpkg-deb --root-owner-group --build` from a `mktemp` staging tree — no `fpm`, no
Ruby. It needs `dpkg-deb` (`dpkg-dev`). Contents:

```
/usr/bin/synapsed
/usr/bin/synapse
/usr/bin/synapse-sensor
/usr/share/man/man1/synapsed.1.gz
/usr/share/man/man1/synapse.1.gz
/usr/share/man/man1/synapse-sensor.1.gz
/usr/share/doc/synapseids/copyright              DEP-5, from packaging/debian/copyright
/usr/share/doc/synapseids/changelog.Debian.gz    from packaging/debian/changelog.in
DEBIAN/control                                    from packaging/debian/control.in
```

`control.in` (`@VERSION@` / `@ARCH@` substituted; a leading `v` is stripped from
the version):

- `Package: synapseids`, `Section: net`, `Priority: optional`
- `Maintainer: kawaiipantsu <12233528+kawaiipantsu@users.noreply.github.com>`,
  `Homepage: https://github.com/kawaiipantsu/synapseids`
- **no `Depends`** — the binaries are static
- **no maintainer scripts** — no `preinst` / `postinst` / `prerm` / `postrm`

> [!NOTE]
> systemd units are **not in the `.deb`** yet. They are intended to ship in
> `contrib/` (referenced by `package-deb.sh` and the man page; the directory is
> not in the tree yet). Tracked: "Ship systemd units inside the `.deb`".

Inspect a built package:

```bash
dpkg-deb -I dist/synapseids_0.1.0_amd64.deb     # control metadata
dpkg-deb -c dist/synapseids_0.1.0_amd64.deb     # file list
sudo dpkg -i dist/synapseids_0.1.0_amd64.deb
```

## Signing

`.deb` packages are **unsigned**. Integrity is via `SHA256SUMS`, published with
every release: `scripts/package.sh` seeds it with the `.tar.gz` and `*.1.gz`
sums, `scripts/package-deb.sh` appends the `.deb` sums. Tracked: "Signed `.deb`
packages + apt repository" (`dpkg-sig` / a hosted apt repo).

## Release workflow

`.github/workflows/release.yml`, triggered on `push` of a `v*` tag
(`permissions: contents: write`):

1. Checkout; `actions/setup-go` at Go `1.27`.
2. Verify `${tag#v}` equals the first `## [x.y.z]` heading in `CHANGELOG.md`.
3. `make dist` then `make deb`.
4. `gh release create <tag> --title "SynapseIDS <tag>" --notes "<changelog section>"`
   — with `--prerelease` when the tag contains a hyphen — attaching
   `dist/*.tar.gz`, `dist/*.deb` and `dist/SHA256SUMS`.

`install.sh` (`curl -fsSL … | sh`) resolves the latest release (or
`SYNAPSEIDS_VERSION`), downloads `synapseids_<ver>_linux_<arch>.tar.gz`, verifies
it against `SHA256SUMS` when `sha256sum` is available, and installs all three
binaries into `SYNAPSEIDS_INSTALL` (default `~/.local/bin`, or `/usr/local/bin`
when writable).

---

⟦THUGS⟧ (c) 2026
