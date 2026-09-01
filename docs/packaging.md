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
| `make deb-sign` | `scripts/sign-deb.sh`: GPG detached signatures for every `.deb` and `SHA256SUMS`, plus an optional in-`.deb` `debsigs` signature. See [Signing](#signing). |
| `make apt-repo` | `scripts/apt-repo.sh`: a signed flat APT repository under `dist/apt/` from the built `.deb` files. See [APT repository](#apt-repository). |
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

Two layers, both driven by `gpg` (no `dpkg-sig`, no Ruby). The signing key is
chosen by `SYNAPSE_GPG_KEY` (id / fingerprint / uid), falling back to gpg's
default key; CI imports one from the `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE`
secrets.

| Target | Produces |
|---|---|
| `make deb-sign` | `scripts/sign-deb.sh`: an armoured detached signature `<file>.asc` for **every `.deb`** and for **`SHA256SUMS`** (the anchor `install.sh` already verifies, so signing it covers the `.tar.gz` archives too); an in-`.deb` `origin` signature via `debsigs` **when it is installed** (optional — consumers normally verify the repo's `Release`, not the package); and the public key as `dist/synapseids-signing-key.{asc,gpg}`. With no usable secret key it prints how to make one and **exits non-zero** — a release must not silently ship unsigned. |
| `make apt-repo` | `scripts/apt-repo.sh`: a signed APT repository under `dist/apt/` — see below. |

Verify a downloaded package or the checksum file:

```bash
gpg --verify synapseids_0.2.1_amd64.deb.asc synapseids_0.2.1_amd64.deb
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c SHA256SUMS
```

## APT repository

`make apt-repo` (after `make deb`) builds a **flat, single-suite** repository
from `dist/*.deb` that publishes as static files anywhere — GitHub Pages, S3, a
plain web root. It needs `apt-ftparchive` (`apt-utils`).

```
dist/apt/
  pool/main/synapseids_<ver>_<arch>.deb
  dists/stable/main/binary-{amd64,i386,arm64,armhf}/Packages[.gz]
  dists/stable/Release
  dists/stable/InRelease       clearsigned  ┐ written when a signing key
  dists/stable/Release.gpg     detached     ┘ is available
  synapseids-archive-keyring.gpg            dearmored public key, for signed-by=
```

Overridable via env: `APT_SUITE` (default `stable`), `APT_COMPONENT` (`main`),
`APT_ORIGIN` / `APT_LABEL` (`SynapseIDS`), `APT_OUT` (`dist/apt`). Without a
signing key the `Release` file is still written but left unsigned and the script
warns; such a repo must be added with `deb [trusted=yes] …`.

Consume it (signed):

```bash
sudo install -m 0644 synapseids-archive-keyring.gpg \
  /usr/share/keyrings/synapseids-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/synapseids-archive-keyring.gpg] \
  https://<host>/apt stable main' | sudo tee /etc/apt/sources.list.d/synapseids.list
sudo apt update && sudo apt install synapseids
```

The repo is regenerated whole on every run (`pool/` and `dists/` are wiped
first); hosting is just serving the directory.

## Release workflow

`.github/workflows/release.yml`, triggered on `push` of a `v*` tag
(`permissions: contents: write`):

1. Checkout; `actions/setup-go` at Go `1.27`.
2. Verify `${tag#v}` equals the first `## [x.y.z]` heading in `CHANGELOG.md`.
3. `make dist` then `make deb`.
4. When the `GPG_PRIVATE_KEY` secret is set: import it, then `make deb-sign` and
   `make apt-repo`. The step is skipped (not failed) when the secret is absent,
   so a fork without signing keys still produces a release.
5. `gh release create <tag> --title "SynapseIDS <tag>" --notes "<changelog section>"`
   — with `--prerelease` when the tag contains a hyphen — attaching
   `dist/*.tar.gz`, `dist/*.deb`, `dist/SHA256SUMS` and, when signing ran, the
   `*.asc` signatures and `dist/synapseids-signing-key.asc`.

The `dist/apt/` tree is built but not attached to the GitHub release — it is
meant to be rsync'd to a web root. Publishing it (a `gh-pages` push, an S3 sync)
is deployment config, out of scope for this repo.

`install.sh` (`curl -fsSL … | sh`) resolves the latest release (or
`SYNAPSEIDS_VERSION`), downloads `synapseids_<ver>_linux_<arch>.tar.gz`, verifies
it against `SHA256SUMS` when `sha256sum` is available, and installs all three
binaries into `SYNAPSEIDS_INSTALL` (default `~/.local/bin`, or `/usr/local/bin`
when writable).

---

⟦THUGS⟧ (c) 2026
