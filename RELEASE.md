# Publishing a SynapseIDS release

## 1. Choosing a tag

Semantic versioning, `v` prefix, annotated tags only, on `main` only.

| Situation | Tag |
|:--|:--|
| Testing before a real release | `v0.1.0-rc.1` (bump the `rc` each attempt) |
| First usable release | `v0.1.0` |
| Bug fixes only | `v0.1.1` |
| New features, pre-1.0 (may include breaking changes) | `v0.2.0` |
| First stable API / schema commitment | `v1.0.0` |

Release candidates are marked pre-release on GitHub (the `Release` workflow does
this automatically for any tag containing `-`).

## 2. Cutting the release

```bash
git switch develop
git switch -c release/0.1.0

# Move [Unreleased] entries into a new "## [0.1.0] - <date>" section in
# CHANGELOG.md. The Makefile reads VERSION from the first "## [x.y.z]" heading.

make release-check           # fmt-check, vet, lint, test, build-linux, clean tree, tag free
make dist                    # four tar.gz + SHA256SUMS
make deb                     # four .deb, folded into SHA256SUMS

git commit -am "chore: prepare v0.1.0"
```

Open a PR from `release/0.1.0` to `main` (the *Branch flow* check allows
`release/*` → `main`). When CI is green, merge it with a merge commit
(`--no-ff`), then:

```bash
git switch main && git pull
git tag -a v0.1.0-rc.1 -m "SynapseIDS v0.1.0-rc.1" && git push origin v0.1.0-rc.1   # verify the pre-release
git tag -a v0.1.0      -m "SynapseIDS v0.1.0"      && git push origin v0.1.0

git switch develop && git merge --no-ff main && git push
git branch -d release/0.1.0
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which rebuilds every
archive and package and publishes the GitHub release with `SHA256SUMS` attached.

## 3. GitHub release (manual fallback)

If the workflow cannot run:

```bash
gh release create v0.1.0 \
  --title "SynapseIDS v0.1.0" \
  --notes-file dist/notes.md \
  dist/*.tar.gz dist/*.deb dist/SHA256SUMS
```

Add `--prerelease` for an `-rc`. **Always upload `SHA256SUMS`.**

### What to write

Write for someone deciding whether to upgrade. No marketing language — "faster"
needs a number.

```markdown
One or two sentences on what this release is for.

## Highlights
- The three or four things a reader actually cares about
- Lead with anything affecting safety, the API, or a frozen schema

## Install
Download a binary or `.deb` below and verify it:

    sha256sum -c SHA256SUMS --ignore-missing
    sudo dpkg -i synapseids_0.1.0_amd64.deb

## Known limitations
Copy this section from CHANGELOG.md verbatim.

## Full changelog
https://github.com/kawaiipantsu/synapseids/compare/v0.0.0...v0.1.0
```

## 4. Artifacts

| File | Platform |
|:--|:--|
| `synapseids_<ver>_linux_amd64.tar.gz` | Linux x86-64 |
| `synapseids_<ver>_linux_386.tar.gz` | Linux x86 (32-bit) |
| `synapseids_<ver>_linux_arm64.tar.gz` | Linux ARM64 |
| `synapseids_<ver>_linux_arm.tar.gz` | Linux ARMv7 |
| `synapseids_<ver>_{amd64,i386,arm64,armhf}.deb` | Debian/Ubuntu |
| `SHA256SUMS` | checksums for all of the above |

Each `.tar.gz` and each `.deb` carries all three binaries (`synapsed`, `synapse`,
`synapse-sensor`) plus man pages. All binaries are static (`CGO_ENABLED=0`,
`-trimpath`). `.deb` packages are currently unsigned; the checksums are the
integrity check.

## 5. After publishing

Add a fresh `## [Unreleased]` section to `CHANGELOG.md` on `develop`.
