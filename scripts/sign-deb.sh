#!/bin/sh
# GPG-sign the release artifacts in $DIST:
#
#   * a detached, armoured signature (<file>.asc) for every .deb and for
#     SHA256SUMS — the checksum file is the integrity anchor install.sh already
#     uses, so signing it covers every archive too;
#   * an in-package signature per .deb when `debsigs` is installed (optional —
#     most consumers verify the repo's Release file, not the .deb itself).
#
# Invoked by `make deb-sign`. Needs `gpg`. The signing key is chosen by, in
# order: $SYNAPSE_GPG_KEY (id / fingerprint / uid), else gpg's default key.
# With no usable secret key it prints how to make one and exits non-zero — a
# release must not silently ship unsigned.
set -eu

DIST="${DIST:-dist}"
KEY="${SYNAPSE_GPG_KEY:-}"

command -v gpg >/dev/null 2>&1 || {
	echo "sign-deb.sh: gpg not found (install gnupg)" >&2
	exit 1
}

[ -d "$DIST" ] || {
	echo "sign-deb.sh: $DIST/ does not exist — run 'make dist' / 'make deb' first" >&2
	exit 1
}

set -- "$DIST"/synapseids_*_*.deb
[ -e "$1" ] || {
	echo "sign-deb.sh: no .deb files in $DIST/ — run 'make deb' first" >&2
	exit 1
}

# One --local-user flag, reused for every call; empty when $KEY is unset so gpg
# falls back to its configured default key. A passphrase-protected key must have
# its passphrase cached in the gpg-agent first (CI does a warm-up signature).
KEYARG=""
[ -n "$KEY" ] && KEYARG="--local-user $KEY"

# Fail early with a useful message rather than a cryptic gpg error per file.
# shellcheck disable=SC2086
gpg $KEYARG --list-secret-keys >/dev/null 2>&1 || {
	echo "sign-deb.sh: no secret key available${KEY:+ for '$KEY'}." >&2
	echo "  generate one:  gpg --quick-generate-key 'SynapseIDS Releases <releases@example.org>' default sign 2y" >&2
	echo "  then export it: gpg --armor --export-secret-keys <id> > signing.key   (for CI's GPG_PRIVATE_KEY secret)" >&2
	exit 1
}

sign_detached() {
	f="$1"
	[ -f "$f" ] || return 0
	rm -f "$f.asc"
	# shellcheck disable=SC2086
	gpg $KEYARG --batch --yes --armor --detach-sign --output "$f.asc" "$f"
	gpg --verify "$f.asc" "$f" >/dev/null 2>&1 &&
		echo "signed  $f.asc" ||
		{ echo "sign-deb.sh: verification of $f.asc failed" >&2; exit 1; }
}

for deb in "$DIST"/synapseids_*_*.deb; do
	sign_detached "$deb"
	if command -v debsigs >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		debsigs --sign=origin ${KEY:+-k "$KEY"} "$deb" >/dev/null 2>&1 &&
			echo "embedded origin signature in $(basename "$deb")" ||
			echo "sign-deb.sh: debsigs failed for $(basename "$deb") (skipped)" >&2
	fi
done

sign_detached "$DIST/SHA256SUMS"

# Ship the public key beside the artifacts so a verifier does not have to hunt
# for it. Both armoured (.asc) and dearmored (.gpg, for apt's signed-by=).
if [ -n "$KEY" ]; then
	gpg --armor --export "$KEY" > "$DIST/synapseids-signing-key.asc"
	gpg --export "$KEY" > "$DIST/synapseids-signing-key.gpg"
	echo "exported public key to $DIST/synapseids-signing-key.{asc,gpg}"
fi
