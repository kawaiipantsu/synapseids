#!/bin/sh
# Build a flat, single-suite APT repository from the .deb files in $DIST, ready
# to publish as static files (GitHub Pages, S3, any web root).
#
#   $APT_OUT/
#     pool/main/synapseids_<ver>_<arch>.deb
#     dists/<suite>/main/binary-<arch>/Packages[.gz]
#     dists/<suite>/Release
#     dists/<suite>/InRelease          (clearsigned — when a key is available)
#     dists/<suite>/Release.gpg        (detached  — when a key is available)
#     synapseids-archive-keyring.gpg   (dearmored public key, for signed-by=)
#
# Invoked by `make apt-repo`. Needs `apt-ftparchive` (from `apt-utils`) and, to
# sign, `gpg` with a secret key selected by $SYNAPSE_GPG_KEY (else gpg's
# default). Without a key the Release file is still written but left unsigned and
# a warning is printed — apt then needs `[trusted=yes]`.
set -eu

DIST="${DIST:-dist}"
APT_OUT="${APT_OUT:-$DIST/apt}"
SUITE="${APT_SUITE:-stable}"
COMPONENT="${APT_COMPONENT:-main}"
ORIGIN="${APT_ORIGIN:-SynapseIDS}"
LABEL="${APT_LABEL:-SynapseIDS}"
KEY="${SYNAPSE_GPG_KEY:-}"
ARCHES="amd64 i386 arm64 armhf"

command -v apt-ftparchive >/dev/null 2>&1 || {
	echo "apt-repo.sh: apt-ftparchive not found (install apt-utils)" >&2
	exit 1
}

set -- "$DIST"/synapseids_*_*.deb
[ -e "$1" ] || {
	echo "apt-repo.sh: no .deb files in $DIST/ — run 'make deb' first" >&2
	exit 1
}

# Resolve to an absolute path before any cd.
mkdir -p "$APT_OUT"
APT_OUT="$(cd "$APT_OUT" && pwd)"
DEBS="$(cd "$DIST" && pwd)"

rm -rf "$APT_OUT"
mkdir -p "$APT_OUT/pool/$COMPONENT"
for a in $ARCHES; do
	mkdir -p "$APT_OUT/dists/$SUITE/$COMPONENT/binary-$a"
done
cp "$DEBS"/synapseids_*_*.deb "$APT_OUT/pool/$COMPONENT/"

# Every path apt-ftparchive writes into an index must be relative to the repo
# root, so run it from there.
cd "$APT_OUT"

for a in $ARCHES; do
	d="dists/$SUITE/$COMPONENT/binary-$a"
	apt-ftparchive -a "$a" packages "pool/$COMPONENT" > "$d/Packages"
	gzip -9 -kf "$d/Packages"
	n="$(grep -c '^Package: ' "$d/Packages" || true)"
	echo "  binary-$a: $n package(s)"
done

now="$(date -u '+%a, %d %b %Y %H:%M:%S UTC')"
# Write Release outside the tree first: apt-ftparchive would otherwise hash the
# half-written file it is redirected into.
rel_tmp="$(mktemp)"
apt-ftparchive \
	-o "APT::FTPArchive::Release::Origin=$ORIGIN" \
	-o "APT::FTPArchive::Release::Label=$LABEL" \
	-o "APT::FTPArchive::Release::Suite=$SUITE" \
	-o "APT::FTPArchive::Release::Codename=$SUITE" \
	-o "APT::FTPArchive::Release::Architectures=$ARCHES" \
	-o "APT::FTPArchive::Release::Components=$COMPONENT" \
	-o "APT::FTPArchive::Release::Date=$now" \
	-o "APT::FTPArchive::Release::Description=$ORIGIN APT repository ($SUITE)" \
	release "dists/$SUITE" > "$rel_tmp"
mv "$rel_tmp" "dists/$SUITE/Release"

echo "wrote $APT_OUT/dists/$SUITE/Release"

if [ -z "$KEY" ] && ! gpg --list-secret-keys >/dev/null 2>&1; then
	echo "apt-repo.sh: no GPG key — Release is UNSIGNED." >&2
	echo "  set SYNAPSE_GPG_KEY=<id> (see 'make deb-sign') and re-run to produce InRelease / Release.gpg." >&2
	echo "  an unsigned repo must be added with 'deb [trusted=yes] ...'." >&2
	exit 0
fi

KEYARG=""
[ -n "$KEY" ] && KEYARG="--local-user $KEY"

# shellcheck disable=SC2086
gpg $KEYARG --batch --yes --clearsign --output "dists/$SUITE/InRelease" "dists/$SUITE/Release"
# shellcheck disable=SC2086
gpg $KEYARG --batch --yes --detach-sign --armor --output "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"

gpg --verify "dists/$SUITE/InRelease" >/dev/null 2>&1 &&
	echo "signed  $APT_OUT/dists/$SUITE/{InRelease,Release.gpg}" ||
	{ echo "apt-repo.sh: InRelease failed to verify" >&2; exit 1; }

# The dearmored public key for `signed-by=` in the sources entry.
# shellcheck disable=SC2086
gpg --export ${KEY:+"$KEY"} > "synapseids-archive-keyring.gpg"
echo "wrote $APT_OUT/synapseids-archive-keyring.gpg"
