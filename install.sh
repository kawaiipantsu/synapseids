#!/bin/sh
# SynapseIDS installer. Detects your Linux arch, downloads the matching release
# archive, verifies it against the release SHA256SUMS, and installs all three
# binaries (synapsed, synapse, synapse-sensor).
#
#   curl -fsSL https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/install.sh | sh
#
# Environment:
#   SYNAPSEIDS_VERSION   version to install (default: latest release)
#   SYNAPSEIDS_INSTALL   install directory (default: ~/.local/bin, or /usr/local/bin if writable)
set -eu

REPO="kawaiipantsu/synapseids"
BINS="synapsed synapse synapse-sensor"

err() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname -s)" = "Linux" ] || err "this build targets Linux only (got $(uname -s))"

case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	i386 | i686) ARCH=386 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	armv7l | armv7 | armhf) ARCH=arm ;;
	*) err "unsupported architecture: $(uname -m)" ;;
esac

if have curl; then
	dl() { curl -fsSL --connect-timeout 15 --max-time 120 "$1"; }
	dlo() { curl -fsSL --connect-timeout 15 --max-time 120 -o "$2" "$1"; }
elif have wget; then
	dl() { wget -qO- --connect-timeout=15 --timeout=120 "$1"; }
	dlo() { wget -qO "$2" --connect-timeout=15 --timeout=120 "$1"; }
else
	err "need curl or wget"
fi

VERSION="${SYNAPSEIDS_VERSION:-}"
if [ -z "$VERSION" ]; then
	# Bounded, and a blocked api.github.com now fails fast with advice rather
	# than hanging: see contrib/opnsense/install.sh, where an unbounded fetch on
	# this exact host hung a real gateway with no output at all.
	VERSION="$(dl "https://api.github.com/repos/$REPO/releases/latest" \
		| sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
	[ -n "$VERSION" ] || err "could not resolve the latest release"
fi
VER="${VERSION#v}"

DEST="${SYNAPSEIDS_INSTALL:-}"
if [ -z "$DEST" ]; then
	if [ -w /usr/local/bin ]; then DEST=/usr/local/bin; else DEST="$HOME/.local/bin"; fi
fi
mkdir -p "$DEST"

TARBALL="synapseids_${VER}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "downloading $TARBALL ($VERSION)"
dlo "$BASE/$TARBALL" "$TMP/$TARBALL"

if dlo "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null && have sha256sum; then
	( cd "$TMP" && grep " $TARBALL\$" SHA256SUMS | sha256sum -c - ) \
		|| err "checksum verification failed"
	echo "checksum OK"
else
	echo "warning: could not verify checksum (SHA256SUMS or sha256sum unavailable)" >&2
fi

tar -C "$TMP" -xzf "$TMP/$TARBALL"
for b in $BINS; do
	install -m 0755 "$TMP/synapseids_${VER}_linux_${ARCH}/$b" "$DEST/$b"
	echo "installed $DEST/$b"
done

case ":$PATH:" in
	*":$DEST:"*) ;;
	*) echo "note: $DEST is not on your PATH" ;;
esac
"$DEST/synapsed" --version || true
