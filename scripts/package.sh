#!/bin/sh
# Package the cross-built Linux binaries into per-arch tar.gz archives and a
# single SHA256SUMS file. Invoked by `make dist` with VERSION, DIST, BINARIES set.
set -eu

VERSION="${VERSION:?}"
DIST="${DIST:?}"
BINARIES="${BINARIES:?}"

ARCHES="amd64 386 arm64 arm"

cd "$DIST"
: > SHA256SUMS

for arch in $ARCHES; do
	dir="synapseids_${VERSION}_linux_${arch}"
	for b in $BINARIES; do
		if [ ! -x "$dir/$b" ]; then
			echo "package.sh: missing $dir/$b — run 'make build-linux' first" >&2
			exit 1
		fi
	done

	stage="$(mktemp -d)"
	mkdir -p "$stage/$dir"
	for b in $BINARIES; do cp "$dir/$b" "$stage/$dir/"; done
	cp ../LICENSE ../README.md ../CHANGELOG.md "$stage/$dir/" 2>/dev/null || true
	for b in $BINARIES; do [ -f "$b.1.gz" ] && cp "$b.1.gz" "$stage/$dir/"; done

	tar -C "$stage" -czf "$dir.tar.gz" "$dir"
	rm -rf "$stage"

	sha256sum "$dir.tar.gz" >> SHA256SUMS
	echo "packaged $dir.tar.gz"
done

for b in $BINARIES; do
	[ -f "$b.1.gz" ] && sha256sum "$b.1.gz" >> SHA256SUMS || true
done

echo
echo "SHA256SUMS:"
cat SHA256SUMS
