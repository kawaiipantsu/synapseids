#!/bin/sh
# Build one .deb per Linux arch from the cross-built binaries, using dpkg-deb
# directly (no fpm, no ruby). Invoked by `make deb` with VERSION, DIST, BINARIES set.
#
# Each package carries all three binaries plus a man page each, DEP-5 copyright
# and a Debian changelog. No Depends — the binaries are static. systemd units
# ship separately in contrib/ (tracked: unit in the .deb).
set -eu

VERSION="${VERSION:?}"
DIST="${DIST:?}"
BINARIES="${BINARIES:?}"

command -v dpkg-deb >/dev/null 2>&1 || {
	echo "package-deb.sh: dpkg-deb not found (install dpkg-dev)" >&2
	exit 1
}

deb_arch() {
	case "$1" in
	amd64) echo amd64 ;;
	386) echo i386 ;;
	arm64) echo arm64 ;;
	arm) echo armhf ;;
	*) echo "unknown arch $1" >&2; exit 1 ;;
	esac
}

DEBVER="${VERSION#v}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTROL_IN="$ROOT/packaging/debian/control.in"
COPYRIGHT="$ROOT/packaging/debian/copyright"
CHANGELOG_IN="$ROOT/packaging/debian/changelog.in"

for arch in amd64 386 arm64 arm; do
	da="$(deb_arch "$arch")"
	src="$DIST/synapseids_${VERSION}_linux_${arch}"
	for b in $BINARIES; do
		[ -x "$src/$b" ] || {
			echo "package-deb.sh: missing $src/$b — run 'make build-linux' first" >&2
			exit 1
		}
	done

	pkgdir="$(mktemp -d)"
	chmod 0755 "$pkgdir"
	mkdir -p "$pkgdir/DEBIAN" \
		"$pkgdir/usr/bin" \
		"$pkgdir/usr/share/doc/synapseids" \
		"$pkgdir/usr/share/man/man1"

	for b in $BINARIES; do
		install -m 0755 "$src/$b" "$pkgdir/usr/bin/$b"
		[ -f "$DIST/$b.1.gz" ] && install -m 0644 "$DIST/$b.1.gz" \
			"$pkgdir/usr/share/man/man1/$b.1.gz"
	done

	sed -e "s/@VERSION@/$DEBVER/g" -e "s/@ARCH@/$da/g" "$CONTROL_IN" \
		> "$pkgdir/DEBIAN/control"
	install -m 0644 "$COPYRIGHT" "$pkgdir/usr/share/doc/synapseids/copyright"
	sed -e "s/@VERSION@/$DEBVER/g" -e "s/@DATE@/$(date -u -R)/g" "$CHANGELOG_IN" \
		| gzip -9 -n > "$pkgdir/usr/share/doc/synapseids/changelog.Debian.gz"

	out="$DIST/synapseids_${DEBVER}_${da}.deb"
	dpkg-deb --root-owner-group --build "$pkgdir" "$out" >/dev/null
	rm -rf "$pkgdir"

	echo "built $out"
	dpkg-deb -I "$out" | sed 's/^/    /'
done

if [ -f "$DIST/SHA256SUMS" ]; then
	(cd "$DIST" && sha256sum ./*.deb >> SHA256SUMS)
fi
