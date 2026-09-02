#!/bin/sh
# Build one .deb per Linux arch from the cross-built binaries, using dpkg-deb
# directly (no fpm, no ruby). Invoked by `make deb` with VERSION, DIST, BINARIES set.
#
# Each package carries all three binaries plus a man page each, DEP-5 copyright
# and a Debian changelog, the systemd units + sysusers + tmpfiles fragments, and
# a default config under /etc/synapseids (conffiles). No Depends — the binaries
# are static. The maintainer scripts create the `synapse` user and its
# directories and reload the systemd manager; they never enable or start the
# daemon (issue #60, PROJECT.md §21).
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
		"$pkgdir/usr/share/man/man1" \
		"$pkgdir/lib/systemd/system" \
		"$pkgdir/usr/lib/sysusers.d" \
		"$pkgdir/usr/lib/tmpfiles.d" \
		"$pkgdir/etc/synapseids"

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

	# systemd units + sysusers/tmpfiles fragments (issue #60). The units carry
	# their [Install] section commented out / the daemon-off posture; the
	# maintainer scripts do not enable them.
	install -m 0644 "$ROOT/contrib/systemd/synapsed.service" \
		"$pkgdir/lib/systemd/system/synapsed.service"
	install -m 0644 "$ROOT/contrib/systemd/synapse-sensor.service" \
		"$pkgdir/lib/systemd/system/synapse-sensor.service"
	install -m 0644 "$ROOT/contrib/systemd/synapseids.sysusers" \
		"$pkgdir/usr/lib/sysusers.d/synapseids.conf"
	install -m 0644 "$ROOT/contrib/systemd/synapseids.tmpfiles" \
		"$pkgdir/usr/lib/tmpfiles.d/synapseids.conf"

	# Default config under /etc, tracked as conffiles so an operator's edits
	# survive an upgrade. Laid down root:root 0640; postinst chgrps to `synapse`
	# once that group exists.
	install -m 0640 "$ROOT/contrib/config/synapse.json" \
		"$pkgdir/etc/synapseids/synapse.json"
	install -m 0640 "$ROOT/contrib/systemd/synapsed.env" \
		"$pkgdir/etc/synapseids/synapsed.env"
	install -m 0644 "$ROOT/packaging/debian/conffiles" "$pkgdir/DEBIAN/conffiles"

	# Maintainer scripts: create the user + dirs, reload systemd, stop on remove.
	# Never enable or start (PROJECT.md §21, §28.18).
	for s in postinst prerm postrm; do
		install -m 0755 "$ROOT/packaging/debian/$s" "$pkgdir/DEBIAN/$s"
	done

	out="$DIST/synapseids_${DEBVER}_${da}.deb"
	dpkg-deb --root-owner-group --build "$pkgdir" "$out" >/dev/null
	rm -rf "$pkgdir"

	echo "built $out"
	dpkg-deb -I "$out" | sed 's/^/    /'
done

if [ -f "$DIST/SHA256SUMS" ]; then
	(cd "$DIST" && sha256sum ./*.deb >> SHA256SUMS)
fi
