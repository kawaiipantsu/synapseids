#!/bin/sh
# End-to-end check that install.sh asks for exactly the file make opnsense-pkg
# built, and verifies it against a real SHA256SUMS.
#
# Copyright (C) 2026 SynapseIDS contributors
# BSD 2-Clause; see Sensor.php for the full text.
#
# install.sh runs on FreeBSD and refuses to run anywhere else, so it cannot be
# executed here. Instead this lifts its two derivations -- the package file name
# and the SHA256SUMS lookup -- out of the shipped script and runs them against
# the artefacts actually present in dist/, for every ABI the Makefile builds.
#
# A mismatch is the difference between a working install and a 404 that reads
# like the release is missing.
#
#     make opnsense-pkg
#     sh contrib/opnsense/tools/check-install-derivation.sh
set -u

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
INSTALL_SH="$ROOT/contrib/opnsense/install.sh"
DIST="${DIST:-$ROOT/dist}"
PKGNAME="os-synapseids-sensor"

rc=0
ok() { printf 'ok    %s\n' "$*"; }
bad() {
	printf 'FAIL  %s\n' "$*"
	rc=1
}

pkgs=$(ls "$DIST"/${PKGNAME}-*.pkg 2>/dev/null)
if [ -z "$pkgs" ]; then
	printf 'check-install-derivation: no %s-*.pkg in %s -- run "make opnsense-pkg" first\n' \
		"$PKGNAME" "$DIST" >&2
	exit 77
fi

# A SHA256SUMS in exactly the shape the release workflow produces: appended by
# package-opnsense.sh with `sha256sum ./*.pkg`, hence the leading "./".
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT 0
(cd "$DIST" && sha256sum ./*.pkg) > "$TMP/SHA256SUMS"
ok "built a SHA256SUMS with $(wc -l < "$TMP/SHA256SUMS" | tr -d ' ') entries"

# Lift the derivations out of install.sh rather than restating them here.
arch_case=$(sed -n '/^case "\$PKG_ARCH" in$/,/^esac$/p' "$INSTALL_SH")
[ -n "$arch_case" ] || {
	printf 'could not extract the PKG_ARCH case block from install.sh\n' >&2
	exit 1
}
name_line=$(grep '^PKGFILE=' "$INSTALL_SH")
[ -n "$name_line" ] || {
	printf 'could not extract PKGFILE= from install.sh\n' >&2
	exit 1
}
re_line=$(grep '^	pkgfile_re=' "$INSTALL_SH")
sums_lines=$(sed -n '/^	want="\$(sed -n/,/head -1)"$/p' "$INSTALL_SH")
[ -n "$re_line" ] && [ -n "$sums_lines" ] || {
	printf 'could not extract the SHA256SUMS parser from install.sh\n' >&2
	exit 1
}

# `pkg config abi` reports aarch64 on arm64 hardware, so both spellings are
# exercised for the arm64 package.
for abi in FreeBSD:14:amd64 FreeBSD:14:aarch64 FreeBSD:14:arm64; do
	VER=$(basename "$(echo "$pkgs" | head -1)" | sed "s,^${PKGNAME}-,,; s,-freebsd.*\$,,")

	derived=$(
		set -eu
		err() {
			echo "UNSUPPORTED: $*"
			exit 1
		}
		ABI="$abi"
		PKGNAME="$PKGNAME"
		VER="$VER"
		FBSD_MAJOR=$(echo "$ABI" | cut -d: -f2)
		PKG_ARCH=$(echo "$ABI" | cut -d: -f3)
		eval "$arch_case"
		eval "$name_line"
		printf '%s' "$PKGFILE"
	) || {
		bad "$abi: install.sh refuses this ABI"
		continue
	}

	if [ -f "$DIST/$derived" ]; then
		ok "$abi -> $derived (present in dist/)"
	else
		bad "$abi -> $derived, but that file was NOT built. dist/ has:"
		echo "$pkgs" | sed 's,^,        ,'
		continue
	fi

	# Now the verification path: does install.sh's parser find the digest, and
	# does it match the real file?
	found=$(
		set -u
		TMP="$TMP"
		PKGFILE="$derived"
		eval "$re_line"
		eval "$sums_lines"
		printf '%s' "$want"
	)
	real=$(sha256sum "$DIST/$derived" | cut -d' ' -f1)
	if [ -z "$found" ]; then
		bad "$derived: install.sh's SHA256SUMS parser found no entry"
	elif [ "$found" != "$real" ]; then
		bad "$derived: parser returned $found, real digest is $real"
	else
		ok "$derived: checksum lookup returned the correct digest ${found}"
	fi
done

# The same parser must also cope with a mirror index written without "./",
# which is what a hand-rolled LAN mirror produces.
bare_pkg=$(basename "$(echo "$pkgs" | head -1)")
sed 's,  \./,  ,' "$TMP/SHA256SUMS" > "$TMP/SHA256SUMS.bare"
found=$(
	set -u
	TMP="$TMP"
	PKGFILE="$bare_pkg"
	eval "$re_line"
	eval "$(printf '%s\n' "$sums_lines" | sed 's,SHA256SUMS",SHA256SUMS.bare",')"
	printf '%s' "$want"
)
real=$(sha256sum "$DIST/$bare_pkg" | cut -d' ' -f1)
if [ "$found" = "$real" ]; then
	ok "bare-name SHA256SUMS (no leading ./) also parses"
else
	bad "bare-name SHA256SUMS did not parse: got '$found', want '$real'"
fi

printf '\n'
if [ "$rc" -eq 0 ]; then
	printf 'check-install-derivation: install.sh and make opnsense-pkg agree\n'
else
	printf 'check-install-derivation: FAILURES above\n'
fi
exit "$rc"
