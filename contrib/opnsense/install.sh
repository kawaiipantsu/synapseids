#!/bin/sh
# SynapseIDS OPNsense sensor plugin installer. Detects the firewall's pkg ABI,
# downloads the matching package, verifies it against the release SHA256SUMS,
# and installs it with pkg(8).
#
# Recommended (review before you run it — this is a firewall, and the script
# runs as root):
#
#   fetch -o install.sh https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh
#   less install.sh
#   sh ./install.sh
#
# Convenience one-liner:
#
#   fetch -qo - https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh | sh
#   fetch -qo - .../install.sh | sh -s -- --version v0.2.0
#
# It never asks for, transmits or logs the bearer token: that is entered in the
# OPNsense web UI afterwards, so it cannot land in shell history or ps(1).
set -eu

REPO="kawaiipantsu/synapseids"
PKGNAME="os-synapseids-sensor"
BASE_URL=""
VERSION=""
DRY_RUN=0
UNINSTALL=0
GRANT_BPF=0

err() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '  would run: %s\n' "$*"
	else
		"$@"
	fi
}

usage() {
	cat <<'USAGE'
Install the SynapseIDS sensor plugin on an OPNsense firewall.

Usage:
  sh install.sh [--version <tag>] [--url <base>] [--grant-bpf] [--dry-run]
  sh install.sh --uninstall
  sh install.sh --help

Flags:
  --version <tag>   release tag to install, e.g. v0.2.0 (default: latest release)
  --url <base>      base URL to download from instead of the GitHub release,
                    for an air-gapped mirror. Must serve the .pkg and SHA256SUMS.
  --grant-bpf       also install the devfs rule that lets the unprivileged
                    sensor user read /dev/bpf*. Opt-in: it changes device
                    permissions on your firewall. Without it the sensor cannot
                    capture and will tell you so at start-up.
  --dry-run         print what would happen, change nothing
  --uninstall       pkg delete the plugin and remove the rendered config. The
                    bearer token stored in the OPNsense configuration is NOT
                    deleted -- remove it from Services > SynapseIDS Sensor if
                    you want it gone.
  --help            this text

Notes:
  * Must run as root, because it installs a package. It never calls sudo.
  * The package is published by the SynapseIDS release workflow. If the
    download 404s, the release you asked for predates the OPNsense plugin --
    pick a newer tag, or build it yourself with `make opnsense-pkg`.
  * Re-running upgrades in place; it is idempotent.
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version) [ $# -ge 2 ] || err "--version needs a value"; VERSION="$2"; shift 2 ;;
	--version=*) VERSION="${1#--version=}"; shift ;;
	--url) [ $# -ge 2 ] || err "--url needs a value"; BASE_URL="$2"; shift 2 ;;
	--url=*) BASE_URL="${1#--url=}"; shift ;;
	--grant-bpf) GRANT_BPF=1; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) err "unknown option $1 (try --help)" ;;
	esac
done

# ---------------------------------------------------------------- platform

[ "$(uname -s)" = "FreeBSD" ] || err "this installs an OPNsense plugin; the host is $(uname -s), not FreeBSD"
[ -f /usr/local/opnsense/version/core ] \
	|| err "no /usr/local/opnsense/version/core -- this is FreeBSD but not OPNsense"
[ "$(id -u)" = "0" ] \
	|| err "must run as root to install a package. Re-run as root, e.g. 'su -' then 'sh install.sh'"
have pkg || err "pkg(8) not found"

CORE_VERSION="$(cat /usr/local/opnsense/version/core 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------- uninstall

if [ "$UNINSTALL" = 1 ]; then
	say "uninstalling $PKGNAME (OPNsense $CORE_VERSION)"
	if pkg info -e "$PKGNAME" 2>/dev/null; then
		run pkg delete -y "$PKGNAME"
	else
		say "  $PKGNAME is not installed"
	fi
	for f in /usr/local/etc/synapseids/sensor.conf /usr/local/etc/synapseids/sensor.token; do
		[ -e "$f" ] && run rm -f "$f"
	done
	say ""
	say "Removed the package and the rendered configuration."
	say "The bearer token stored in the OPNsense configuration was NOT deleted."
	say "Clear it under Services > SynapseIDS Sensor if you no longer want it."
	exit 0
fi

# ---------------------------------------------------------------- abi

ABI="$(pkg config abi 2>/dev/null || true)"
[ -n "$ABI" ] || err "could not read 'pkg config abi'"

FBSD_MAJOR="$(echo "$ABI" | cut -d: -f2)"
PKG_ARCH="$(echo "$ABI" | cut -d: -f3)"
case "$PKG_ARCH" in
amd64) GOARCH=amd64 ;;
aarch64 | arm64) GOARCH=arm64 ;;
*) err "unsupported architecture $PKG_ARCH (the plugin ships amd64 and arm64)" ;;
esac

say "OPNsense $CORE_VERSION, pkg ABI $ABI -> package arch $GOARCH"

# ---------------------------------------------------------------- download

if have fetch; then
	dl() { fetch -qo - "$1"; }
	dlo() { fetch -qo "$2" "$1"; }
elif have curl; then
	dl() { curl -fsSL "$1"; }
	dlo() { curl -fsSL -o "$2" "$1"; }
else
	err "need fetch or curl"
fi

if [ -z "$VERSION" ]; then
	VERSION="$(dl "https://api.github.com/repos/$REPO/releases/latest" \
		| sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
	[ -n "$VERSION" ] || err "could not resolve the latest release (pass --version)"
fi
VER="${VERSION#v}"

[ -n "$BASE_URL" ] || BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
PKGFILE="${PKGNAME}-${VER}-freebsd${FBSD_MAJOR}-${GOARCH}.pkg"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading $PKGFILE ($VERSION)"
if [ "$DRY_RUN" = 1 ]; then
	say "  would download $BASE_URL/$PKGFILE"
	say "  would download $BASE_URL/SHA256SUMS"
else
	dlo "$BASE_URL/$PKGFILE" "$TMP/$PKGFILE" || err "could not download $BASE_URL/$PKGFILE
The release may predate the OPNsense plugin. Try a newer --version, point
--url at your own mirror, or build the package with 'make opnsense-pkg'."
fi

# ------------------------------------------------------------ verify first

if [ "$DRY_RUN" = 1 ]; then
	say "  would verify $PKGFILE against SHA256SUMS"
else
	dlo "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" \
		|| err "could not download SHA256SUMS -- refusing to install an unverified package"

	# The release SHA256SUMS is produced by sha256sum(1) on Linux, so entries
	# look like "<hash>  ./<name>". FreeBSD has sha256(1), not sha256sum(1).
	want="$(sed -n "s,^\([0-9a-f]\{64\}\)  \./\{0,1\}${PKGFILE}\$,\1,p" "$TMP/SHA256SUMS" | head -1)"
	[ -n "$want" ] || err "$PKGFILE has no entry in SHA256SUMS -- refusing to install"
	got="$(sha256 -q "$TMP/$PKGFILE")"
	[ "$got" = "$want" ] || err "checksum verification failed for $PKGFILE
  expected $want
  got      $got"
	say "checksum OK ($got)"
fi

# ---------------------------------------------------------------- install

# pkg add -f reinstalls over an existing copy, which makes re-running an
# in-place upgrade rather than an error.
say "installing $PKGFILE"
run pkg add -f "$TMP/$PKGFILE"

# The package's post-install script creates the _synapseids account, the log
# directory, and refreshes configd and the web GUI. Re-run the refresh here
# too: harmless if it already happened, and it covers a pkg(8) that was told
# not to run scripts.
if [ -x /usr/local/etc/rc.configure_plugins ]; then
	run /usr/local/etc/rc.configure_plugins install "$PKGNAME"
fi
run service configd restart

# ---------------------------------------------------------------- bpf grant

DEVFS_RULES=/etc/devfs.rules
if [ "$GRANT_BPF" = 1 ]; then
	if grep -q 'synapseids_bpf' "$DEVFS_RULES" 2>/dev/null; then
		say "devfs rule synapseids_bpf already present in $DEVFS_RULES"
	else
		say "installing the synapseids_bpf devfs ruleset into $DEVFS_RULES"
		if [ "$DRY_RUN" = 1 ]; then
			say "  would append the [synapseids_bpf=10] ruleset and set devfs_system_ruleset"
		else
			{
				printf '\n[synapseids_bpf=10]\n'
				printf "add path 'bpf*' mode 0640 group net\n"
			} >> "$DEVFS_RULES"
		fi
	fi
	run sysrc devfs_system_ruleset=synapseids_bpf
	run service devfs restart
fi

# ---------------------------------------------------------------- summary

say ""
say "Installed $PKGNAME $VER."
say ""
say "Next:"
say "  1. Open  https://$(hostname)/ui/synapseidssensor/settings"
say "     (Services > SynapseIDS Sensor)"
say "  2. Pick the WAN interface, enter the daemon address and the bearer token,"
say "     tick 'I am authorised to monitor this traffic', and save."
say "  3. Start the service from the same page."
if [ "$GRANT_BPF" != 1 ]; then
	say ""
	say "The sensor runs as the unprivileged _synapseids user and needs read access"
	say "to /dev/bpf*. If it refuses to start, either re-run with --grant-bpf or do it"
	say "by hand:"
	say "    printf '[synapseids_bpf=10]\\nadd path '\\''bpf*'\\'' mode 0640 group net\\n' >> /etc/devfs.rules"
	say "    sysrc devfs_system_ruleset=synapseids_bpf && service devfs restart"
fi
say ""
say "Verify from the daemon side:  curl -s http://<synapsed>:8080/api/v1/captures | jq"
