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
                    for a LAN host or air-gapped mirror. Must serve the .pkg and
                    SHA256SUMS. With --url and no --version, the version is read
                    from the mirror's own SHA256SUMS rather than from
                    api.github.com, so no internet access is needed.
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

# /usr/local/opnsense/version/core is a bare version string on some builds and a
# JSON object on others (OPNsense 25.10 and the Business edition), so cat'ing it
# printed the whole blob into the banner. Take product_version / CORE_VERSION when
# it is JSON, the trimmed first line when it is not.
CORE_VERSION="$(
	sed -n 's/.*"product_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
		/usr/local/opnsense/version/core 2>/dev/null | head -1
)"
[ -n "$CORE_VERSION" ] || CORE_VERSION="$(
	sed -n 's/.*"CORE_VERSION"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
		/usr/local/opnsense/version/core 2>/dev/null | head -1
)"
[ -n "$CORE_VERSION" ] || CORE_VERSION="$(
	head -1 /usr/local/opnsense/version/core 2>/dev/null \
		| tr -d '[:space:]' | grep -v '[{}]' || true
)"
[ -n "$CORE_VERSION" ] || CORE_VERSION="unknown"

# ---------------------------------------------------------------- uninstall

if [ "$UNINSTALL" = 1 ]; then
	say "uninstalling $PKGNAME (OPNsense $CORE_VERSION)"
	if pkg info -e "$PKGNAME" 2>/dev/null; then
		run pkg delete -y "$PKGNAME"
	else
		say "  $PKGNAME is not installed"
	fi
	# Everything configd renders, including the TLS private key -- leaving a key
	# behind after an uninstall is bad hygiene even though it is mode 0400.
	#
	# instances/*.conf is one file per capture instance (issue #124). It carries
	# no secret, but a rendered configuration for a sensor that is no longer
	# installed is exactly the kind of file that gets read a year later and
	# believed.
	for f in /usr/local/etc/synapseids/sensor.conf \
		/usr/local/etc/synapseids/sensor.token \
		/usr/local/etc/synapseids/sensor-ca.pem \
		/usr/local/etc/synapseids/sensor-cert.pem \
		/usr/local/etc/synapseids/sensor-key.pem \
		/usr/local/etc/synapseids/instances/*.conf; do
		if [ -e "$f" ]; then
			run rm -f "$f"
		fi
	done
	if [ -d /usr/local/etc/synapseids/instances ]; then
		run rmdir /usr/local/etc/synapseids/instances 2>/dev/null || true
	fi
	say ""
	say "Removed the package, the rendered configuration and the rendered TLS material."
	say "The bearer token and the PEM text stored in the OPNsense configuration were NOT"
	say "deleted. Clear them under Services > SynapseIDS Sensor if you no longer want them."
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

# Every network call is bounded. fetch(1) and curl(1) both wait forever by
# default, and with fetch's -q that wait is completely silent: a firewall that
# cannot reach api.github.com hung the installer with no output and no clue.
# CONNECT_TIMEOUT catches a blackholed host; TIMEOUT catches a stalled transfer.
CONNECT_TIMEOUT=15
TIMEOUT=120

if have fetch; then
	dl() { fetch -qo - -T "$CONNECT_TIMEOUT" "$1"; }
	dlo() { fetch -qo "$2" -T "$TIMEOUT" "$1"; }
elif have curl; then
	dl() { curl -fsSL --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" "$1"; }
	dlo() { curl -fsSL --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -o "$2" "$1"; }
else
	err "need fetch or curl"
fi

# redirect_tag prints the tag that /releases/latest redirects to, or nothing.
redirect_tag() {
	_loc=""
	if have fetch; then
		# fetch prints the resolved URL to stderr with -v; simpler and portable:
		# ask for headers only via curl when present, else parse fetch -v.
		_loc="$(fetch -v -o /dev/null -T "$CONNECT_TIMEOUT" \
			"https://github.com/$REPO/releases/latest" 2>&1 \
			| sed -n 's|.*releases/tag/\([^ ]*\).*|\1|p' | head -1)"
	fi
	if [ -z "$_loc" ] && have curl; then
		_loc="$(curl -sI --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
			"https://github.com/$REPO/releases/latest" \
			| sed -n 's/^[Ll]ocation:.*releases\/tag\/\([^[:space:]]*\).*/\1/p' | head -1)"
	fi
	printf '%s' "$_loc"
}

# Resolving the version.
#
# With --url pointing at a private mirror or a LAN host we must NOT reach out to
# api.github.com: that host may have no route to the internet at all, and an
# air-gapped install would fail on a call it never needed to make. So when a base
# URL is given without a version, the version is discovered from the mirror's own
# SHA256SUMS instead -- which we are about to download anyway.
MIRROR_SUMS=""
if [ -z "$VERSION" ] && [ -n "$BASE_URL" ]; then
	say "resolving the version from $BASE_URL/SHA256SUMS"
	MIRROR_SUMS="$(dl "$BASE_URL/SHA256SUMS" 2>/dev/null || true)"
	if [ -n "$MIRROR_SUMS" ]; then
		# Match os-synapseids-sensor-<ver>-freebsd<major>-<goarch>.pkg and keep
		# <ver>. The name is anchored on both sides so a stray file cannot match.
		VERSION="$(printf '%s\n' "$MIRROR_SUMS" \
			| sed -n "s,.*[/ ]${PKGNAME}-\(.*\)-freebsd${FBSD_MAJOR}-${GOARCH}\.pkg\$,\1,p" \
			| head -1)"
	fi
	[ -n "$VERSION" ] || err "could not work out which version $BASE_URL serves.
Pass it explicitly, e.g. --url $BASE_URL --version v0.2.0"
	say "  found $VERSION"
fi

if [ -z "$VERSION" ]; then
	# github.com/<repo>/releases/latest redirects to the tag. Reading the
	# redirect avoids api.github.com entirely: that host is rate-limited
	# unauthenticated, and is blocked on plenty of firewalls that can still
	# reach github.com — which is exactly how this hung on a real gateway.
	VERSION="$(redirect_tag)"
	if [ -z "$VERSION" ]; then
		# Fall back to the API, still bounded, before giving up.
		VERSION="$(dl "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
			| sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
	fi
	[ -n "$VERSION" ] || err "could not resolve the latest release of $REPO.
Pass it explicitly:  --version v0.2.0
(both https://github.com/$REPO/releases/latest and api.github.com were unreachable
or gave nothing; a firewall that blocks them will need --version, or --url
pointing at a local mirror)"
fi
VER="${VERSION#v}"

[ -n "$BASE_URL" ] || BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

# This must match, character for character, the name scripts/package-opnsense.sh
# writes:  out="$DIST/${PKGNAME}-${VER}-freebsd${major}-${goarch}.pkg"
# A mismatch here is the difference between a working install and a confusing
# 404, so TestOPNsensePackageFilenameDerivation in cmd/synapse-sensor pins the
# two format strings and the ABI-to-GOARCH mapping against each other.
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
	if [ -n "$MIRROR_SUMS" ]; then
		# Already fetched while resolving the version from a mirror.
		printf '%s\n' "$MIRROR_SUMS" > "$TMP/SHA256SUMS"
	else
		dlo "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" \
			|| err "could not download SHA256SUMS -- refusing to install an unverified package"
	fi

	# The release SHA256SUMS is produced by sha256sum(1) on Linux, where the
	# entry for a file named on the command line as ./x is "<hash>  ./x" and one
	# named as x is "<hash>  x". Both forms must be accepted -- and the previous
	# pattern here required the leading dot, so a bare-name entry silently found
	# no match and the install aborted as "no entry in SHA256SUMS".
	#
	# The name is escaped first, because a package version contains dots and a
	# dot is a regex metacharacter -- unescaped, "0.2.0" would also match a
	# hypothetical "0X2Y0" build.
	#
	# Three separate -e expressions rather than one clever pattern with optional
	# groups: every BRE interval (\{0,1\}, \{1,\}) contains a comma, and comma is
	# this s///'s delimiter, so a single combined pattern silently truncates.
	# Three plain alternatives are also easier to read and to check by eye.
	pkgfile_re="$(printf '%s\n' "$PKGFILE" | sed 's,[][*.^$\\],\\&,g')"
	want="$(sed -n \
		-e "s,^\([0-9a-f]*\)  *${pkgfile_re}\$,\1,p" \
		-e "s,^\([0-9a-f]*\)  *\./${pkgfile_re}\$,\1,p" \
		-e "s,^\([0-9a-f]*\)  *[*]${pkgfile_re}\$,\1,p" \
		"$TMP/SHA256SUMS" | head -1)"
	[ -n "$want" ] || err "$PKGFILE has no entry in $BASE_URL/SHA256SUMS -- refusing to install.
The mirror may be serving a different version; check what it lists:
    fetch -qo - $BASE_URL/SHA256SUMS | grep $PKGNAME"
	[ "${#want}" = 64 ] || err "the SHA256SUMS entry for $PKGFILE is not a 64-character hex digest
(got ${#want} characters) -- refusing to install against a malformed checksum file"
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
# The bpf group is detected, not assumed. FreeBSD base ships "network" (gid 69);
# much documentation says "net", which does not exist on a stock system. Writing
# a devfs rule against a nonexistent group grants nothing and fails silently.
bpf_group() {
	for _g in network net; do
		if /usr/sbin/pw groupshow "$_g" >/dev/null 2>&1; then
			printf '%s' "$_g"
			return 0
		fi
	done
	printf 'network'
}
BPF_GROUP="$(bpf_group)"

# existing_bpf_rule_group prints the group named in an existing [synapseids_bpf]
# block, or nothing when there is no such block.
existing_bpf_rule_group() {
	[ -f "$DEVFS_RULES" ] || return 0
	awk '
		/^[[:space:]]*\[synapseids_bpf=/ { inblock = 1; next }
		/^[[:space:]]*\[/               { inblock = 0 }
		inblock {
			for (i = 1; i < NF; i++)
				if ($i == "group") { print $(i + 1); exit }
		}
	' "$DEVFS_RULES" 2>/dev/null
}

# write_bpf_ruleset removes any existing [synapseids_bpf] block and appends a
# correct one. Editing rather than appending matters: devfs(8) rejects the WHOLE
# file when any line is bad, so a single stale rule disables every ruleset in it.
write_bpf_ruleset() {
	if [ "$DRY_RUN" = 1 ]; then
		say "  would rewrite the [synapseids_bpf=10] ruleset with group $BPF_GROUP"
		return 0
	fi
	cp "$DEVFS_RULES" "$DEVFS_RULES.synapseids.bak" 2>/dev/null || true
	tmp="$(mktemp)"
	if [ -f "$DEVFS_RULES" ]; then
		awk '
			/^[[:space:]]*\[synapseids_bpf=/ { skip = 1; next }
			/^[[:space:]]*\[/               { skip = 0 }
			!skip
		' "$DEVFS_RULES" > "$tmp"
	fi
	{
		printf '\n[synapseids_bpf=10]\n'
		printf "add path 'bpf*' mode 0640 group %s\n" "$BPF_GROUP"
	} >> "$tmp"
	cat "$tmp" > "$DEVFS_RULES"
	rm -f "$tmp"
}

if [ "$GRANT_BPF" = 1 ]; then
	EXISTING_GROUP="$(existing_bpf_rule_group)"
	if [ -z "$EXISTING_GROUP" ]; then
		say "installing the synapseids_bpf devfs ruleset into $DEVFS_RULES (group $BPF_GROUP)"
		write_bpf_ruleset
	elif /usr/sbin/pw groupshow "$EXISTING_GROUP" >/dev/null 2>&1; then
		say "devfs rule synapseids_bpf already present in $DEVFS_RULES (group $EXISTING_GROUP)"
	else
		# The reason this branch exists: an earlier release of this installer
		# wrote `group net`, which does not exist on a stock FreeBSD system.
		# devfs then refuses to parse the file at all --
		#   devfs rule: error converting to integer: net
		#   devfs_init_rulesets: could not read rules from /etc/devfs.rules
		# -- so NO ruleset loads and /dev/bpf* keeps its default 0600 root:wheel.
		# "Already present" is the wrong answer here; repair it.
		say "the existing synapseids_bpf rule names group '$EXISTING_GROUP', which does not exist"
		say "  devfs rejects the whole file when one line is bad, so no ruleset is loading"
		say "  rewriting it with group $BPF_GROUP (backup: $DEVFS_RULES.synapseids.bak)"
		write_bpf_ruleset
	fi
	run sysrc devfs_system_ruleset=synapseids_bpf
	run service devfs restart

	# Verify the ruleset actually took effect rather than trusting that it did.
	# devfs reports a parse error and then simply carries on with NO rules
	# applied, so "sysrc + restart returned 0" proves nothing -- /dev/bpf* can
	# still be 0600 root:wheel and the sensor would capture nothing while every
	# install step looked successful.
	if [ "$DRY_RUN" != 1 ]; then
		_bpfdev=""
		for _d in /dev/bpf0 /dev/bpf; do
			[ -c "$_d" ] && { _bpfdev="$_d"; break; }
		done
		if [ -n "$_bpfdev" ]; then
			_got="$(stat -f '%Sg' "$_bpfdev" 2>/dev/null || echo '')"
			if [ "$_got" = "$BPF_GROUP" ]; then
				say "devfs: $_bpfdev is group $BPF_GROUP — the sensor can read it"
			else
				say ""
				say "WARNING: $_bpfdev is still group '${_got:-unknown}', not '$BPF_GROUP'."
				say "         The devfs ruleset did not take effect, so the sensor will"
				say "         capture nothing. Look for a parse error from:"
				say "             service devfs restart"
				say "         Any single bad line in $DEVFS_RULES makes devfs discard"
				say "         the entire file -- check that no rule names a group that"
				say "         does not exist (pw groupshow <name>)."
			fi
		fi
	fi
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
	say "    printf '[synapseids_bpf=10]\\nadd path '\\''bpf*'\\'' mode 0640 group $BPF_GROUP\\n' >> /etc/devfs.rules"
	say "    sysrc devfs_system_ruleset=synapseids_bpf && service devfs restart"
fi
say ""
say "If anything does not work, run the selftest FIRST -- it checks the binary, the"
say "service account, /dev/bpf* access, that the chosen interface resolved to a device"
say "that exists, the rendered config, the token mode, the TLS material and whether"
say "the daemon answers. One line per check:"
say "    service synapseids_sensor selftest"
say ""
say "Verify from the daemon side:  curl -s http://<synapsed>:8080/api/v1/captures | jq"
