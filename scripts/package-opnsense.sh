#!/bin/sh
# Build the OPNsense plugin package (os-synapseids-sensor) for one or more
# FreeBSD ABIs, plus a plain FreeBSD tarball. Invoked by `make opnsense-pkg`
# and by `make dist` with VERSION, DIST and ABIS set.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# A FreeBSD package is not a special format: it is a compressed tar archive
# whose leading members are the UCL/JSON metadata (+MANIFEST and
# +COMPACT_MANIFEST) followed by the payload under absolute paths. pkg(8) does
# not exist on the Linux build host, so this builds the archive directly with
# tar and xz — the same posture as scripts/package-deb.sh, which drives
# dpkg-deb rather than a packaging framework.
#
# WHAT IS AND IS NOT VERIFIED
# ---------------------------
# verify_pkg() below asserts everything that can be checked without pkg(8):
# member order, absolute payload paths under the prefix, a parseable manifest
# carrying every required key, a sha256 for every payload file that matches the
# bytes actually in the archive, and the file modes. What it CANNOT do is prove
# that pkg(8) accepts the result — that needs a FreeBSD/OPNsense box:
#
#     pkg info -F dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
#     pkg add     dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
#
# See contrib/opnsense/README.md and docs/adr/0014-*.md.
#
# NOTE ON THE files HASHES: pkg's own +MANIFEST records a bare lowercase hex
# sha256 per path, not a "sha256:"-prefixed string. This script matches pkg.
set -eu

VERSION="${VERSION:?}"
DIST="${DIST:?}"
ABIS="${ABIS:-FreeBSD:14:amd64 FreeBSD:14:arm64}"
FREEBSD_ARCHES="${FREEBSD_ARCHES:-amd64 arm64}"
FREEBSD_BINARIES="${FREEBSD_BINARIES:-synapse-sensor synapsed synapse}"

PKGNAME="os-synapseids-sensor"
ORIGIN="opnsense/os-synapseids-sensor"
PREFIX="/usr/local"
COMMENT="SynapseIDS WAN sensor plugin for OPNsense"
MAINTAINER="12233528+kawaiipantsu@users.noreply.github.com"
WWW="https://github.com/kawaiipantsu/synapseids"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/contrib/opnsense/src"
PLIST="$ROOT/contrib/opnsense/pkg-plist"
DESCR="$ROOT/contrib/opnsense/pkg-descr"
VER="${VERSION#v}"

err() { printf 'package-opnsense.sh: %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || err "jq not found (install jq) — needed to emit the package manifest"
command -v xz >/dev/null 2>&1 || err "xz not found (install xz-utils)"
[ -d "$SRC" ] || err "missing $SRC"
[ -f "$DESCR" ] || err "missing $DESCR"

# Reproducibility: honour SOURCE_DATE_EPOCH exactly as the rest of the build
# does, and otherwise let tar record natural mtimes.
MTIME_FLAG=""
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	MTIME_FLAG="--mtime=@${SOURCE_DATE_EPOCH}"
fi

# --owner/--group with an explicit numeric id gives uid 0 / gid 0 without
# consulting the build host's passwd database (which has no "wheel"), while
# still recording the root/wheel names a FreeBSD package is expected to carry.
TAR_OWNER="--owner=root:0 --group=wheel:0"

mkdir -p "$DIST"

# ---------------------------------------------------------------- payload

# stage_payload builds the install image for one GOARCH under $1.
# src/<rel> installs to /usr/local/<rel>; anything under etc/rc.d is executable.
stage_payload() {
	stage="$1"
	goarch="$2"
	bin="$DIST/synapseids_${VERSION}_freebsd_${goarch}/synapse-sensor"

	[ -x "$bin" ] || err "missing $bin — run 'make build-freebsd' first"

	install -D -m 0555 "$bin" "$stage/usr/local/bin/synapse-sensor"

	(cd "$SRC" && find . -type f | LC_ALL=C sort) | while read -r rel; do
		rel="${rel#./}"
		case "$rel" in
		etc/rc.d/*) mode=0555 ;;
		*) mode=0644 ;;
		esac
		install -D -m "$mode" "$SRC/$rel" "$stage/usr/local/$rel"
	done
}

# check_plist fails when the staged tree and contrib/opnsense/pkg-plist have
# drifted apart. The plist is what a real FreeBSD port build would consume, so
# keeping the two in lockstep is what makes the port skeleton trustworthy.
check_plist() {
	stage="$1"
	[ -f "$PLIST" ] || err "missing $PLIST"

	staged="$(mktemp)"
	listed="$(mktemp)"
	(cd "$stage/usr/local" && find . -type f | sed 's,^\./,,' | LC_ALL=C sort) > "$staged"
	grep -v -e '^[[:space:]]*$' -e '^#' "$PLIST" | LC_ALL=C sort > "$listed"

	if ! diff -u "$listed" "$staged" > /dev/null; then
		echo "package-opnsense.sh: pkg-plist does not match the staged tree:" >&2
		diff -u "$listed" "$staged" >&2 || true
		rm -f "$staged" "$listed"
		exit 1
	fi
	rm -f "$staged" "$listed"
}

# ---------------------------------------------------------------- metadata

post_install_script() {
	cat <<'POSTINSTALL'
#!/bin/sh
# Least privilege: the sensor runs as a dedicated unprivileged account, never
# as root. Membership of the group a devfs rule grants bpf* to is what gives it
# read access (PROJECT.md 21).
set -e

# The bpf group is NOT hardcoded. FreeBSD base ships "network" (gid 69); a lot
# of documentation -- including earlier versions of this package -- says "net",
# which does not exist on a stock system. `pw useradd -G net` then fails, and
# under `set -e` that aborted this whole script: the group was created, the
# ACCOUNT WAS NOT, and every later step was skipped. Detect instead of assume,
# and treat supplementary membership as best-effort so a missing group can
# never again cost us the account.
bpf_group=""
for _g in network net; do
	if /usr/sbin/pw groupshow "$_g" >/dev/null 2>&1; then
		bpf_group="$_g"
		break
	fi
done

if ! /usr/sbin/pw groupshow _synapseids >/dev/null 2>&1; then
	/usr/sbin/pw groupadd _synapseids
fi
if ! /usr/sbin/pw usershow _synapseids >/dev/null 2>&1; then
	# Primary group only. Supplementary groups are added separately below so
	# that this command cannot fail for a reason unrelated to the account.
	/usr/sbin/pw useradd _synapseids -g _synapseids \
		-d /nonexistent -s /usr/sbin/nologin -c 'SynapseIDS sensor'
fi
if [ -n "$bpf_group" ]; then
	/usr/sbin/pw groupmod "$bpf_group" -m _synapseids >/dev/null 2>&1 || true
else
	echo "WARNING: neither group 'network' nor 'net' exists, so _synapseids was"
	echo "         not added to a bpf group. Create the devfs rule against a"
	echo "         group the account is in, or the sensor cannot read /dev/bpf*."
fi

# Guarded: if the account somehow still does not exist, create the directory as
# root rather than aborting. `configctl synapseidssensor fixperms` re-applies
# ownership on every save, so a root-owned directory here self-corrects.
if /usr/sbin/pw usershow _synapseids >/dev/null 2>&1; then
	install -d -o _synapseids -g wheel -m 0750 /var/log/synapseids
else
	install -d -o root -g wheel -m 0750 /var/log/synapseids
fi
install -d -o root -g wheel -m 0750 /usr/local/etc/synapseids

# Make the MVC pages, ACL and configd actions visible.
if [ -x /usr/local/etc/rc.configure_plugins ]; then
	/usr/local/etc/rc.configure_plugins install os-synapseids-sensor >/dev/null 2>&1 || true
fi
if [ -x /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart >/dev/null 2>&1 || true
fi
if [ -x /usr/local/etc/rc.restart_webgui ]; then
	/usr/local/etc/rc.restart_webgui >/dev/null 2>&1 || true
fi

echo "SynapseIDS sensor installed. Configure it at Services > SynapseIDS Sensor."
echo "The sensor needs read access to /dev/bpf*. If it will not start, run:"
echo "    printf '[synapseids_bpf=10]\\nadd path \\'bpf*\\' mode 0640 group ${bpf_group:-network}\\n' >> /etc/devfs.rules"
echo "    sysrc devfs_system_ruleset=synapseids_bpf && service devfs restart"
POSTINSTALL
}

pre_deinstall_script() {
	cat <<'PREDEINSTALL'
#!/bin/sh
# Stop the sensor before the binary goes away. The stored bearer token in the
# OPNsense configuration is deliberately left alone: removing a package must
# not silently destroy credentials the operator may still need.
if [ -x /usr/local/etc/rc.d/synapseids_sensor ]; then
	/usr/local/etc/rc.d/synapseids_sensor onestop >/dev/null 2>&1 || true
fi
if [ -x /usr/local/etc/rc.configure_plugins ]; then
	/usr/local/etc/rc.configure_plugins remove os-synapseids-sensor >/dev/null 2>&1 || true
fi
PREDEINSTALL
}

# write_manifests emits +MANIFEST and +COMPACT_MANIFEST into $1 for the staged
# tree in $2, targeting abi $3 / arch $4.
write_manifests() {
	meta="$1"
	stage="$2"
	abi="$3"
	altabi="$4"

	# path<TAB>sha256 for every payload file, in a stable order.
	: > "$meta/files.tsv"
	(cd "$stage" && find . -type f | LC_ALL=C sort) | while read -r rel; do
		rel="${rel#./}"
		printf '/%s\t%s\n' "$rel" "$(sha256sum "$stage/$rel" | cut -d' ' -f1)" >> "$meta/files.tsv"
	done

	# Directories the package itself owns, so pkg creates them on install and
	# reaps them on delete. Everything else already exists on an OPNsense box.
	(cd "$stage" && find . -type d) \
		| sed 's,^\.,,' \
		| grep -E 'SynapseIDSSensor|synapseids' \
		| LC_ALL=C sort > "$meta/dirs.txt" || true

	flatsize="$(find "$stage" -type f -printf '%s\n' | awk '{s += $1} END {print s + 0}')"

	post_install_script > "$meta/post-install.sh"
	pre_deinstall_script > "$meta/pre-deinstall.sh"

	jq -n \
		--arg name "$PKGNAME" \
		--arg origin "$ORIGIN" \
		--arg version "$VER" \
		--arg comment "$COMMENT" \
		--arg maintainer "$MAINTAINER" \
		--arg www "$WWW" \
		--arg abi "$abi" \
		--arg arch "$altabi" \
		--arg prefix "$PREFIX" \
		--argjson flatsize "$flatsize" \
		--rawfile desc "$DESCR" \
		--rawfile files "$meta/files.tsv" \
		--rawfile dirs "$meta/dirs.txt" \
		--rawfile postinstall "$meta/post-install.sh" \
		--rawfile predeinstall "$meta/pre-deinstall.sh" \
		'{
			name: $name,
			origin: $origin,
			version: $version,
			comment: $comment,
			maintainer: $maintainer,
			www: $www,
			abi: $abi,
			arch: $arch,
			prefix: $prefix,
			categories: ["security"],
			licenselogic: "single",
			licenses: ["MIT"],
			desc: ($desc | rtrimstr("\n")),
			flatsize: $flatsize,
			deps: {},
			directories: (
				$dirs | rtrimstr("\n") | split("\n")
				| map(select(length > 0))
				| map({key: ., value: {uname: "root", gname: "wheel", perm: "0755"}})
				| from_entries
			),
			files: (
				$files | rtrimstr("\n") | split("\n")
				| map(select(length > 0) | split("\t"))
				| map({key: .[0], value: .[1]})
				| from_entries
			),
			scripts: {
				"post-install": $postinstall,
				"pre-deinstall": $predeinstall
			}
		}' > "$meta/+MANIFEST"

	# The compact manifest is the same metadata without the per-file detail:
	# it is what a repository index is built from.
	jq 'del(.files, .directories, .scripts)' "$meta/+MANIFEST" > "$meta/+COMPACT_MANIFEST"
}

# ---------------------------------------------------------------- verify

# verify_pkg asserts everything about the archive that can be checked without
# pkg(8). Any failure aborts the build rather than shipping a broken package.
verify_pkg() {
	out="$1"
	work="$(mktemp -d)"

	tar -tf "$out" > "$work/members" 2>/dev/null || err "$out is not a readable tar archive"

	first="$(sed -n 1p "$work/members")"
	second="$(sed -n 2p "$work/members")"
	[ "$first" = "+MANIFEST" ] || err "first archive member is $first, want +MANIFEST"
	[ "$second" = "+COMPACT_MANIFEST" ] || err "second archive member is $second, want +COMPACT_MANIFEST"

	bad="$(tail -n +3 "$work/members" | grep -v "^${PREFIX}/" || true)"
	[ -z "$bad" ] || err "payload members outside $PREFIX:
$bad"

	tar -xf "$out" -C "$work" +MANIFEST +COMPACT_MANIFEST
	jq -e . "$work/+MANIFEST" > /dev/null || err "+MANIFEST is not valid JSON/UCL"
	for key in name origin version comment desc maintainer www abi arch prefix \
		categories licenselogic licenses flatsize deps files scripts; do
		jq -e "has(\"$key\")" "$work/+MANIFEST" > /dev/null \
			|| err "+MANIFEST is missing the required key \"$key\""
	done
	jq -e '.scripts | has("post-install") and has("pre-deinstall")' "$work/+MANIFEST" > /dev/null \
		|| err "+MANIFEST scripts must define post-install and pre-deinstall"
	jq -e --arg n "$PKGNAME" '.name == $n' "$work/+MANIFEST" > /dev/null \
		|| err "+MANIFEST name does not match $PKGNAME"

	# Every declared hash must match the bytes actually inside the archive.
	# Extract everything, metadata included: an --exclude glob for the '+'
	# members would also swallow payload files such as the configd +TARGETS.
	mkdir -p "$work/x"
	# stderr is dropped only to hide tar's "Removing leading /" note: the paths
	# ARE absolute, which is the point, and stripping them on extraction into a
	# scratch directory is exactly the behaviour we want here.
	tar -xf "$out" -C "$work/x" 2>/dev/null
	jq -r '.files | to_entries[] | "\(.value)  \(.key)"' "$work/+MANIFEST" \
		| while read -r sum path; do
			f="$work/x${path}"
			[ -f "$f" ] || err "manifest lists $path but the archive does not contain it"
			got="$(sha256sum "$f" | cut -d' ' -f1)"
			[ "$got" = "$sum" ] || err "checksum mismatch for $path: archive $got, manifest $sum"
		done

	# Count parity: no payload file may be missing from the manifest either.
	declared="$(jq -r '.files | length' "$work/+MANIFEST")"
	archived="$(tail -n +3 "$work/members" | wc -l | tr -d ' ')"
	[ "$declared" = "$archived" ] \
		|| err "manifest lists $declared files but the archive holds $archived"

	# Modes: the binary and the rc script must be executable, the rest not.
	binmode="$(stat -c '%a' "$work/x$PREFIX/bin/synapse-sensor")"
	[ "$binmode" = "555" ] || err "synapse-sensor is mode $binmode, want 555"
	rcmode="$(stat -c '%a' "$work/x$PREFIX/etc/rc.d/synapseids_sensor")"
	[ "$rcmode" = "555" ] || err "the rc.d script is mode $rcmode, want 555"

	# Ownership: uid/gid 0 recorded as root/wheel.
	badown="$(tar -tvf "$out" 2>/dev/null | grep -v ' root/wheel ' || true)"
	[ -z "$badown" ] || err "archive members not owned by root/wheel:
$badown"

	rm -rf "$work"
	echo "    verified: member order, $declared payload files, checksums, modes, root/wheel ownership"
}

# ---------------------------------------------------------------- build

for abi in $ABIS; do
	case "$abi" in
	*:*:*) ;;
	*) err "malformed ABI $abi (want e.g. FreeBSD:14:amd64)" ;;
	esac
	major="$(echo "$abi" | cut -d: -f2)"
	pkgarch="$(echo "$abi" | cut -d: -f3)"

	case "$pkgarch" in
	amd64) goarch=amd64; altarch="x86:64" ;;
	arm64 | aarch64) goarch=arm64; pkgarch=aarch64; altarch="aarch64:64" ;;
	i386) goarch=386; altarch="x86:32" ;;
	*) err "unsupported package architecture $pkgarch" ;;
	esac
	abi="FreeBSD:${major}:${pkgarch}"
	altabi="freebsd:${major}:${altarch}"

	stage="$(mktemp -d)"
	meta="$(mktemp -d)"
	chmod 0755 "$stage" "$meta"

	stage_payload "$stage" "$goarch"
	check_plist "$stage"
	write_manifests "$meta" "$stage" "$abi" "$altabi"

	(cd "$stage" && find . -type f | sed 's,^\./,,' | LC_ALL=C sort) > "$meta/payload.list"

	out="$DIST/${PKGNAME}-${VER}-freebsd${major}-${goarch}.pkg"
	rm -f "$out"
	# --transform makes the payload absolute (/usr/local/...) the way pkg(8)
	# writes it, while leaving the two +-prefixed metadata members alone. -P
	# stops tar undoing that. --no-recursion keeps the archive to exactly the
	# files the manifest declares, with no directory members.
	# shellcheck disable=SC2086 # TAR_OWNER and MTIME_FLAG are deliberate word lists
	tar --create --xz --file "$out" \
		-P --transform 's,^usr/,/usr/,' \
		$TAR_OWNER $MTIME_FLAG --no-recursion \
		-C "$meta" +MANIFEST +COMPACT_MANIFEST \
		-C "$stage" -T "$meta/payload.list"

	echo "built $out ($abi)"
	verify_pkg "$out"

	rm -rf "$stage" "$meta"
done

# ------------------------------------------------- plain FreeBSD tarballs

for arch in $FREEBSD_ARCHES; do
	dir="synapseids_${VERSION}_freebsd_${arch}"
	[ -d "$DIST/$dir" ] || continue
	stage="$(mktemp -d)"
	mkdir -p "$stage/$dir"
	for b in $FREEBSD_BINARIES; do
		[ -x "$DIST/$dir/$b" ] || err "missing $DIST/$dir/$b — run 'make build-freebsd' first"
		cp "$DIST/$dir/$b" "$stage/$dir/"
	done
	cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$stage/$dir/" 2>/dev/null || true
	tar -C "$stage" -czf "$DIST/$dir.tar.gz" "$dir"
	rm -rf "$stage"
	echo "packaged $dir.tar.gz"
done

# Append to the release checksum file when `make dist` already created it.
if [ -f "$DIST/SHA256SUMS" ]; then
	(cd "$DIST" && sha256sum ./*.pkg >> SHA256SUMS)
	(cd "$DIST" && for f in ./synapseids_*_freebsd_*.tar.gz; do
		[ -f "$f" ] && sha256sum "$f" >> SHA256SUMS
	done)
fi
