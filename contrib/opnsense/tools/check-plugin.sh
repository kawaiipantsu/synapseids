#!/bin/sh
# Static and behavioural checks for the OPNsense plugin sources.
#
# Copyright (C) 2026 SynapseIDS contributors
# BSD 2-Clause; see Sensor.php for the full text.
#
# Nothing in this repo can load an OPNsense MVC runtime or run configd, so this
# is the most that can be checked from a build host. It runs, in order:
#
#   1. php -l on every PHP file
#   2. an XML parse of every XML file
#   3. sh -n on every shell script
#   4. the Jinja2 render of every configd template against a mock context, with
#      configd's own Environment and +TARGETS expansion, including the
#      interface-identifier lookup in all of its states and the one-file-per-
#      instance expansion for 0, 1 and 4 sensors
#   5. Sensor::performValidation and Migrations\M1_0_1 against real generated
#      key material and a real pre-upgrade configuration
#   6. +TARGETS / pkg-plist / template-directory agreement, and that every
#      configd action can address a single sensor instance
#   7. that the model version has a matching migration, and that the package
#      actually runs it
#
# Steps 4 and 5 need jinja2 and PHP's openssl extension; each SKIPs (exit 77)
# rather than failing if its interpreter is missing.
#
# shellcheck is deliberately NOT invoked: it is not installed in the development
# environment this was written in, so claiming it passed would be a lie.
#
#     sh contrib/opnsense/tools/check-plugin.sh
set -u

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
SRC="$ROOT/contrib/opnsense/src"
TOOLS="$ROOT/contrib/opnsense/tools"

rc=0
step() { printf '\n=== %s\n' "$*"; }
ok() { printf 'ok    %s\n' "$*"; }
bad() {
	printf 'FAIL  %s\n' "$*"
	rc=1
}
skipped() { printf 'SKIP  %s\n' "$*"; }

# ------------------------------------------------------------------ 1. php -l

step "php -l"
if ! command -v php >/dev/null 2>&1; then
	skipped "php is not installed"
else
	find "$SRC" -name '*.php' -print | sort | while read -r f; do
		if php -l "$f" >/dev/null 2>&1; then
			ok "${f#"$ROOT"/}"
		else
			php -l "$f"
			printf 'FAIL  %s\n' "${f#"$ROOT"/}"
			exit 1
		fi
	done || rc=1
fi

# ------------------------------------------------------------- 2. xml parsing

step "XML parse"
if ! command -v python3 >/dev/null 2>&1; then
	skipped "python3 is not installed"
else
	find "$SRC" -name '*.xml' -print | sort | while read -r f; do
		if python3 -c 'import sys,xml.dom.minidom; xml.dom.minidom.parse(sys.argv[1])' "$f" 2>/dev/null; then
			ok "${f#"$ROOT"/}"
		else
			python3 -c 'import sys,xml.dom.minidom; xml.dom.minidom.parse(sys.argv[1])' "$f"
			printf 'FAIL  %s\n' "${f#"$ROOT"/}"
			exit 1
		fi
	done || rc=1
fi

# --------------------------------------------------------------- 3. sh syntax

step "sh -n"
for f in "$SRC/etc/rc.d/synapseids_sensor" \
	"$SRC/opnsense/scripts/OPNsense/SynapseIDSSensor/fixperms.sh" \
	"$ROOT/contrib/opnsense/install.sh" "$TOOLS/check-plugin.sh"; do
	if sh -n "$f" 2>/dev/null; then
		ok "${f#"$ROOT"/}"
	else
		sh -n "$f"
		bad "${f#"$ROOT"/}"
	fi
done

# The rc.d script and the installer must be executable in the source tree, since
# pkg-plist installs them mode 0555 and package-opnsense.sh copies the mode.
if [ -x "$SRC/etc/rc.d/synapseids_sensor" ]; then
	ok "rc.d script is executable"
else
	bad "rc.d script is not executable (chmod +x it)"
fi

# ----------------------------------------------------- 4. configd templates

step "configd template render (Jinja2)"
if ! command -v python3 >/dev/null 2>&1; then
	skipped "python3 is not installed"
else
	python3 "$TOOLS/render-templates.py" --check
	case $? in
	0) ;;
	77) skipped "jinja2 is not installed" ;;
	*) bad "template render" ;;
	esac
fi

# ------------------------------------------------------------- 5. model rules

step "Sensor::performValidation"
if ! command -v php >/dev/null 2>&1; then
	skipped "php is not installed"
else
	php "$TOOLS/test-sensor-model.php"
	case $? in
	0) ;;
	77) skipped "the PHP openssl extension is not available" ;;
	*) bad "model validation" ;;
	esac
fi

# ------------------------------------------------------ 6. actions.d sanity

step "configd actions"
ACTIONS="$SRC/opnsense/service/conf/actions.d/actions_synapseidssensor.conf"
for action in start stop restart status log fixperms selftest; do
	if grep -q "^\[$action\]\$" "$ACTIONS"; then
		ok "[$action] is defined"
	else
		bad "[$action] is missing from actions_synapseidssensor.conf"
	fi
done
# configd substitutes into the `parameters:` template, never into `command:`, so
# a `%` on a command line would be eaten rather than passed through.
if grep -n '^command:.*%' "$ACTIONS"; then
	bad "a command: line contains '%', which configd would treat as a parameter"
else
	ok "no '%' in any command: line"
fi

# Every lifecycle action must accept an optional instance name (issue #124):
# `configctl synapseidssensor restart wan` has to reach exactly one sensor, or
# taking one segment out of service interrupts the capture of all the others.
for action in start stop restart status log selftest; do
	block=$(awk -v a="[$action]" '$0 == a {f=1; next} /^\[/ {f=0} f' "$ACTIONS")
	if printf '%s\n' "$block" | grep -q '^parameters:%s$'; then
		ok "[$action] takes an instance parameter"
	else
		bad "[$action] has no 'parameters:%s', so it cannot address one instance"
	fi
done
# fixperms is the exception: it clamps every file on the box, so a parameter
# would only invite the idea that it does less than it does.
if awk '$0 == "[fixperms]" {f=1; next} /^\[/ {f=0} f' "$ACTIONS" | grep -q '^parameters:$'; then
	ok "[fixperms] takes no parameter"
else
	bad "[fixperms] should take no parameter"
fi

# The per-instance parameter reaches a path in the log action, so it must be
# re-validated there. configd single-quotes it, which stops shell injection but
# not path traversal.
if grep -q '^command:.*\[!A-Za-z0-9_\]' "$ACTIONS"; then
	ok "the log action sanitises the instance name before building a path"
else
	bad "no action sanitises the instance name; a name like ../../etc would traverse"
fi

# The token must never appear in a command line.
if grep -niE '^command:.*(--token[^-]|token=)' "$ACTIONS"; then
	bad "an action puts the bearer token on a command line"
else
	ok "no action puts a token on a command line"
fi

# ---------------------------------------------------- 7. model + migration

step "model version and migration"
MODEL="$SRC/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor/Sensor.xml"
version=$(sed -n 's,.*<version>\(.*\)</version>.*,\1,p' "$MODEL" | head -n 1)
if [ -n "$version" ]; then
	ok "model version is $version"
else
	bad "Sensor.xml declares no <version>"
fi
# BaseModel::runMigrations() runs Migrations/M<version with dots as underscores>.php,
# so a model version with no matching migration silently never migrates anything
# -- and an operator's single-sensor configuration would appear to vanish.
MIG="$SRC/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor/Migrations/M$(printf '%s' "$version" | tr '.' '_').php"
if [ -f "$MIG" ]; then
	ok "a migration exists for model version $version"
else
	bad "no migration $(basename "$MIG") for model version $version"
fi
# The package must actually run the migrations, or the migration above never
# executes on an upgrade.
if grep -q 'run_migrations.php' "$ROOT/scripts/package-opnsense.sh"; then
	ok "post-install runs run_migrations.php"
else
	bad "package-opnsense.sh post-install does not run run_migrations.php"
fi

printf '\n'
if [ "$rc" -eq 0 ]; then
	printf 'check-plugin: all checks passed\n'
else
	printf 'check-plugin: FAILURES above\n'
fi
exit "$rc"
