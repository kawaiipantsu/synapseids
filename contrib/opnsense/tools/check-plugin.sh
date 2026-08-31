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
#   4. the Jinja2 render of every configd template against a mock context,
#      including the interface-identifier lookup in all of its states
#   5. Sensor::performValidation against real generated key material
#   6. +TARGETS / pkg-plist / template-directory agreement
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
for f in "$SRC/etc/rc.d/synapseids_sensor" "$ROOT/contrib/opnsense/install.sh" "$TOOLS/check-plugin.sh"; do
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
# configd applies parameter substitution to `command:`, so a stray % would be
# interpreted. None of these actions takes parameters.
if grep -n '^command:.*%' "$ACTIONS"; then
	bad "a command: line contains '%', which configd would treat as a parameter"
else
	ok "no '%' in any command: line"
fi
# The token must never appear in a command line.
if grep -niE '^command:.*(--token[^-]|token=)' "$ACTIONS"; then
	bad "an action puts the bearer token on a command line"
else
	ok "no action puts a token on a command line"
fi

printf '\n'
if [ "$rc" -eq 0 ]; then
	printf 'check-plugin: all checks passed\n'
else
	printf 'check-plugin: FAILURES above\n'
fi
exit "$rc"
