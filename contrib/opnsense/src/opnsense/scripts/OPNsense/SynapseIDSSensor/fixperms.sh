#!/bin/sh
#
# Copyright (C) 2026 SynapseIDS contributors
# All rights reserved. BSD 2-Clause; see Sensor.php for the full text.
#
# ---------------------------------------------------------------------------
# `configctl synapseidssensor fixperms`
#
# configd renders templates as root under its own umask, which would leave the
# two secrets on this box - the bearer token and the TLS private key - world
# readable for as long as it took an operator to notice.  This script closes
# that window, and it runs immediately after EVERY `template reload`
# (Api\SettingsController::applyConfiguration and
# Api\ServiceController::reconfigureAction both do so).  The rc.d start_precmd
# re-checks before every start, so this is one of two barriers, not the only one.
#
# It used to be a single very long `command:` line in
# actions_synapseidssensor.conf.  Since issue #124 there is a variable number of
# per-instance files and directories to clamp, and a stale instance file to
# remove, which is more logic than belongs on one line of an ini file - and none
# of it was checkable by `sh -n` while it lived there.
#
#     /usr/local/etc/synapseids                  root:_synapseids 0750
#     /usr/local/etc/synapseids/instances        root:_synapseids 0750
#     /usr/local/etc/synapseids/sensor.token     _synapseids:_synapseids 0400  SECRET
#     /usr/local/etc/synapseids/sensor-key.pem   _synapseids:_synapseids 0400  SECRET
#     /usr/local/etc/synapseids/sensor.conf      root:wheel 0640  (index, no secrets)
#     /usr/local/etc/synapseids/instances/*.conf root:wheel 0640  (flags, no secrets)
#     /usr/local/etc/synapseids/sensor-ca.pem    root:wheel 0444  (public)
#     /usr/local/etc/synapseids/sensor-cert.pem  root:wheel 0444  (public)
#     /var/log/synapseids                        _synapseids:wheel 0750
#     /var/log/synapseids/<instance>             _synapseids:wheel 0750
#
# A file that has not been rendered yet is skipped rather than treated as an
# error, so this is safe to run at any time, and it never reads, echoes or logs
# the token or the key - only their paths and modes.
#
# It always exits 0: a permission fixup that cannot complete must not turn a
# successful save into the GUI's "Unexpected error".  What it could not do shows
# up on the selftest's token-file / tls-identity lines, where it is actionable.
# ---------------------------------------------------------------------------

ETCDIR="/usr/local/etc/synapseids"
INSTDIR="${ETCDIR}/instances"
LOGBASE="/var/log/synapseids"
RUNAS="_synapseids"

# clamp <owner:group> <mode> <path> -- skip anything not rendered yet.
clamp()
{
    [ -f "$3" ] || return 0
    /usr/sbin/chown "$1" "$3" 2>/dev/null
    /bin/chmod "$2" "$3" 2>/dev/null
    return 0
}

clampdir()
{
    [ -d "$3" ] || /bin/mkdir -p "$3" 2>/dev/null
    [ -d "$3" ] || return 0
    /usr/sbin/chown "$1" "$3" 2>/dev/null
    /bin/chmod "$2" "$3" 2>/dev/null
    return 0
}

clampdir "root:${RUNAS}" 0750 "${ETCDIR}"
clampdir "root:${RUNAS}" 0750 "${INSTDIR}"
clampdir "${RUNAS}:wheel" 0750 "${LOGBASE}"

# The two secrets.
clamp "${RUNAS}:${RUNAS}" 0400 "${ETCDIR}/sensor.token"
clamp "${RUNAS}:${RUNAS}" 0400 "${ETCDIR}/sensor-key.pem"

# Public material and the flag files.
clamp root:wheel 0444 "${ETCDIR}/sensor-ca.pem"
clamp root:wheel 0444 "${ETCDIR}/sensor-cert.pem"
clamp root:wheel 0640 "${ETCDIR}/sensor.conf"

# The instance index. Read from the rendered file rather than from config.xml,
# because this script has no MVC runtime and the rendered file is what the rc.d
# script obeys: clamping and pruning against the same source it starts from is
# the property that matters.
profiles=""
if [ -r "${ETCDIR}/sensor.conf" ]; then
    # shellcheck source=/dev/null
    . "${ETCDIR}/sensor.conf"
    profiles="${synapseids_sensor_profiles:-}"
fi

for f in "${INSTDIR}"/*.conf; do
    [ -f "$f" ] || continue
    b="${f##*/}"
    b="${b%.conf}"
    case " ${profiles} " in
    *" ${b} "*)
        clamp root:wheel 0640 "$f"
        # One log directory per instance: `synapse-sensor doctor --log-dir` looks
        # for sensor.log inside it, and daemon(8) -o writes there as the
        # unprivileged user, so it has to exist and be owned before a start.
        clampdir "${RUNAS}:wheel" 0750 "${LOGBASE}/${b}"
        ;;
    *)
        # A renamed or deleted instance. The rc.d script only ever acts on the
        # names in the index, so this file is already inert - but leaving a
        # rendered configuration for a sensor that no longer exists on a
        # firewall is exactly the kind of thing that gets read a year later and
        # believed.
        rm -f "$f" 2>/dev/null
        ;;
    esac
done

exit 0
