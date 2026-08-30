#!/bin/sh
# synapseids-backup — tar+gzip the SynapseIDS state and config
# THUGS(red) SynapseIDS
#
# Install:  install -m 0755 contrib/scripts/synapseids-backup.sh \
#             /usr/local/bin/synapseids-backup
#
# Backs up /var/lib/synapseids and /etc/synapseids to a timestamped archive in
# BACKUP_DIR, then keeps only the newest KEEP archives. Run from cron or a
# systemd timer, e.g.:
#   /etc/cron.d/synapseids-backup:
#     30 2 * * *  root  /usr/local/bin/synapseids-backup
#
# Environment:
#   BACKUP_DIR   destination directory   (default /var/backups/synapseids)
#   KEEP         archives to retain      (default 14)
#
# Note: this does NOT stop the daemon. The Phase-1 "memory" store keeps nothing
# on disk, so the archive is just config plus any model bundles. Once a durable
# file-backed store lands, stop synapsed (or snapshot the filesystem) first.
set -eu

BACKUP_DIR="${BACKUP_DIR:-/var/backups/synapseids}"
KEEP="${KEEP:-14}"
SOURCES="/var/lib/synapseids /etc/synapseids"

if [ "$(id -u)" -ne 0 ]; then
    echo "synapseids-backup: must run as root (reads $SOURCES)" >&2
    exit 1
fi

# Collect the sources that actually exist, as paths relative to / (so tar stores
# them without a leading slash and without warnings).
set --
for s in $SOURCES; do
    if [ -e "$s" ]; then
        set -- "$@" "${s#/}"
    else
        echo "synapseids-backup: skipping $s (does not exist)" >&2
    fi
done
[ "$#" -gt 0 ] || { echo "synapseids-backup: nothing to back up" >&2; exit 1; }

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
host="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)"
out="$BACKUP_DIR/synapseids-${host}-${ts}.tar.gz"

umask 077
tar -czf "$out" -C / "$@"
echo "synapseids-backup: wrote $out ($(du -h "$out" | cut -f1))"
echo "synapseids-backup: contents: $*"

# Prune: keep the newest $KEEP, delete the rest.
n=0
# shellcheck disable=SC2012  # names are controlled (timestamped); ls -t is fine
for f in $(ls -1t "$BACKUP_DIR"/synapseids-*.tar.gz 2>/dev/null); do
    n=$((n + 1))
    if [ "$n" -gt "$KEEP" ]; then
        rm -f "$f"
        echo "synapseids-backup: pruned $f"
    fi
done
kept=$(ls -1 "$BACKUP_DIR"/synapseids-*.tar.gz 2>/dev/null | wc -l | tr -d ' ')
echo "synapseids-backup: $BACKUP_DIR now holds $kept archive(s) (KEEP=$KEEP)"
