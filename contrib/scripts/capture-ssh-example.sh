#!/bin/sh
# capture-ssh-example.sh — remote tcpdump over SSH into a local PCAP for replay
# THUGS(red) SynapseIDS
#
# Demonstrates the PROJECT.md §6 "SSH remote tcpdump" pattern: run tcpdump on a
# remote sensor, stream the raw capture back over SSH, and write it to a local
# file that synapsed can then replay through the normal pipeline. Daemon-managed
# live SSH ingestion is Phase 3; this script is the manual stopgap.
#
# Usage:
#   HOST=user@sensor.example.org \
#   [ FILTER='not port 22' ] [ IFACE=any ] [ SNAPLEN=0 ] \
#   [ OUT=./synapse-capture-<ts>.pcap ] [ SSH_OPTS='-i ~/.ssh/id_ed25519' ] \
#   I_AM_AUTHORIZED=yes ./capture-ssh-example.sh
#
# Then replay it:
#   synapse replay "$OUT" --speed 1
#   # or: curl -fsS -XPOST localhost:8080/api/v1/replay \
#   #       -H 'Content-Type: application/json' -d "{\"path\":\"$OUT\",\"speed\":\"1\"}"
set -eu

banner() {
    cat >&2 <<'EOF'
############################################################################
#  AUTHORIZED MONITORING ONLY
#
#  This script starts a PACKET CAPTURE on a REMOTE host over SSH. Capturing
#  traffic on systems you do not own or lack explicit written authorization
#  to monitor is unlawful in most jurisdictions and violates PROJECT.md §21
#  and §28.18. SynapseIDS is a DEFENSIVE tool: observe, classify, explain,
#  alert. Nothing here modifies traffic or the remote host.
#
#  Proceed only against systems you are explicitly authorized to monitor.
#  Set  I_AM_AUTHORIZED=yes  to confirm and continue.
############################################################################
EOF
}

banner

if [ "${I_AM_AUTHORIZED:-}" != "yes" ]; then
    echo "refusing to run: set I_AM_AUTHORIZED=yes once you have confirmed authorization" >&2
    exit 3
fi

HOST="${HOST:?set HOST=user@sensor-host}"
FILTER="${FILTER:-not port 22}"
IFACE="${IFACE:-any}"
SNAPLEN="${SNAPLEN:-0}"
SSH_OPTS="${SSH_OPTS:-}"
OUT="${OUT:-./synapse-capture-$(date -u +%Y%m%dT%H%M%SZ).pcap}"

command -v ssh >/dev/null 2>&1 || { echo "ssh not found" >&2; exit 1; }
[ -e "$OUT" ] && { echo "refusing to overwrite existing file: $OUT" >&2; exit 1; }

finish() {
    st=$?
    if [ -s "$OUT" ]; then
        echo "" >&2
        echo "wrote $(du -h "$OUT" | cut -f1) to $OUT" >&2
        echo "replay it:  synapse replay \"$OUT\" --speed 1" >&2
    else
        rm -f "$OUT"
    fi
    exit "$st"
}
trap finish EXIT INT TERM

echo "capturing from $HOST  (iface=$IFACE filter='$FILTER' snaplen=$SNAPLEN)" >&2
echo "writing        $OUT" >&2
echo "press Ctrl-C to stop" >&2

# -U  pack each packet immediately (unbuffered)      -w -  write pcap to stdout
# -n  no name resolution                              -s    snaplen (0 = full)
# tcpdump on the remote host needs CAP_NET_RAW (run as root or via a sudo rule).
# shellcheck disable=SC2086  # SSH_OPTS is a deliberate word-split option string
ssh $SSH_OPTS "$HOST" tcpdump -U -n -i "$IFACE" -s "$SNAPLEN" -w - "$FILTER" > "$OUT"
