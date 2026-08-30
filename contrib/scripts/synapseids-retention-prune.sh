#!/bin/sh
# synapseids-retention-prune — retention backstop for THUGS(red) SynapseIDS
#
# Install:  install -m 0755 contrib/scripts/synapseids-retention-prune.sh \
#             /usr/local/bin/synapseids-retention-prune
# Run by:   /etc/cron.d/synapseids-retention, daily at 03:17 as user 'synapse'.
#
# TODAY this is a thin health + telemetry wrapper. synapsed already enforces its
# own windows (retention.flows / retention.classifications in synapse.json —
# PROJECT.md §20), and the Phase-1 "memory" store is a self-evicting bounded
# ring with nothing on disk to prune. This script queries GET /api/v1/status and
# prints what the daemon is holding, so each scheduled run leaves an audit trail.
#
# Environment:
#   SYNAPSE_SERVER   base URL of the daemon      (default http://127.0.0.1:8080)
#   CURL_OPTS        extra curl options, e.g. "-u operator:secret" for a proxy
set -eu

SYNAPSE_SERVER="${SYNAPSE_SERVER:-http://127.0.0.1:8080}"
CURL_OPTS="${CURL_OPTS:-}"
base="${SYNAPSE_SERVER%/}"

command -v curl >/dev/null 2>&1 || { echo "prune: curl not found" >&2; exit 1; }

# shellcheck disable=SC2086  # CURL_OPTS is a deliberate word-split option string
status="$(curl -fsS $CURL_OPTS "$base/api/v1/status")" || {
    echo "prune: daemon not reachable at $base/api/v1/status" >&2
    exit 1
}

echo "synapseids-retention-prune $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  server : $base"
if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$status" | jq -r '
      "  version        : \(.version)",
      "  uptime_sec     : \(.uptime_sec)",
      "  listen         : \(.listen)   (loopback=\(.loopback))",
      "  storage.driver : \(.storage.driver)",
      "  flows          : \(.storage.flows)",
      "  classifications: \(.storage.classifications)",
      "  flows_evicted  : \(.storage.flows_evicted)",
      "  class_evicted  : \(.storage.classifications_evicted)",
      "  live.client_drops: \(.live.client_drops)"'
else
    echo "  (install jq for parsed stats; raw /api/v1/status follows)"
    printf '%s\n' "$status" | sed 's/^/  | /'
fi

# ==========================================================================
# TODO(retention): perform a real prune here once the daemon supports it.
#
# Blocked on the "Configurable retention engine" work: a durable store
# (sqlite / ClickHouse — tracked) plus a maintenance endpoint, e.g.
#   POST /api/v1/maintenance/prune
#     { "flows": "720h", "classifications": "2160h", "dry_run": false }
#
# Until then there is nothing to delete: the memory driver self-evicts and the
# retention.* durations in synapse.json are advisory. See PROJECT.md §20.
#
# Intended implementation:
#   # shellcheck disable=SC2086
#   curl -fsS $CURL_OPTS -X POST "$base/api/v1/maintenance/prune" \
#     -H 'Content-Type: application/json' \
#     -d '{"flows":"720h","classifications":"2160h","dry_run":false}'
# ==========================================================================

exit 0
