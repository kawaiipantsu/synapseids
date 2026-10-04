# 0044 — Editable network policy, reputation and name provenance

Accepted, 2026-10-04.

Operator-owned addresses belong in a durable policy file, never product code.
`policy_file` holds an optimistic-revision document edited by the admin-only
`PUT /api/v1/policy` API and Network policy page. IPv4/IPv6 rules distinguish
OWNED from EXCLUDED. An owned rule can suppress any selection of the current
traffic classes for flows **initiated by** that asset. Predictions remain in
storage, live events and review; only delivery into the detection policy is
suppressed. Scans targeting an owned server remain eligible for alerting.

Any matching exclusion wins, on either endpoint. Local/raw packets bypass flow
aggregation; remote flow/feature records bypass storage and scoring. A final
publication check handles flows already open when a policy changes. Previously
stored records are not retroactively deleted. Capture counters still include
received traffic; exclusion counters must never be described as firewall drops.
Immutable prefix indexes keep policy reads free of filesystem/network I/O.

Spamhaus DROP (IPv4/IPv6) and CINS Army refresh off the packet path every six
hours, retaining original feed metadata and copyright in private cache files.
Validated feeds remain usable for at most 48 hours, with stale state visible.
No arbitrary URLs or executable feed plugins are accepted. Optional AbuseIPDB
checks require a local key file, cache results for 24 hours, and allow at most
100 unique checks per UTC day. HTTP 429 backs off for 24 hours. Optional DNSBL
configuration resides in a local file because a zone can contain credentials;
only explicitly configured response codes are listings. Provider failures and
unrecognized DNS answers are incomplete evidence, never a clean bill of health.
These integrations read reputation and never submit abuse reports or alter a
neural verdict. Names, IPs and credentials do not become metric labels.

Reverse DNS means a DNS PTR answer. Go's LookupAddr can satisfy a request from
/etc/hosts even with a custom Resolver.Dial, so using it conflates local aliases
with PTR records. The bounded DNS client queries the selected recursive resolver
directly, validates transaction/question identity, follows answer CNAME chains,
and retries truncated UDP responses over TCP. Local hosts mappings appear under
Associated names with their own provenance. They do not populate reverse DNS.

Sources: [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/),
[CINS Army](https://cinsscore.com/), [AbuseIPDB API](https://docs.abuseipdb.com/).
The original feed bytes retain provider attribution. Integrations do not imply
that all associated traffic is malicious or that these advisory lists enforce
firewall policy.
