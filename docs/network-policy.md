# Network policy and reputation

Open **System → Network policy**. Add an IP or CIDR, give it an asset label, and
select **OWNED · inspect traffic**. Select only the classifications whose alerts
you want to suppress, then **Save policy**. Changes take effect immediately.
Suppression applies to flows initiated by the asset. Original classifications
remain visible with a `muted` marker; traffic targeting the asset is still
inspected and eligible for detection. Ownership is an operator assertion, not
an inference from DNS or cloud-provider allocation.

For complete IDS bypass, select **EXCLUDED · bypass IDS**. This affects either
endpoint and all classifications. It takes precedence over owned rules, including
more-specific rules. Previously retained data stays until normal retention.
Capture statistics count received packets; exclusion statistics count bypasses.

Rules can be edited or removed on the same page. The daemon stores them in
`policy_file` (default `./data/policy.json`, private mode 0600). Concurrent edits
are detected by revision: reload, reapply your edits, and save. An invalid policy
file prevents startup so exclusions cannot silently disappear.

## Reputation

Enable the providers on the same page. Feed changes take effect within a minute.
Spamhaus DROP and CINS Army need no key. The status table reports provider health,
entry counts and last successful download. These sources refresh every six hours;
stale matches are marked and feeds older than 48 hours no longer produce matches.
Spamhaus Project copyright and date metadata are retained with the original data.

Optional provider configuration belongs in the daemon configuration:

```json
{
  "policy_file": "/var/lib/synapseids/policy.json",
  "reputation": {
    "abuseipdb_key_file": "/etc/synapseids/secrets/abuseipdb.key",
    "dnsbl_file": "/etc/synapseids/secrets/dnsbl.json"
  }
}
```

The key file contains only your AbuseIPDB API key. Set permissions to 0600 and
restart after adding/changing secret files. Enabling the provider without its
secret shows `needs_credentials`. Checks use a 30-day report window and mark
`BadRep` at confidence 75 or greater. Results cache for 24 hours; budget is 100
unique addresses per UTC day per process. Restart resets the budget, so avoid
frequent restarts when using a limited account. No abuse reports are submitted.

A DNSBL file is an array of configurations. Use your provider's documented return
codes and permitted resolver. Example with a documentation-only zone:

```json
[
  {
    "name": "Example RBL",
    "zone": "rbl.example.test",
    "codes": {"127.0.0.2": "Listed for abusive activity"}
  }
]
```

Do not copy a mail-policy code into a malware category. NXDOMAIN means unlisted;
timeouts, SERVFAIL and unexpected answers mean unavailable/unrecognized. Provider
error responses in 127.255.255.0/24 cannot be configured as listings. DNSBL zones
may contain an account key, so they never appear in API responses or metrics.

Visible observed public addresses trigger bounded asynchronous lookups. Private,
reserved and excluded addresses never reach external reputation services. Lists,
flow rows and host details show `BadRep` / `RBL` tags with provider, reason and
freshness. A tag is advisory evidence and never changes the trained prediction.
Absence of a tag does not establish safety.

## Reverse DNS versus associated names

**Reverse DNS · PTR** contains only actual DNS PTR responses from the configured
resolver. **Associated names** lists local hosts-file names with explicit source.
A forward mapping can share an IP with many other domains, and it is not a PTR.
These labels are informational; neither one establishes ownership.

## Monitoring

`/metrics` adds policy excluded packet/record counters, suppressed alert counter,
reputation provider readiness, feed sizes and successful-update timestamps.
Policy exclusions are IDS bypasses and are not firewall drop counters.
