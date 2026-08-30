# `contrib/` — operator deployment assets

THUGS(red) SynapseIDS · MIT licensed

Reference material for running SynapseIDS on a Linux host: a hardened systemd
unit set, an annotated production config, a TLS reverse-proxy block, and a few
maintenance scripts. Nothing here is installed by `go build` or the `.deb` — it
is copied into place by hand (or by your configuration management). Every file
carries a header comment with its exact install path and commands; this page is
the map.

The three binaries: **`synapsed`** (the daemon — capture → flow → feature →
inference → REST + WebSocket API, binds `127.0.0.1:8080`), **`synapse`** (admin
CLI, talks to `synapsed` over HTTP), **`synapse-sensor`** (Phase-6 placeholder,
not functional yet).

---

## Quick start (daemon on one host, behind nginx)

```sh
# 1. binaries
sudo ./install.sh                      # or: sudo dpkg -i synapseids_*.deb

# 2. user + directories  (order matters: sysusers -> tmpfiles)
sudo install -m 0644 contrib/systemd/synapseids.sysusers  /usr/lib/sysusers.d/synapseids.conf
sudo install -m 0644 contrib/systemd/synapseids.tmpfiles  /usr/lib/tmpfiles.d/synapseids.conf
sudo systemd-sysusers
sudo systemd-tmpfiles --create

# 3. config
sudo install -D -m 0640 -o root -g synapse contrib/config/synapse.json   /etc/synapseids/synapse.json
sudo install    -m 0640 -o root -g synapse contrib/systemd/synapsed.env  /etc/synapseids/synapsed.env   # optional

# 4. service
sudo install -m 0644 contrib/systemd/synapsed.service /etc/systemd/system/synapsed.service
sudo systemctl daemon-reload
sudo systemctl enable --now synapsed
curl -fsS localhost:8080/api/v1/status | jq .

# 5. remote access: TLS + auth at the edge
sudo install -m 0644 contrib/nginx/synapseids.conf /etc/nginx/sites-available/synapseids.conf
sudo ln -s ../sites-available/synapseids.conf /etc/nginx/sites-enabled/
sudo htpasswd -c /etc/nginx/synapseids.htpasswd operator   # then uncomment auth_basic in the conf
sudo nginx -t && sudo systemctl reload nginx
```

---

## systemd — `contrib/systemd/`

| File | Installs to | Purpose |
|---|---|---|
| `synapseids.sysusers` | `/usr/lib/sysusers.d/synapseids.conf` | Creates the unprivileged `synapse` user + group (no login, home `/var/lib/synapseids`). |
| `synapseids.tmpfiles` | `/usr/lib/tmpfiles.d/synapseids.conf` | Creates `/var/lib/synapseids` (`0750 synapse:synapse`) and `/etc/synapseids` (`0755 root:root`). |
| `synapsed.service` | `/etc/systemd/system/synapsed.service` | Hardened unit for the daemon. |
| `synapse-sensor.service` | `/etc/systemd/system/synapse-sensor.service` | Hardened unit for the sensor — **Phase-6 placeholder, do not enable.** |
| `synapsed.env` | `/etc/synapseids/synapsed.env` | Example `EnvironmentFile`: every `SYNAPSE_*` override, commented, documented. |

**Ordering constraints**

1. `systemd-sysusers` **before** `systemd-tmpfiles` — tmpfiles chowns the state
   dir to `synapse`, which must exist first.
2. tmpfiles and `/etc/synapseids/synapse.json` in place **before** the first
   `systemctl start`. (`StateDirectory=` / `ConfigurationDirectory=` in the unit
   also create the dirs, so a start without tmpfiles still works — tmpfiles just
   pins mode/owner for packaged installs.)
3. `systemctl daemon-reload` after copying or editing any unit.

Install the units:

```sh
sudo install -m 0644 contrib/systemd/synapsed.service       /etc/systemd/system/synapsed.service
sudo install -m 0644 contrib/systemd/synapse-sensor.service /etc/systemd/system/synapse-sensor.service   # not enabled
sudo systemctl daemon-reload
sudo systemctl enable --now synapsed
```

**What the hardening does** (PROJECT.md §21): runs as `synapse`, not root;
grants only `CAP_NET_RAW` + `CAP_NET_ADMIN` as *ambient* capabilities for the
live capture that arrives in Phase 3 (Phase-1 PCAP replay needs none — comment
the two `*Capabilities=` lines out for a replay-only host); `ProtectSystem=strict`
with a read-only `/` except `StateDirectory=synapseids`; `NoNewPrivileges`,
`PrivateTmp`, `PrivateDevices`, kernel/cgroup/namespace/realtime restrictions,
`MemoryDenyWriteExecute` (safe for the pure-Go binary), a `@system-service`
syscall filter, and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
AF_PACKET`. Tune `MemoryMax=` (default `2G`) and `LimitNOFILE=` to the host.

`synapse-sensor.service` keeps the same posture but its `[Install]` section is
commented out on purpose: the binary only answers `synapse-sensor version` today
and will exit non-zero as started by the unit. Do not `systemctl enable` it
until Phase 6.

---

## config — `contrib/config/`

| File | Installs to | Purpose |
|---|---|---|
| `synapse.json` | `/etc/synapseids/synapse.json` | Complete, valid production config — every key from `internal/config/config.go` set explicitly. |
| `synapse.annotated.md` | (documentation, not installed) | Per-key reference: type, default, meaning, validation rules. Cross-references PROJECT.md §23. |

```sh
sudo install -D -m 0640 -o root -g synapse contrib/config/synapse.json /etc/synapseids/synapse.json
sudo -u synapse /usr/bin/synapsed --config /etc/synapseids/synapse.json --version   # smoke test parse
```

Notes: config is **JSON, not YAML**. Durations are Go strings (`"30s"`, `"5m"`,
`"720h"`) — there is no day/week unit, so 30 days is `"720h"`. `storage.driver`
must be `"memory"` (`"sqlite"` is parsed then rejected). Unknown keys are a hard
error. Anything host-specific or secret goes in `synapsed.env`, not this file.
`server.listen` stays on loopback — nginx handles remote access.

---

## nginx — `contrib/nginx/`

| File | Installs to | Purpose |
|---|---|---|
| `synapseids.conf` | `/etc/nginx/sites-available/synapseids.conf` (symlink into `sites-enabled/`) or `/etc/nginx/conf.d/synapseids.conf` | TLS-terminating reverse proxy to `127.0.0.1:8080`. |

Proxies `/`, `/api/` and the `/api/v1/stream` WebSocket (HTTP/1.1 +
`Upgrade`/`Connection` + 1 h `proxy_read_timeout`). `listen 443 ssl` with
`ssl_protocols TLSv1.2 TLSv1.3` and `ssl_certificate` placeholders. Ships a
**commented-out** `auth_basic` block — PROJECT.md §21 requires authenticating all
non-local access, so uncomment it (or put mTLS / an SSO proxy in front) before
exposing the host.

```sh
sudo install -m 0644 contrib/nginx/synapseids.conf /etc/nginx/sites-available/synapseids.conf
sudo ln -s ../sites-available/synapseids.conf /etc/nginx/sites-enabled/synapseids.conf
sudo htpasswd -c /etc/nginx/synapseids.htpasswd operator
# edit the conf: set server_name, real ssl_certificate paths, uncomment auth_basic
sudo nginx -t && sudo systemctl reload nginx
```

---

## logrotate — `contrib/logrotate/`

| File | Installs to | Purpose |
|---|---|---|
| `synapseids` | `/etc/logrotate.d/synapseids` | Rotates `/var/log/synapseids/*.log` weekly, keep 8, compress + delaycompress, `copytruncate`. |

`synapsed` logs to stdout → journald by default, so this is **only** for
deployments that redirect output to files (a unit drop-in with
`StandardOutput=append:/var/log/synapseids/synapsed.log`). Journald's own size
limits live in `journald.conf`, not here.

```sh
sudo install -m 0644 contrib/logrotate/synapseids /etc/logrotate.d/synapseids
sudo logrotate --debug /etc/logrotate.d/synapseids   # dry run
```

---

## apparmor — `contrib/apparmor/`

| File | Installs to | Purpose |
|---|---|---|
| `usr.bin.synapsed` | `/etc/apparmor.d/usr.bin.synapsed` | Permissive-but-real confinement: read `/etc/synapseids/**`, read/write `/var/lib/synapseids/**`, read the (adjustable) PCAP dirs, `inet`/`inet6`/`packet` networking, `net_raw` + `net_admin` capabilities, deny-by-default for everything else. |

```sh
sudo install -m 0644 contrib/apparmor/usr.bin.synapsed /etc/apparmor.d/usr.bin.synapsed
sudo apparmor_parser -r -W /etc/apparmor.d/usr.bin.synapsed
sudo aa-complain /usr/bin/synapsed          # learn first
sudo journalctl -k | grep -i 'apparmor.*synapsed'
sudo aa-enforce  /usr/bin/synapsed          # then enforce
```

Adjust every path to your layout — especially the PCAP input directories
(`/var/lib/synapseids/pcaps/**`, `/srv/pcap/**`). Works alongside the systemd
sandbox; neither replaces the other.

---

## cron — `contrib/cron/`

| File | Installs to | Purpose |
|---|---|---|
| `synapseids-retention` | `/etc/cron.d/synapseids-retention` | Runs `/usr/local/bin/synapseids-retention-prune` daily at 03:17 as `synapse`. |

Retention is primarily configured in `synapse.json` (`retention.flows`,
`retention.classifications` — PROJECT.md §20). This cron is a belt-and-braces
external prune and an audit trail; today the script only reports daemon storage
stats (see below).

```sh
sudo install -m 0644 contrib/cron/synapseids-retention /etc/cron.d/synapseids-retention
```

---

## scripts — `contrib/scripts/`

All POSIX `sh`, `set -eu`. Install the ones you use into `/usr/local/bin/`
without the `.sh` suffix.

| File | Installs to | Purpose |
|---|---|---|
| `synapseids-retention-prune.sh` | `/usr/local/bin/synapseids-retention-prune` | Checks the daemon is up (`GET /api/v1/status`) and prints storage stats. Contains a marked `TODO(retention)` block for when a real prune endpoint exists. Env: `SYNAPSE_SERVER`, `CURL_OPTS`. |
| `synapseids-backup.sh` | `/usr/local/bin/synapseids-backup` | tar + gzip of `/var/lib/synapseids` and `/etc/synapseids` to `${BACKUP_DIR:-/var/backups/synapseids}`, keeps the newest `${KEEP:-14}`. Refuses to run as non-root. |
| `capture-ssh-example.sh` | run from a checkout / `/usr/local/bin/` | Demonstrates PROJECT.md §6: `ssh "$HOST" tcpdump -U -w - -n "$FILTER" > "$OUT"`, then replay `$OUT`. Prints an authorized-monitoring banner and requires `I_AM_AUTHORIZED=yes`. |

```sh
sudo install -m 0755 contrib/scripts/synapseids-retention-prune.sh /usr/local/bin/synapseids-retention-prune
sudo install -m 0755 contrib/scripts/synapseids-backup.sh           /usr/local/bin/synapseids-backup

HOST=user@sensor.example.org FILTER='not port 22' I_AM_AUTHORIZED=yes \
  contrib/scripts/capture-ssh-example.sh
```

---

## Security notes (PROJECT.md §21)

- **Localhost by default.** `synapsed` binds `127.0.0.1:8080` and does no auth or
  TLS of its own. A non-loopback `server.listen` is allowed but logged as a
  `WARNING` at startup.
- **Authenticate all non-local access.** The nginx block is the supported edge:
  TLS + `auth_basic` at minimum, mTLS or SSO preferred. Never expose the raw
  daemon port.
- **TLS for remote sensors and remote UI.** `ssl_protocols TLSv1.2 TLSv1.3`;
  Phase-6 sensor transport will be authenticated + encrypted.
- **Least-privilege capture.** Do not run the daemon as root. The unit runs as
  `synapse` and isolates capture with ambient `CAP_NET_RAW` + `CAP_NET_ADMIN`
  only; Phase-1 replay needs no capabilities at all. The AppArmor profile is a
  second layer.
- **Remote capture only where authorized.** `capture-ssh-example.sh` will not run
  without `I_AM_AUTHORIZED=yes`. Development/testing captures must be authorized
  or synthetic (§28.18).
- **Untrusted input.** All packet-derived data is untrusted; uploaded
  PCAP/model/dataset inputs are validated and resource use is capped; queues are
  bounded and slow WebSocket clients are dropped (counted), never allowed to
  stall ingestion.
- **Audit trail.** Model activation, training, dataset edits and human label
  changes are audit-logged. Newly trained models are **never** auto-activated —
  activation is an explicit operator action.
- **Secrets stay out of files and logs.** Put deployment/secret values in
  `synapsed.env`, not `synapse.json`; SSH keys use normal OS/`ssh` mechanisms.

---

<sub>⟦ <b>THUGS</b> ⟧ &nbsp;·&nbsp; (c) 2026 kawaiipantsu / THUGS &nbsp;·&nbsp; MIT &nbsp;·&nbsp; localhost by default, authenticated at the edge, least privilege for capture</sub>
