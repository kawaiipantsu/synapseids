# The OPNsense sensors

Turn an OPNsense firewall into a sensor — or **one per interface** — for a
central SynapseIDS daemon: capture through FreeBSD's BPF devices, stream to
`synapsed` over the authenticated SYNPOIP transport, and see the classifications
in the SynapseIDS UI. Everything is configured from
**Services → SynapseIDS Sensor**.

**One `synapse-sensor` process per captured interface.** The settings page holds
a *list* of sensor instances; each has its own interface, its own sensor
identity, its own capture settings, its own log and its own authorisation
assertion. Four monitored segments are four named sensors on the daemon, which is
what makes a packet routed between two of them legible: it is reported twice, by
the two sensors that saw it, rather than two observations quietly merging into
one flow. See [ADR 0031](adr/0031-opnsense-one-sensor-process-per-interface.md)
and the [worked four-interface example](#a-worked-four-interface-example).

The firewall only observes. Flow assembly, feature extraction and
classification all happen on the daemon (unless you move them onto the firewall
with **Send**); the sensor never modifies, injects or blocks traffic
(PROJECT.md §28.17).

> **Status: untested on hardware.** Every part of this — the FreeBSD BPF
> capture source, the package, the plugin — was written and tested on Linux.
> Nobody has yet run it on a real OPNsense box. See
> [What is not verified](#what-is-not-verified) before you deploy it, and
> [ADR 0014](adr/0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md)
> for the design.

## 1. Install

### The recommended way: read it, then run it

The installer runs as root on your firewall. Download it, read it, then run it:

```sh
fetch -o install.sh https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh
less install.sh
sh ./install.sh
```

### The convenience one-liner

```sh
fetch -qo - https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh | sh
# pinned to a release
fetch -qo - https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh | sh -s -- --version v0.2.0
```

Piping a remote script into a shell executes unreviewed code as root on the
device that guards your network. It is offered because it is convenient, not
because it is the safer option — prefer the three lines above.

### What the installer does

1. Refuses to run unless the host is FreeBSD **and** has
   `/usr/local/opnsense/version/core`, and unless it is running as root. It
   never calls `sudo`.
2. Reads `pkg config abi` to pick the matching package (`FreeBSD:14:amd64` →
   the `freebsd14-amd64` build).
3. Resolves the release tag (latest, or `--version`), then downloads the
   `.pkg` and `SHA256SUMS` from the GitHub release (or from `--url <base>`).
4. **Verifies the checksum before installing**, with `sha256 -q`. No
   `SHA256SUMS`, or no entry for this file, is a hard failure — it will not
   install an unverified package.
5. `pkg add -f` the local file, so re-running upgrades in place.
6. Refreshes the plugin registration and restarts `configd` so the new pages
   appear.

Flags: `--version <tag>`, `--url <base>`, `--grant-bpf`, `--dry-run`,
`--uninstall`, `--help`.

**The installer never touches the bearer token.** It does not ask for one, does
not accept one on the command line, and never transmits or logs one. The token
is entered in the web UI afterwards, so it cannot land in shell history or in
`ps(1)`.

### Granting BPF access

The sensor runs as the unprivileged `_synapseids` account, not as root, so it
needs read access to `/dev/bpf*`. Changing device permissions on a firewall is
not something a package should do behind your back, so it is opt-in — either
re-run the installer with `--grant-bpf`, or do it yourself:

```sh
printf "[synapseids_bpf=10]\nadd path 'bpf*' mode 0640 group net\n" >> /etc/devfs.rules
sysrc devfs_system_ruleset=synapseids_bpf
service devfs restart
```

Without it the sensor refuses to start and prints exactly these commands.

## 2. Configure

**Services → SynapseIDS Sensor** has two parts: a **grid of sensor instances**,
one per interface, and below it the settings they share.

### The shared settings — one collector, one identity

| field | meaning |
|-------|---------|
| Enable sensors | master switch. Start the configured instances with the firewall |
| Mode | **Daemon connects to this firewall** (`--listen`) or **This firewall connects out** (`--connect`) |
| Collector address | connect mode: the `host:port` every instance dials |
| Bearer token | the shared secret for the SYNPOIP handshake. One for the firewall — instances are told apart by their **sensor IDs**, not by their credentials |
| Verify peer / CA | TLS trust for the daemon, in connect mode |
| Client certificate / key | optional mutual TLS, used by every instance |

### Each sensor instance

| field | meaning |
|-------|---------|
| Enabled | run a `synapse-sensor` process for this interface |
| Name | letters, digits and underscores. Not decoration: it names the service profile (`service synapseids_sensor restart wan`), the rendered configuration, the pidfile, the log directory and the selftest column. Name it after the interface |
| Interface | the single interface this instance captures — one process, one device |
| Sensor ID | the identity reported to the daemon. **Must differ from every other instance's**: it is the only thing that tells two observations of the same routed packet apart |
| Location | free-form label shown in the daemon's capture-sources view |
| Listen address | listen mode only: `host:port` this instance binds. **Each instance needs its own port** — four processes cannot share one |
| Filter | a built-in cBPF preset: all, `ip`, `ip6`, `ip-any`, `not-arp`. There is no filter-expression compiler (§28.16) |
| Direction | `in` for inbound only (the WAN-sensor default), `out`, or both |
| Promiscuous | see traffic not addressed to the firewall — usually wanted on a routed edge or a SPAN port |
| Snaplen | bytes captured per frame |
| BPF buffer (advanced) | store-buffer bytes for the capture device (`--bpf-buffer`). Blank = 512 KiB. FreeBSD clamps the request to `net.bpf.maxbufsize` (also 512 KiB out of the box), so raising it here only helps once `sysctl net.bpf.maxbufsize` is raised too — the sensor log prints requested vs granted at start. A bigger buffer absorbs bursts before the kernel drops frames (#128) |
| Send | what leaves the firewall for **this segment** (`--mode`): **Raw packets** (every frame, the default), **Flow records** (flows assembled here — around 1.4 % of the raw bandwidth), or **Feature vectors only** (only the 48 computed features, so **no packet content from this segment ever leaves the box** — around 1.8 %). Classifications are identical in all three; the two record modes need a daemon that speaks SYNPOIP v2, and an older one refuses the connection rather than quietly reverting to sending packets. Per instance, so a sensitive internal segment can be feature-only while the WAN stays raw. See [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md) |
| **I am authorised to monitor this interface** | required, **per instance**. Being authorised to monitor the WAN uplink is not being authorised to monitor a tenant VLAN, so this is asked separately for every instance and is never inherited from another one or set by the grid's enable toggle (§28.18, §21) |

The form refuses to save two instances that share a **name**, a **sensor ID**, an
**interface** or a **listen port**. None of those is tidiness: each one would
leave a sensor that never runs, or a segment whose flows are attributed to the
wrong place.

### Upgrading from a single-sensor release

The package's `post-install` runs the model migration. The interface that was
being captured comes back as an **enabled, authorised instance** with all of its
settings; any further interfaces that the old multi-select accepted but never
actually captured come back **disabled and unauthorised**, named and visible, for
you to review — enabling them is a new authorisation decision, so the plugin will
not make it for you.

If the instance list is empty after an upgrade, nothing has been lost: the
settings are still in `config.xml` and the migration simply has not run. The page
says so, and one command fixes it:

```sh
/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/SynapseIDSSensor
```

## A worked four-interface example

A gateway with WAN, a DMZ, an IoT VLAN and a management VLAN, streaming to a
collector at `ids.example.net:4789`. **Connect** mode, because four instances
dialling out need no inbound rules and no extra ports.

**Shared settings**

| | |
|---|---|
| Enable sensors | ✔ |
| Mode | This firewall connects out (`--connect`) |
| Collector address | `ids.example.net:4789` |
| Bearer token | the collector's token |
| Verify collector certificate | ✔, with the collector CA pasted below |

**Instances**

| Enabled | Name | Interface | Sensor ID | Location | Direction | Promisc | Send | Authorised |
|---|---|---|---|---|---|---|---|---|
| ✔ | `wan` | WAN | `fw1-wan` | `hq/edge` | Inbound only | ✔ | Raw packets | ✔ |
| ✔ | `dmz` | DMZ | `fw1-dmz` | `hq/dmz` | Both | ✔ | Flow records | ✔ |
| ✔ | `iot` | IOT | `fw1-iot` | `hq/iot` | Both | ✔ | Flow records | ✔ |
| ✔ | `mgmt` | MGMT | `fw1-mgmt` | `hq/mgmt` | Both | ✔ | Feature vectors only | ✔ |

`mgmt` is feature-only because management traffic is the segment you least want
copied off the box; `wan` is raw because the uplink is where full fidelity is
worth the bandwidth.

Press **Save**. That renders the index and one configuration per instance, fixes
their permissions and restarts the sensors. On the box:

```sh
service synapseids_sensor selftest        # 10 checks per instance, the name in a column
service synapseids_sensor status
ls -l /var/run/synapseids/                # wan.pid dmz.pid iot.pid mgmt.pid
ls -l /var/log/synapseids/*/sensor.log    # one log per instance
service synapseids_sensor restart iot     # one segment, without disturbing the others
tail -f /var/log/synapseids/iot/sensor.log
```

And on the daemon, four sensors rather than one:

```sh
curl -s http://127.0.0.1:8080/api/v1/sensors | jq '.[] | {id, location, packets}'
```

In **listen** mode the same four instances additionally need four ports —
`0.0.0.0:4789`, `:4790`, `:4791`, `:4792` — one firewall rule each, and four
`capture.sources[]` entries on the daemon. That is the cost of `listen` with
several instances, and the reason `connect` is the mode that scales here.

### Which mode to pick

**Both modes work now.** `connect` mode is the better fit for a firewall and is
what most deployments should use; `listen` mode remains the plugin's shipped
default and is unchanged.

**`connect` mode — the firewall dials out (recommended).** Nothing has to reach
*into* the firewall: no inbound rule, no NAT port-forward, no hole in the box you
are trying to monitor. The sensor reconnects with capped exponential backoff and
jitter, so a daemon restart heals itself. Enable the daemon-side collector
([ADR 0018](adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md)):

```jsonc
"capture": {
  "collector": {
    "listen": "0.0.0.0:4789",
    "cert_file": "/etc/synapseids/collector.crt",     // the daemon is the TLS server here
    "key_file":  "/etc/synapseids/collector.key",
    "token_file": "/etc/synapseids/collector.token",  // the same token the firewall holds
    "client_ca_file": "/etc/synapseids/sensors-ca.pem", // optional mTLS; authenticates the firewall
    "max_sensors": 32,
    "authorized": true
  }
}
```

In the plugin form set **Mode** to *This firewall connects out*, point **Server**
at the daemon's collector `host:port`, and set **Verify peer / CA** to the
daemon's certificate (`collector.crt` doubles as its own CA if you generated it
with `synapse-sensor gen-cert`). The firewall then appears on the daemon's
`GET /api/v1/sensors` under its **Sensor ID** and **Location**, and as a
`kind: "pcap-over-ip-listen"` row in `GET /api/v1/captures`.

**`listen` mode — the daemon dials the firewall.** Still fully supported, exactly
as [ADR 0012](adr/0012-pcap-over-ip-transport.md) describes. Add a firewall rule
permitting the daemon's address to reach the sensor port, and a matching
`capture.sources[]` entry on the daemon:

```jsonc
{ "name": "opnsense-wan", "kind": "pcap-over-ip",
  "addr": "10.0.0.1:4789",
  "token_file": "/etc/synapse/opnsense.token",
  "ca_file": "/etc/synapse/opnsense-sensor-ca.pem",
  "authorized": true }
```

Note the asymmetry that survives: a `listen`-mode source has **no auto-reconnect**
on the daemon side, so a dropped stream sits in `state: "error"` until `synapsed`
restarts. `connect` mode does reconnect, because the reconnecting end is the one
that dials.

### Where the secrets live

| file | mode / owner | contents |
|------|--------------|----------|
| `/usr/local/etc/synapseids/` | `0750 root:_synapseids` | |
| `/usr/local/etc/synapseids/sensor.conf` | `0640 root:wheel` | the instance index. **No flags, no secrets.** |
| `/usr/local/etc/synapseids/instances/` | `0750 root:_synapseids` | |
| `/usr/local/etc/synapseids/instances/<name>.conf` | `0640 root:wheel` | one per instance: its command-line flags. **No secrets.** |
| `/usr/local/etc/synapseids/sensor.token` | `0400 _synapseids:_synapseids` | **the bearer token, and nothing else** |
| `/usr/local/etc/synapseids/sensor-ca.pem` | `0444 root:wheel` | peer CA bundle (optional) |
| `/usr/local/etc/synapseids/sensor-cert.pem` | `0444 root:wheel` | this firewall's certificate (optional mTLS) |
| `/usr/local/etc/synapseids/sensor-key.pem` | **`0400 _synapseids:_synapseids`** | **this firewall's TLS private key** |

Every one of these is rendered by configd from the OPNsense configuration store —
nothing is placed on the firewall by hand. The two secrets are per *firewall*,
not per instance: there is one collector and one firewall identity, and
duplicating a token and a private key per sensor would multiply what has to be
protected without protecting anything.

**The bearer token never reaches a command line.** It is passed with
`--token-file`, never `--token`, so it is absent from `ps(1)`, from the
rendered flag string, from shell history and from every log line. Logs go to
`/var/log/synapseids/` and never contain it. It also lives in the OPNsense
configuration store, which is what the UI reads and writes.

**The TLS private key is treated exactly like the bearer token.** configd renders
templates as root under its own umask, so the `fixperms` configd action clamps
every mode immediately after every `template reload` — closing the window in
which a freshly rendered secret would sit world-readable — and the `rc.d` script
re-checks before every start. The same action creates each instance's log
directory and removes the rendered configuration of an instance that has been
renamed or deleted. `service synapseids_sensor selftest` reports the
modes it actually finds, so this is checkable on the box rather than assumed.

**It fails safe.** The `rc.d` script refuses to start, naming the path, whenever
a flag references a PEM that is missing, empty or has no `-----BEGIN` line. There
is no path that turns absent TLS material into an unverified connection. The
model also refuses at save time to store a blob that is not PEM, a private key
pasted into a certificate field, a passphrase-protected key, or a key that does
not match its certificate.

## 3. Verify

On the daemon:

```sh
curl -s http://127.0.0.1:8080/api/v1/captures | jq
```

**One entry per enabled instance**, each with `"state": "running"`, a rising
`packets`, a real `connection_latency_ms`, and a `filter` describing that
capture (`"wan in ip-any promisc"`). Four configured instances and three entries
means one sensor is not running — that is the check worth doing, because it is
the failure this design exists to make visible.

```sh
curl -s http://127.0.0.1:8080/api/v1/sensors | jq '.[] | {id, location, packets}'
```

Classifications then show up in `GET /api/v1/classifications` and in the live
rolling log at `http://127.0.0.1:8080/`, attributed to the sensor that saw them.

On the firewall:

```sh
service synapseids_sensor status          # one block per instance
service synapseids_sensor status wan      # just that one
tail -f /var/log/synapseids/wan/sensor.log
```

## 4. Troubleshoot

| symptom | cause / fix |
|---------|-------------|
| `bpf: open /dev/bpf failed: permission denied` | the devfs rule is missing — see [Granting BPF access](#granting-bpf-access). The message prints the exact commands. |
| `bpf: no usable BPF device` | every device is busy, or devfs exposes none. Another capture (tcpdump, the OPNsense packet-capture page) may be holding them. |
| `interface "x" uses BSD loopback framing (DLT 0)` | you selected a tunnel/PPPoE pseudo-interface. Capture on the physical parent instead. |
| `reports link type DLT n` | SynapseIDS decodes only Ethernet (DLT 1) and raw IP (DLT 12/101). |
| The service starts but the daemon shows no packets | check the direction: `in` only captures inbound. Check the filter preset. Check the firewall rule allowing the daemon to reach the sensor port. |
| `pcapoverip: server rejected connection (unauthorized)` | the daemon's token and the sensor's token differ. |
| Rising `drops` in `/api/v1/captures` | the kernel discarded frames before the sensor read them (`BIOCGSTATS` `bs_drop`). Confirm on the box with `netstat -B`: if `Sblen`/`Hblen` are at their maximum the kernel is batching fine and the *sensor* is not draining. Raise the **BPF buffer** (and `sysctl net.bpf.maxbufsize` to match — the sensor log shows requested vs granted at start), lower the snaplen, narrow the filter — or stop re-streaming every byte and switch to `--mode flow` / `--mode feature`. A `raw` sensor on a saturated uplink ships as much traffic as it sees. |
| The Services page does not appear after install | `service configd restart`, then reload the web UI. The package's post-install does this, but a partial install may not have. |
| The instance list is empty after an upgrade | the model migration has not run. **Nothing is lost** — the settings are still in `config.xml`. Run `/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/SynapseIDSSensor` and reload the page. The page shows a banner saying exactly this when it detects the state. |
| One instance runs and the others do not | `service synapseids_sensor selftest` and read the `[FAIL]` line for the instance name in question — most often an interface that no longer resolves, or (in listen mode) a port another instance already holds. |
| A deleted instance is still capturing | `service synapseids_sensor restart`, which sweeps pidfiles that belong to no configured instance. Report it if it recurs: the sweep is meant to make this impossible. |
| Instances share a log file, or a log is empty | each instance writes to `/var/log/synapseids/<name>/sensor.log`. An empty one while the sensor runs is the known `daemon(8) -f` question — capture is unaffected; the selftest's `log-sink` line prints the remedy. |

## What is not verified

Nobody has run any of this on FreeBSD or OPNsense. Concretely:

- **The BPF capture source is compile-verified only.** `GOOS=freebsd` builds
  for amd64 and arm64 pass, and the ioctl request numbers are machine-checked
  against the FreeBSD ABI at compile time — but no packet has been captured
  through it. The chunk parser and the ioctl derivation *are* unit-tested, on
  Linux.
- **The package has never been through `pkg add`.** It is structurally verified
  at build time (member order, manifest keys, per-file checksums against the
  archived bytes, modes, ownership), but `pkg(8)` has not accepted it.
- **The plugin has never been loaded by an OPNsense MVC runtime.** The PHP is
  `php -l`-clean, every XML parses, every configd template has been rendered with
  configd's own Jinja environment and `+TARGETS` expansion against a mock config,
  and the model's validation rules and the 1.0.0 → 1.0.1 migration have been
  exercised against real generated key material and a real pre-upgrade
  configuration (`contrib/opnsense/tools/check-plugin.sh`) — but no Phalcon and
  no configd has loaded any of it.
- **Nothing about the multi-instance work has run on hardware.** Specifically
  unproven: that configd's repeating `+TARGETS` target really writes one file per
  instance; that four `synapse-sensor` processes can hold four BPF descriptors at
  once (`/dev/bpf` is a cloning device, so they should); that the rc.d profile
  loop starts, stops and reports each instance independently; that the orphan
  pidfile sweep stops a deleted instance; and that the model migration rewrites a
  real `config.xml` correctly. **Take a configuration backup before the first
  upgrade.**
- **Real WAN traffic has now been captured once**, and it found a real bug: a
  5 GB download through a `raw`-mode sensor dropped 63% of frames in the kernel
  (`netstat -B`: `Recv 1455970 / Drop 916190`, both buffers full, 81% CPU)
  because the sensor wrote one TLS record and one syscall per packet. That is
  fixed — outbound frames are batched, 10.6× cheaper per frame over TLS, see
  [ADR 0029](adr/0029-synpoip-batched-sensor-writes.md) — but the post-fix drop
  rate on the same box has not been re-measured, and timestamp accuracy under
  load is still unmeasured.

A maintainer with a real box should, in order:

```sh
# 1. does pkg accept the package at all?
pkg info -F dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
pkg add     dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg

# 2. upgrading? confirm the migration ran and kept the sensor you had.
/usr/local/opnsense/mvc/script/run_migrations.php -v OPNsense/SynapseIDSSensor

# 3. do the UI pages appear? Services > SynapseIDS Sensor
#    add one instance per interface, save, then:

# 4. did the repeating template really produce one file per instance?
ls -l /usr/local/etc/synapseids/instances/

# 5. THE SELFTEST. One command, one line per check, the instance in its own
#    column, remedies inline.
service synapseids_sensor selftest

# 6. does the capture source actually open? and two at once?
/usr/local/bin/synapse-sensor pcap-over-ip \
    --listen 127.0.0.1:4789 --iface em0 --authorized --direction in --filter ip-any

# 7. does a daemon see one sensor per instance?  GET /api/v1/sensors
```

**Start with the selftest.** For every configured instance it checks the binary,
the `_synapseids` account, `/dev/bpf*` access, that that instance's interface
resolved to a device that actually exists, that its rendered configuration
parses, that the token is `0400`, that the TLS material parses and that the
certificate matches its key, and whether the daemon answers a TCP connect. Every
line carries its own remedy and the instance it belongs to; the per-line
troubleshooting table is in
[`contrib/opnsense/README.md`](../contrib/opnsense/README.md#troubleshooting-by-output-line).

Please report what breaks — especially anything a selftest `interface` line says,
and the value of `synapseids_sensor_iface_src` in
`/usr/local/etc/synapseids/instances/<name>.conf`, which records *which* of the
two interface lookups succeeded.
