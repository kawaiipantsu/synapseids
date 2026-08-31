# The OPNsense WAN sensor

Turn an OPNsense firewall into an inbound-WAN sensor for a central SynapseIDS
daemon: capture on the WAN interface through FreeBSD's BPF devices, stream the
raw frames to `synapsed` over the authenticated SYNPOIP transport, and see the
classifications in the SynapseIDS UI. Everything is configured from
**Services → SynapseIDS Sensor**.

The firewall only observes. Flow assembly, feature extraction and
classification all happen on the daemon; the sensor never modifies, injects or
blocks traffic (PROJECT.md §28.17).

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

**Services → SynapseIDS Sensor**:

| field | meaning |
|-------|---------|
| Enabled | start the sensor with the firewall |
| Interface | the interface(s) to capture — WAN for an inbound-edge sensor |
| Filter | a built-in cBPF preset: all, `ip`, `ip6`, `ip-any`, `not-arp`. There is no filter-expression compiler (§28.16) |
| Direction | `in` for inbound only (the WAN-sensor default), `out`, or both |
| Promiscuous | see traffic not addressed to the firewall — usually wanted on a routed edge |
| Snaplen | bytes captured per frame |
| Send | what leaves the firewall (`--mode`): **Raw packets** (every frame, the default), **Flow records** (flows assembled here — around 1.4 % of the raw bandwidth), or **Feature vectors only** (only the 48 computed features, so **no packet content ever leaves the box** — around 1.8 %). Classifications are identical in all three; the two record modes need a daemon that speaks SYNPOIP v2, and an older one refuses the connection rather than quietly reverting to sending packets. See [ADR 0024](adr/0024-sensor-modes-and-synpoip-record-frames.md) |
| Mode | **Daemon connects to this firewall** (`--listen`) or **This firewall connects out** (`--connect`) |
| Listen address / Daemon address | depending on the mode |
| Bearer token | the shared secret for the SYNPOIP handshake |
| Verify peer / CA | TLS trust for the daemon, in connect mode |
| Client certificate / key | optional mutual TLS |
| Sensor ID / Location | labels shown in the daemon's capture-sources view |
| **I am authorised to monitor this traffic** | required. The form will not save an enabled sensor without it (§28.18, §21) |

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
| `/usr/local/etc/synapseids/sensor.conf` | `0640 root:wheel` | the command-line flags. **No secrets.** |
| `/usr/local/etc/synapseids/sensor.token` | `0400 _synapseids:_synapseids` | **the bearer token, and nothing else** |
| `/usr/local/etc/synapseids/peer-ca.pem` | `0444 root:wheel` | peer CA bundle (optional) |
| `/usr/local/etc/synapseids/sensor-cert.pem` | `0444 root:wheel` | this sensor's certificate (optional mTLS) |
| `/usr/local/etc/synapseids/sensor-key.pem` | `0400 _synapseids:_synapseids` | this sensor's private key (optional mTLS) |

**The bearer token never reaches a command line.** It is passed with
`--token-file`, never `--token`, so it is absent from `ps(1)`, from the
rendered flag string, from shell history and from every log line. Logs go to
`/var/log/synapseids/` and never contain it. It also lives in the OPNsense
configuration store, which is what the UI reads and writes.

The `fixperms` configd action clamps these modes immediately after every
`template reload`, closing the window in which configd's default umask would
otherwise leave a freshly rendered token file readable; the `rc.d` script
re-checks before every start.

> **Gap: the TLS PEM files are not yet rendered.** The model stores the CA
> bundle, certificate and key as PEM text, but `sensor.conf` only *names* the
> three paths above — delivering the text itself needs three more configd
> template targets, which this package does not yet install. Until then, place
> the files by hand at those paths. This fails safe: the `rc.d` script refuses
> to start, naming the missing file, whenever a flag references a PEM that is
> not on disk, so a missing certificate can never silently downgrade the
> transport.

## 3. Verify

On the daemon:

```sh
curl -s http://127.0.0.1:8080/api/v1/captures | jq
```

The sensor should appear with `"state": "running"`, a rising `packets`, a real
`connection_latency_ms`, and a `filter` describing the capture (`"wan in
ip-any promisc"`). Classifications for WAN flows then show up in
`GET /api/v1/classifications` and in the live rolling log at
`http://127.0.0.1:8080/`.

On the firewall:

```sh
service synapseids_sensor status
tail -f /var/log/synapseids/sensor.log
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
| Rising `drops` in `/api/v1/captures` | the kernel discarded frames before the sensor read them (`BIOCGSTATS` `bs_drop`). Raise the snaplen down or the buffer up, or narrow the filter. |
| The Services page does not appear after install | `service configd restart`, then reload the web UI. The package's post-install does this, but a partial install may not have. |

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
  `php -l`-clean and the XML/Volt are conventional; that is all.
- **No real WAN traffic has been captured**, so throughput, drop behaviour and
  timestamp accuracy under load are unmeasured.

A maintainer with a real box should, in order:

```sh
# 1. does pkg accept the package at all?
pkg info -F dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
pkg add     dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg

# 2. do the UI pages appear? Services > SynapseIDS Sensor

# 3. does the capture source actually open?
/usr/local/bin/synapse-sensor pcap-over-ip \
    --listen 127.0.0.1:4789 --iface em0 --authorized --direction in --filter ip-any

# 4. does a daemon see packets?  GET /api/v1/captures
```

Please report what breaks — especially the configd template's interface-name
lookup, which carries an explicit `TODO(verify):`.
