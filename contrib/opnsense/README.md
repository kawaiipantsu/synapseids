# `os-synapseids-sensor` — the SynapseIDS plugin for OPNsense

Turns an OPNsense firewall into an inbound-WAN sensor for a central SynapseIDS
daemon: capture on the WAN interface through FreeBSD's BPF devices, stream to
`synapsed` over the authenticated SYNPOIP transport, and configure it all from
**Services → SynapseIDS Sensor**.

The firewall only observes. Classification always happens on the daemon; the
**Send** setting chooses whether flow assembly and feature extraction happen
there too or here on the firewall — see [Choosing what the sensor
sends](#choosing-what-the-sensor-sends), which is also how you stop packet
content leaving the box at all. The sensor never modifies, injects or blocks
traffic (PROJECT.md §28.17), and it opens the BPF device read-only so it could
not transmit even if it tried.

**Install, configure, verify and troubleshoot are documented in
[`docs/opnsense-sensor.md`](../../docs/opnsense-sensor.md).** This file covers
the packaging: what is in the plugin, how to build it, and what a maintainer
must still validate on real hardware.

> ## ⚠️ Untested on hardware
>
> Every part of this — the FreeBSD BPF capture source, the package, the MVC
> plugin — was written and tested on **Linux**. Cross-builds, unit tests and
> compile-time ABI assertions pass. Nobody has run it on FreeBSD or OPNsense.
> See [What a maintainer must
> validate](#what-a-maintainer-must-validate-on-real-hardware).

## Installing

```sh
# Recommended: fetch it, read it, run it. This is a firewall.
fetch -o install.sh https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh
less install.sh
sh ./install.sh

# Convenience one-liner
fetch -qo - https://raw.githubusercontent.com/kawaiipantsu/synapseids/main/contrib/opnsense/install.sh | sh
fetch -qo - .../install.sh | sh -s -- --version v0.2.0
```

**Why the three-line form is the recommended one:** piping a remote script into
a shell executes unreviewed code as root on the device that guards your
network. The one-liner is offered because it is convenient, not because it is
equally safe.

`install.sh` refuses to run off OPNsense or as a non-root user (it never calls
`sudo`), selects the package from `pkg config abi`, **verifies the SHA256
against the release `SHA256SUMS` before installing**, then `pkg add -f`s it and
refreshes configd. Flags: `--version <tag>`, `--url <base>` (private mirror),
`--grant-bpf`, `--dry-run`, `--uninstall`, `--help`. Re-running upgrades in
place.

**The installer never handles the bearer token.** It does not ask for one,
accept one on the command line, transmit one or log one — the token is entered
in the web UI afterwards, so it cannot end up in shell history or in `ps(1)`.
`--uninstall` removes the package and the rendered config but **deliberately
leaves the token stored in the OPNsense configuration**; clear it from the
Services page if you want it gone.

## Building the package

```sh
make build-freebsd      # cross-compile the sensor for freebsd/{amd64,arm64}
make opnsense-pkg       # -> dist/os-synapseids-sensor-<ver>-freebsd14-{amd64,arm64}.pkg
make dist               # everything, with the .pkg files in SHA256SUMS
```

`scripts/package-opnsense.sh` builds a genuine FreeBSD package from a Linux
host, with no `pkg(8)` involved. A `.pkg` is a compressed tar archive whose
leading members are the UCL metadata (`+MANIFEST`, `+COMPACT_MANIFEST` — JSON
is valid UCL) followed by the payload under absolute paths, so `tar` + `xz` +
`jq` produce one directly. This is the same posture as `scripts/package-deb.sh`,
which drives `dpkg-deb` rather than a packaging framework.

The ABI is parameterised, not hardcoded — OPNsense 24.x/25.x is FreeBSD 14:

```sh
make opnsense-pkg FREEBSD_VERSION=15
make opnsense-pkg OPNSENSE_ABIS='FreeBSD:14:amd64'
```

One `.pkg` per ABI, exactly as there is one `.deb` per Debian arch. The release
workflow publishes them on a `v*` tag, and `install.sh` reconstructs the file
name from the firewall's own `pkg config abi`.

There is also a conventional FreeBSD port skeleton — [`Makefile`](Makefile),
[`pkg-descr`](pkg-descr), [`pkg-plist`](pkg-plist) — for submitting this
upstream to an `opnsense/plugins` tree. Both paths install the same file list,
and `package-opnsense.sh` **fails the build** if the staged tree and
`pkg-plist` have drifted apart.

### What the build verifies, and what it cannot

`verify_pkg()` runs on every package and asserts everything checkable without
`pkg(8)`:

- the first two archive members are `+MANIFEST` then `+COMPACT_MANIFEST`;
- every other member is an absolute path under `/usr/local`;
- `+MANIFEST` parses and carries `name`, `origin`, `version`, `comment`,
  `desc`, `maintainer`, `www`, `abi`, `arch`, `prefix`, `categories`,
  `licenselogic`, `licenses`, `flatsize`, `deps`, `files` and `scripts` (with
  both `post-install` and `pre-deinstall`);
- every `files` entry's sha256 matches the bytes **extracted from the archive**,
  and the counts agree in both directions;
- the binary and the `rc.d` script are mode `0555`, and every member is
  `root/wheel`.

It **cannot** prove `pkg(8)` accepts the result. That needs a FreeBSD box.

## Choosing what the sensor sends

The **Send** dropdown (`send_mode` in the model, `--mode` on the command line)
decides how much of the pipeline runs on the firewall and therefore how much
crosses the link. Verdicts are identical in all three — this is a bandwidth and
privacy choice, not a detection one (issue #45,
[ADR 0024](../../docs/adr/0024-sensor-modes-and-synpoip-record-frames.md)).

| Send | leaves the firewall | wire cost | when |
|------|--------------------|-----------|------|
| **Raw packets** *(default)* | every captured frame | 100 % | the daemon or the site wants full packet fidelity, and the link can carry it |
| **Flow records** | one flow record per closed flow | **~1.4 %** | the usual choice for a WAN-attached firewall: ~70× less traffic for the same classifications |
| **Feature vectors only** | only the 48 computed features, plus each flow's endpoints and timing | **~1.8 %** | **no packet content may leave this host** — a sensitive link, or a site that permits flow telemetry off-box but not payloads |

Measured end to end, TLS included, on a 68 814-packet / 1 176-flow capture.
The cost of the two record modes is per *flow*, not per packet, so the break-even
against raw is around 4-5 packets per flow; a port scan of one-packet flows is
the worst case for them. Note that feature records are slightly *larger* than
flow records — 48 `float64` values cost more than the counters they came from —
so pick **Flow records** for bandwidth and **Feature vectors only** for privacy.

The two record modes need a SynapseIDS daemon that speaks SYNPOIP v2. An older
collector refuses the connection with `mode-unsupported`, which is deliberate: a
firewall configured for **Feature vectors only** must never quietly start
shipping packet content because the far end is old. The refusal is logged to
`/var/log/synapseids/sensor.log`.

## What is in the plugin

Sources live under `src/`, which maps to `/usr/local` on the target
(`src/etc/rc.d/x` → `/usr/local/etc/rc.d/x`).

| path | purpose |
|------|---------|
| `src/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor/Sensor.xml` | the model: capture interface, filter preset, direction, promiscuous, snaplen, **what to send** (`send_mode`), transport posture (`mode`), addresses, token, TLS trust, sensor id/location and the `authorized` assertion |
| `.../Sensor.php` | the model class; its `performValidation` is what refuses to save an enabled sensor without `authorized`, without an interface, or with a half-configured mTLS pair |
| `.../ACL/ACL.xml` | the privilege that gates the page and the API |
| `.../Menu/Menu.xml` | the **Services → SynapseIDS Sensor** entry |
| `src/opnsense/mvc/app/controllers/OPNsense/SynapseIDSSensor/SettingsController.php` | the page controller |
| `.../Api/SettingsController.php` | `GET`/`POST /api/synapseidssensor/settings/*` — read and save the model, then reconfigure |
| `.../Api/ServiceController.php` | `/api/synapseidssensor/service/*` — start, stop, restart, status |
| `.../forms/dialogSensor.xml` | the form definition the Volt page renders |
| `src/opnsense/mvc/app/views/OPNsense/SynapseIDSSensor/index.volt` | the settings page, including the authorisation warning |
| `src/opnsense/service/conf/actions.d/actions_synapseidssensor.conf` | the configd actions the API calls |
| `src/opnsense/service/templates/OPNsense/SynapseIDSSensor/+TARGETS` | maps the two templates to their destinations |
| `.../sensor.conf` | renders the command-line flags — **no secrets** |
| `.../sensor.token` | renders the bearer token, and nothing else |
| `src/etc/rc.d/synapseids_sensor` | the FreeBSD service script: fixes ownership, checks BPF access, and runs the sensor as `_synapseids` under `daemon(8)` |

Plus `/usr/local/bin/synapse-sensor`, the cross-compiled static binary.

## Secrets

All paths are under `/usr/local/etc/synapseids/` (itself `0750
root:_synapseids`).

| file | mode / owner | contents |
|------|--------------|----------|
| `sensor.conf` | `0640 root:wheel` | the command-line flags. **No secrets.** |
| `sensor.token` | `0400 _synapseids:_synapseids` | **the bearer token, and nothing else** |
| `peer-ca.pem` | `0444 root:wheel` | peer CA bundle (optional) |
| `sensor-cert.pem` | `0444 root:wheel` | this sensor's certificate (optional mTLS) |
| `sensor-key.pem` | `0400 _synapseids:_synapseids` | this sensor's private key (optional mTLS) |

The token reaches the sensor through `--token-file`, never `--token`, so it is
absent from `ps(1)`, from the rendered flag string, from shell history and from
every log line (PROJECT.md §23). It is also held in the OPNsense configuration
store, which is what the UI reads and writes. The `fixperms` configd action
clamps these modes immediately after every `template reload` — closing the
window in which configd's default umask would leave a freshly rendered token
readable — and the `rc.d` script re-checks before every start.

**Known gap:** the model stores the TLS PEM material, but `sensor.conf` only
*names* the three paths; rendering the text itself needs three more configd
template targets that this package does not yet install, so for now an operator
places those files by hand. It fails safe — `rc.d` refuses to start, naming the
missing file, whenever a flag references a PEM that is not on disk.

## Least privilege

The package's `post-install` creates a dedicated unprivileged `_synapseids`
account in group `net`, and the service runs as that user under `daemon(8)` —
**never root** (PROJECT.md §21). The BPF device is opened `O_RDONLY`.

Reading `/dev/bpf*` needs a devfs rule. Changing device permissions on
someone's firewall is not a package's business, so `pkg add` does not do it:
either run the installer with `--grant-bpf`, or

```sh
printf "[synapseids_bpf=10]\nadd path 'bpf*' mode 0640 group net\n" >> /etc/devfs.rules
sysrc devfs_system_ruleset=synapseids_bpf
service devfs restart
```

Without it the sensor refuses to start and prints exactly those commands.

## `listen` vs `connect`

**Both modes work.** `listen` is still the plugin's shipped default — the daemon
dials the firewall, as
[ADR 0012](../../docs/adr/0012-pcap-over-ip-transport.md) describes.

**`connect` is now the better choice for a firewall.** It makes the box dial out,
which is what you want behind NAT, and the daemon side finally exists: enable a
`capture.collector` block on `synapsed` and it will accept the connection,
register the firewall as its own capture source and list it on
`GET /api/v1/sensors`
([ADR 0018](../../docs/adr/0018-daemon-side-synpoip-collector-and-sensor-identity.md),
[docs/opnsense-sensor.md](../../docs/opnsense-sensor.md)). The SYNPOIP roles and
wire format are entirely unchanged
([PROTOCOL.md §6](../../internal/capture/pcapoverip/PROTOCOL.md)) — the accepting
daemon still sends the ClientHello. Point **Verify peer / CA** at the daemon's
collector certificate; `synapse-sensor gen-cert` produces one that doubles as its
own CA for testing.

The plugin's *default* mode is deliberately left at `listen` in this change:
flipping a shipped default is a plugin-side release decision, and neither mode has
been exercised on real hardware yet (see below).

## What a maintainer must validate on real hardware

Nothing below has been done. In order:

```sh
# 1. Does pkg(8) accept the package at all?
pkg info -F dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
pkg add     dist/os-synapseids-sensor-<ver>-freebsd14-amd64.pkg
pkg check -s os-synapseids-sensor

# 2. Did post-install do its job?
pw usershow _synapseids
ls -ld /var/log/synapseids /usr/local/etc/synapseids

# 3. Do the UI pages load?  Services > SynapseIDS Sensor
#    Does the form refuse to save without the "authorised" checkbox?
#    Does the ACL show up under System > Access > Groups?

# 4. Do the configd templates render, with the right modes?
configctl template reload OPNsense/SynapseIDSSensor
ls -l /usr/local/etc/synapseids/          # sensor.conf 0640 root:wheel, sensor.token 0400 _synapseids
grep -c . /usr/local/etc/synapseids/sensor.conf   # and confirm the token is NOT in it

# 5. Does the BPF capture actually work? (the biggest unknown)
/usr/local/bin/synapse-sensor pcap-over-ip \
    --listen 127.0.0.1:4789 --iface em0 --authorized --direction in --filter ip-any

# 6. Does the service run as the unprivileged user?
service synapseids_sensor start
ps -o user,command -p "$(cat /var/run/synapseids_sensor.pid)"

# 7. Does a daemon see packets?
curl -s http://<synapsed>:8080/api/v1/captures | jq
```

### Known soft spots

Two that are not OPNsense-API questions at all, and matter most:

- **The BPF read path.** The chunk splitter and the ioctl numbers are unit-tested
  and compile-asserted, but no packet has ever been through `BIOCGDLT` →
  `read(2)` → `parseBPFChunk` on a real kernel. Check that packet counts and
  timestamps look sane and that `drops` behaves under load.
- **`pkg add` script execution.** Confirm `post-install` really ran — it creates
  the `_synapseids` account — and that the Services page appears without a
  manual `service configd restart`.

Then the places where an OPNsense API name could not be confirmed from here.
Each is marked in the source with a `TODO(verify):` comment explaining the
alternative, so `grep -rn 'TODO(verify)' src/` is the checklist:

| file | what to confirm |
|------|-----------------|
| `templates/…/sensor.conf` | **the most likely thing to be wrong.** Does the configd Jinja context expose a top-level `interfaces` node whose child key is `if`, so `interfaces.wan.if` renders `em0`? Some templates use a helper such as `helpers.physical_interface()` instead. The lookup falls back to emitting the bare identifier, which makes `synapse-sensor` fail loudly at device open rather than capture the wrong interface. |
| `models/…/Sensor.xml` | an empty `OptionValues` key cannot be written in XML, so the "All traffic" (empty `--filter`) choice relies on `Required=N` + `<BlankDesc>`. If the dropdown widget does not offer a blank entry, an explicit sentinel value is needed. |
| `models/…/Sensor.php` | `\Phalcon\Messages\Message` (Phalcon 4/5, OPNsense 21.1+) vs `\Phalcon\Validation\Message` (Phalcon 3). |
| `controllers/…/Api/SettingsController.php` | that `getModelNodes()` / `setModelNodes()` exist on this core's `ApiMutableModelControllerBase`. |
| `controllers/…/Api/ServiceController.php` | that `ApiMutableServiceControllerBase` exposes a protected `getModel()` — used only for redacting the token out of the log response. |
| `actions.d/actions_synapseidssensor.conf` | whether configd's `script_output` returns stdout on a non-zero exit. `onestatus` exits 1 when stopped, so `; exit 0` is appended; drop it if unnecessary. |
| `etc/rc.d/synapseids_sensor` | whether `daemon -f` (redirect to `/dev/null`) defeats `-S -T` (syslog capture) on FreeBSD 14. If syslog stays empty, drop `-f` or add `-o /var/log/synapseids/sensor.log`. The UI log viewer reads that path, so syslogd must be pointed at it. |
| `views/…/index.volt` | the `saveFormToEndpoint()` argument order on this core, and whether the base layout already provides `#service_status_container`. |
