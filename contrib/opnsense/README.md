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
> plugin — was written and tested on **Linux**. Cross-builds, unit tests,
> compile-time ABI assertions, a Jinja2 render of every configd template and a
> stubbed run of the model's validation all pass. Nobody has run it on FreeBSD or
> OPNsense. See [What a maintainer must
> validate](#what-a-maintainer-must-validate-on-real-hardware).
>
> **The first thing to run on the box is the selftest** — see
> [Selftest](#selftest). It is designed so one command replaces a remote
> debugging session.

## Selftest

```sh
service synapseids_sensor selftest     # on the console
configctl synapseidssensor selftest    # the same, through configd
synapse-sensor doctor --help           # the underlying subcommand
```

or press **Run selftest** on **Services → SynapseIDS Sensor**.

Nine checks, one line each, in this order. Exit status is 1 if any `[FAIL]`
appeared; a `[WARN]` never fails the run. It is read-only — it never writes,
chowns or chmods anything — and it prints no secrets, only paths, modes and
certificate subjects.

```
[ OK ] binary        synapse-sensor 0.1.0 (abc1234, 2026-08-31) go1.27 freebsd/amd64
[ OK ] config        /usr/local/etc/synapseids/sensor.conf: enable=YES, 17 flags, transport=connect
[ OK ] service-user  _synapseids uid=1001 gid=1001 groups=_synapseids,net
[ OK ] bpf-access    /dev/bpf mode 0640 root:net — readable by group net, which _synapseids is in
[ OK ] interface     wan -> em0 (via interfaces.wan.if) — exists, flags up|broadcast|running
[ OK ] token-file    /usr/local/etc/synapseids/sensor.token mode 0400 _synapseids:_synapseids, 44 bytes
[ OK ] tls-identity  sensor-cert.pem + sensor-key.pem: pair matches, subject "CN=fw1.example", expires 2027-08-31T00:00:00Z
[ OK ] tls-trust     sensor-ca.pem: 1 certificate(s), subject SynapseIDS Collector CA
[ OK ] log-sink      /var/log/synapseids mode 0750 _synapseids:wheel; sensor.log 4096 bytes, modified 2026-08-31T12:00:03Z
[ OK ] collector     ids.example.net:4789: TCP connect succeeded in 3ms (no TLS handshake attempted)

summary: 10 checks, 10 passed, 0 warned, 0 failed, 0 skipped
selftest: PASSED
```

(`tls-identity` and `tls-trust` are two lines from one check, so a full run
prints ten.)

### Troubleshooting, by output line

| line | what it means | what to do |
|---|---|---|
| `[FAIL] config` — *no such file* | the configd template has never rendered | press Save on the settings page, or `configctl template reload OPNsense/SynapseIDSSensor && configctl synapseidssensor fixperms` |
| `[FAIL] config` — *shell metacharacter* / *not name=value* | `sensor.conf` was hand-edited, or a template escaping bug | never edit it; re-render. This file is sourced by `rc.d` as **root** |
| `[FAIL] config` — *`--authorized` is absent* | the authorisation checkbox is not ticked | tick it. `synapse-sensor` refuses live capture without it (PROJECT.md §28.18) |
| `[WARN] config` — *not enabled* | saved but disabled | tick **Enable** |
| `[FAIL] service-user` | `pkg add`'s `post-install` did not run | `pkg install -f os-synapseids-sensor`, or `pw useradd _synapseids -d /nonexistent -s /usr/sbin/nologin -G net` |
| `[WARN] service-user` — *not in group net* | the devfs rule grants `bpf*` to group `net` | `pw groupmod net -m _synapseids` |
| `[FAIL] bpf-access` | **the sensor would capture nothing** | run the installer with `--grant-bpf`, or the two `devfs.rules` commands the line prints |
| `[FAIL] interface` — *does not exist* | **the worst case: bound to nothing** | the line lists the devices that *do* exist. Check **Interfaces → Assignments** and `ifconfig -l`, then re-save |
| `[FAIL] interface` — *could not be resolved* | the configd template could not turn the identifier into a device name | re-select the interface and save. The message names both lookups it tried; please report it — this is the assumption most likely to be wrong |
| `[WARN] interface` — *device is down* | BPF attaches but sees no traffic | bring the interface up |
| `[FAIL] token-file` — *readable by more than the owner* | configd's umask window was not closed | `configctl synapseidssensor fixperms` |
| `[FAIL] token-file` — *empty* | no bearer token: any peer completing the handshake would be accepted | enter one on the settings page |
| `[FAIL] tls-identity` — *no such file* | a flag names a PEM that is not on disk | `configctl template reload OPNsense/SynapseIDSSensor`. **The service refuses to start in this state by design** — it never downgrades to an unverified transport |
| `[FAIL] tls-identity` — *readable by more than its owner* | the private key is not `0400` | `configctl synapseidssensor fixperms` |
| `[FAIL] tls-identity` — *do not match each other* | certificate and key are from different pairs | re-paste both; the model normally catches this at save time |
| `[FAIL] tls-identity` — *EXPIRED* / *not valid until* | certificate dates | reissue, or check the clock: `date; service ntpd status` |
| `[FAIL] tls-trust` — *not a certificate* | a private key was pasted into the CA field | clear it and paste the CA bundle |
| `[WARN] tls-trust` — *`--insecure-tls`* | the collector is **not** verified | paste the collector CA and untick "do not verify" |
| `[WARN] log-sink` — *does not exist* / *empty* while the service runs | `daemon(8)`'s `-f` is suppressing output — the one assumption still unverified | drop `-f` from `command_args` in `/usr/local/etc/rc.d/synapseids_sensor`. **Capture is unaffected; only the log is** |
| `[FAIL] collector` | no TCP path to the daemon | check `synapsed` has a `capture.collector` block listening, and the outbound rule |
| `[WARN] collector` — *bindable but nothing is listening* | listen mode, sensor not running | `service synapseids_sensor start` |
| `[FAIL] collector` — *cannot bind* | the listen address is wrong for this host | fix it, or switch to **connect** mode (better behind NAT) |

If the selftest passes and the daemon still sees nothing, the remaining suspect is
the BPF read path itself — see [Known soft spots](#known-soft-spots).

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

Serving it from a LAN host instead of GitHub:

```sh
sh install.sh --url http://10.0.0.10/synapseids            # version read from the mirror's SHA256SUMS
sh install.sh --url http://10.0.0.10/synapseids --version v0.2.0
sh install.sh --url http://10.0.0.10/synapseids --dry-run  # print every step, change nothing
```

With `--url` the installer never contacts `api.github.com` — it discovers the
version from the mirror's own `SHA256SUMS` — so an air-gapped install works. The
mirror must serve the `.pkg` and a `SHA256SUMS` listing it; both
`<hash>␣␣<name>` and `<hash>␣␣./<name>` lines are accepted. `--dry-run` routes
every mutating command through a printer, so it touches nothing.

The file name is reconstructed from the firewall's own `pkg config abi`
(`FreeBSD:14:amd64` → `…-freebsd14-amd64.pkg`, `FreeBSD:14:aarch64` →
`…-freebsd14-arm64.pkg`). That derivation and the one in
`scripts/package-opnsense.sh` are pinned against each other by
`TestOPNsensePackageABIDerivation` in `make test`, and against the real artefacts
by `tools/check-install-derivation.sh` — a mismatch there is a 404 that reads
like a missing release.

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
| `src/opnsense/service/templates/OPNsense/SynapseIDSSensor/+TARGETS` | maps the five templates to their destinations |
| `.../sensor.conf` | renders the command-line flags plus the resolved capture device and how it was resolved — **no secrets** |
| `.../sensor.token` | renders the bearer token, and nothing else |
| `.../sensor-ca.pem` | renders the peer CA bundle (`0444`) |
| `.../sensor-cert.pem` | renders this sensor's certificate (`0444`) |
| `.../sensor-key.pem` | renders this sensor's **private key** (`0400 _synapseids`) |
| `src/etc/rc.d/synapseids_sensor` | the FreeBSD service script: fixes ownership, checks BPF access, **refuses to start unless the resolved capture device exists**, and runs the sensor as `_synapseids` under `daemon(8)`. Also provides the `selftest` verb |

Plus `/usr/local/bin/synapse-sensor`, the cross-compiled static binary.

### Development harnesses (not packaged)

`contrib/opnsense/tools/` holds what makes this more than a `php -l` claim. None
of it is in `pkg-plist`:

```sh
sh   contrib/opnsense/tools/check-plugin.sh             # everything below, plus php -l / XML / sh -n
python3 contrib/opnsense/tools/render-templates.py      # render every configd template (Jinja2, mock context)
php  contrib/opnsense/tools/test-sensor-model.php       # Sensor::performValidation against real key material
sh   contrib/opnsense/tools/check-install-derivation.sh # install.sh vs. the real dist/*.pkg
```

`render-templates.py` covers the interface-identifier lookup in all four of its
states, which is the assumption most likely to be wrong on real hardware.
`shellcheck` is **not** run — it is not installed in the environment this was
developed in, so no claim is made about it. `sh -n` is what runs.

## Secrets

All paths are under `/usr/local/etc/synapseids/` (itself `0750
root:_synapseids`).

All five files are **rendered by configd** from the OPNsense configuration
store; nothing is copied to the firewall by hand.

| file | mode / owner | contents |
|------|--------------|----------|
| `sensor.conf` | `0640 root:wheel` | the command-line flags. **No secrets.** |
| `sensor.token` | `0400 _synapseids:_synapseids` | **the bearer token, and nothing else** |
| `sensor-ca.pem` | `0444 root:wheel` | peer CA bundle (optional) |
| `sensor-cert.pem` | `0444 root:wheel` | this sensor's certificate (optional mTLS) |
| `sensor-key.pem` | **`0400 _synapseids:_synapseids`** | **this sensor's TLS private key** |

The token reaches the sensor through `--token-file`, never `--token`, so it is
absent from `ps(1)`, from the rendered flag string, from shell history and from
every log line (PROJECT.md §23). Only the *paths* of the PEM files reach `argv`.

**The two secrets — the token and the private key — are clamped identically.**
configd renders templates as root under its own umask, so the `fixperms` configd
action runs **immediately after** every `template reload` (from both
`Api\SettingsController::applyConfiguration` and
`Api\ServiceController::reconfigureAction`), and the `rc.d` `start_precmd`
re-checks before every start. `synapse-sensor doctor` reports the modes it finds,
so the property is checkable on the box rather than assumed.

**It fails safe.** `rc.d` refuses to start — naming the path — whenever a flag
references a PEM that is missing, empty or has no `-----BEGIN` line. There is no
code path that turns absent TLS material into `--insecure-tls`. Additionally the
model refuses at *save* time to store a blob that is not PEM, a private key
pasted into a certificate field, an encrypted key (Go's `crypto/tls` cannot use
one and an unattended firewall has nowhere to type a passphrase), or a key that
does not match its certificate.

> The CA file was called `peer-ca.pem` in the first cut of this plugin
> ([ADR 0014](../../docs/adr/0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md));
> it is `sensor-ca.pem` now that all five rendered files share one prefix
> ([ADR 0028](../../docs/adr/0028-opnsense-tls-material-and-selftest.md)). No
> released package ever installed the old name.

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
#    Does it refuse a mismatched certificate/key pair, and an encrypted key?
#    Does the ACL show up under System > Access > Groups?
#    Does the "Run selftest" button return output?

# 4. Do all FIVE configd templates render, with the right modes?
configctl template reload OPNsense/SynapseIDSSensor
configctl synapseidssensor fixperms
ls -l /usr/local/etc/synapseids/
#   sensor.conf      0640 root:wheel
#   sensor.token     0400 _synapseids:_synapseids
#   sensor-ca.pem    0444 root:wheel
#   sensor-cert.pem  0444 root:wheel
#   sensor-key.pem   0400 _synapseids:_synapseids     <- the one that matters
grep -c . /usr/local/etc/synapseids/sensor.conf   # and confirm the token is NOT in it

# 4b. THE BIG ONE: did the interface identifier resolve to a real device?
grep synapseids_sensor_iface /usr/local/etc/synapseids/sensor.conf
#   synapseids_sensor_iface="em0"                     <- must be a device, not "wan"
#   synapseids_sensor_iface_src="interfaces.wan.if"   <- or helpers.physical_interface(wan)
#   synapseids_sensor_iface_error=""                  <- must be empty
# If iface_src says helpers.physical_interface(), the primary lookup failed and
# that is worth reporting upstream. If iface_error is non-empty, the service will
# refuse to start and say so, which is the intended behaviour.

# 5. Run the selftest FIRST. It covers 2, 4, 4b and 6 in one command.
service synapseids_sensor selftest

# 6. Does the service run as the unprivileged user?
service synapseids_sensor start
ps -o user,command -p "$(cat /var/run/synapseids_sensor.pid)"

# 6b. Is anything reaching the log? (the kept daemon(8) -f question)
ls -l /var/log/synapseids/sensor.log
# Empty while the service runs => drop -f from command_args in
# /usr/local/etc/rc.d/synapseids_sensor. Capture is unaffected either way.

# 7. Does the BPF capture actually work? (the biggest remaining unknown)
/usr/local/bin/synapse-sensor pcap-over-ip \
    --listen 127.0.0.1:4789 --iface em0 --authorized --direction in --filter ip-any

# 8. Does a daemon see packets?
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

Then the places where an OPNsense API name could not be confirmed from a Linux
build host. There were nine `TODO(verify):` markers in `src/`; **eight are now
resolved and one is deliberately kept**, so `grep -rn 'TODO(verify)' src/` is a
one-line checklist. Four of the eight were resolved by *removing* the dependency
rather than confirming it. Full reasoning in
[ADR 0028](../../docs/adr/0028-opnsense-tls-material-and-selftest.md).

**Still carried as a `TODO(verify)`:**

| file | what to confirm | failure mode if the assumption is wrong |
|------|-----------------|------------------------------------------|
| `etc/rc.d/synapseids_sensor` | whether `daemon(8)`'s `-f` (supervisor std fds → `/dev/null`) also defeats `-o` / `-S -T` capture of the **child's** output on FreeBSD 14. `-f` is kept because configd reads this script to EOF and a supervisor holding that pipe open would hang the GUI's Start button. | **Capture is unaffected**; only `sensor.log` stays empty. The selftest's `log-sink` line says so and prints the remedy (drop `-f`). |

**Resolved, but still worth an eye on the box** — each now fails loudly rather
than silently, so a wrong guess is visible immediately:

| file | assumption | how it fails if wrong |
|------|-----------|------------------------|
| `templates/…/sensor.conf` | that the configd Jinja context exposes a top-level `interfaces` node with an `if` child, so `interfaces.wan.if` → `em0`. Reasoned from the fact that the template already reads `OPNsense.…` out of the same dict. `helpers.physical_interface()` is tried second. | **Never binds to the wrong device and never to nothing.** Unresolvable → empty device + a recorded error → `rc.d` refuses to start; resolved-but-absent → `ifconfig` check refuses and lists the real devices. Check `synapseids_sensor_iface_src` to see which lookup won. |
| `models/…/Sensor.xml` | `Required=N` + `<BlankDesc>` renders a blank "All traffic" dropdown entry (a `BaseListField` feature). | Cosmetic: the blank entry is not offered and only the four presets are selectable. Cannot produce a dead sensor. |
| `models/…/Sensor.php` | `\Phalcon\Messages\Message` — Phalcon 4/5, i.e. OPNsense 21.1+. The package is only built for FreeBSD 14 ABIs (OPNsense 24.x/25.x), so pre-21.1 is out of scope. | Class-not-found on save: loud, immediate, first use. |
| `controllers/…/Api/SettingsController.php` | `getModelNodes()`/`setModelNodes()` on `ApiMutableModelControllerBase` (present since 19.7). | Method-not-found on load/save: loud and immediate. |
| `controllers/…/Api/ServiceController.php` | *removed* — the model is now instantiated directly instead of via a base-class `getModel()`. | n/a. |
| `actions.d/actions_synapseidssensor.conf` | *removed* — `; exit 0` makes configd's non-zero `script_output` behaviour irrelevant, deliberately, rather than depending on the answer. | n/a. |
| `views/…/index.volt` | `saveFormToEndpoint(url, formid, ok, disable_dialog, fail)` — the 20.x+ signature; and that a duplicate `#service_status_container` is harmless. | A visibly dead Save button plus a browser-console error. The status pill next to it is ours and always populates. |
