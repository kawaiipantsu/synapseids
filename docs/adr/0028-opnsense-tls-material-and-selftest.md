# 0028 — OPNsense TLS material, interface resolution, and an on-box selftest

**Status:** Accepted, 2026-08-31

## Context

[ADR 0014](0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md) shipped
the OPNsense sensor plugin with two acknowledged holes, tracked as GitHub issues
#104 and #102:

1. **TLS PEM material was never rendered.** `sensor.conf` *named*
   `peer-ca.pem` / `sensor-cert.pem` / `sensor-key.pem`, and the model collected
   the PEM text, but nothing wrote the files — an operator placed them by hand.
2. **Eleven `TODO(verify):` markers** recorded assumptions about the OPNsense
   MVC, Phalcon, configd and FreeBSD APIs that could not be confirmed from a
   Linux build host. Nine were in `contrib/opnsense/src/`; two more were
   references in `docs/`.

The posture in 0014 — "untested, flagged in the ADR" — was acceptable while
nobody had a firewall in front of them. It is not acceptable the day the plugin
goes onto live hardware. Anything that can be made correct from what is readable
here should be; anything that genuinely cannot must **fail loudly and legibly on
the box** rather than half-work.

One of those eleven mattered far more than the rest. The model stores an OPNsense
interface *identifier* (`wan`), and `synapse-sensor` needs a kernel device name
(`em0`). The original template resolved that via `interfaces[<id>]['if']` and,
when that failed, **fell back to emitting the bare identifier**. A sensor started
with `--iface wan` on a box with no `wan` device would report *running* while
capturing zero packets. That is the worst failure mode this plugin has: strictly
worse than refusing to start, because nothing tells anybody.

## Decision

### 1. Three configd template targets, and the key clamped like the token

`+TARGETS` gains three entries, and `pkg-plist` the three template files:

| destination | mode / owner | flag |
|---|---|---|
| `/usr/local/etc/synapseids/sensor-ca.pem` | `0444 root:wheel` | `--ca` (connect) / `--client-ca` (listen) |
| `/usr/local/etc/synapseids/sensor-cert.pem` | `0444 root:wheel` | `--cert` |
| `/usr/local/etc/synapseids/sensor-key.pem` | **`0400 _synapseids:_synapseids`** | `--key` |

The CA file is **renamed** from `peer-ca.pem` to `sensor-ca.pem` so all five
rendered files share one prefix. Nothing had ever installed the old name (the
package has never been through `pkg add`), so there is no migration to do; a test
asserts the old name is gone from the `rc.d` script, because a stale path there
would mean clamping and checking a file configd never writes.

**The private key is clamped exactly the way the bearer token is**, and that
mirroring is the whole point — configd renders templates as root under its own
umask, so a freshly written key is `0644 root:wheel` until something fixes it:

- the `fixperms` configd action now clamps all five rendered files, and is
  invoked **immediately after** every `template reload`;
- both callers of `template reload` run it:
  `Api\SettingsController::applyConfiguration` already did, and
  `Api\ServiceController::reconfigureAction` is now overridden to do so as well.
  That second one closed a real hole: the base class's `reconfigure` re-renders
  the templates itself, so before this change a reconfigure that left the service
  stopped would leave a private key mode `0644` indefinitely;
- the `rc.d` `start_precmd` re-chowns and re-chmods before every start.

`fixperms` is written as one line with an inline `fp()` helper and **no `%`
character**, because configd applies parameter substitution to `command:` values.
A check asserts no `command:` line contains a `%`.

### 2. The fail-safe property is preserved and strengthened

ADR 0014's guarantee was that `rc.d` refuses to start and *names the missing
file* rather than downgrading to an unverified connection. That is kept, and
extended: `synapseids_sensor_check_pem` now refuses when a referenced PEM is
missing, **empty**, or contains **no `-----BEGIN` line**. The empty case is new
and matters, because a template renders an empty file rather than no file when
its model field is blank. There is still no code path anywhere that turns a
missing certificate into `--insecure-tls`.

### 3. PEM validation at save time, not at start time

A blob that is not really PEM used to become a start-time surprise on a firewall
nobody logs into. `Sensor::performValidation` now rejects, in the web UI, with a
human present:

- incomplete or truncated blocks, mismatched `BEGIN`/`END` labels, and a base64
  body that does not decode;
- a private key pasted into the certificate or CA field, and vice versa — the
  mistake two adjacent textareas invite, and a private key in the CA field would
  be rendered `0444`;
- a certificate chain in the single-certificate field;
- **a passphrase-protected key**, checked on the raw text before the base64 check
  so a legacy `Proc-Type: 4,ENCRYPTED` key gets the right message. Go's
  `crypto/tls` cannot use one and an unattended firewall has nowhere to type it;
- a certificate or key that OpenSSL cannot parse;
- **a key that does not match its certificate**, via
  `openssl_x509_check_private_key`. This is the one that otherwise shows up only
  as a TLS handshake failure on a remote box.

Every `openssl_*` call is guarded by `function_exists` so the model degrades to
the shape checks rather than fataling if the extension were absent.

### 4. Interface resolution: two lookups, and a refusal instead of a guess

The template now resolves the device name two ways and, critically, **never
falls back to the bare identifier**:

1. `interfaces[<id>]['if']` — the primary path. `config.xml` holds
   `<interfaces><wan><if>em0</if></wan>`, and the template already depends on
   `OPNsense.SynapseIDSSensor.general` resolving, which means configd renders
   against the whole configuration tree — `interfaces` and `OPNsense` are sibling
   keys of that one dict. A plain subscript also cannot raise, so it goes first.
2. `helpers.physical_interface(<id>)` — the fallback, guarded by `is defined` so
   a core without that helper skips it. Second because calling a helper with an
   identifier the core does not know could raise and abort the whole render.
3. Neither worked → `synapseids_sensor_iface` is left **empty**,
   `synapseids_sensor_iface_error` records the identifier and both attempts, and
   `--iface` is omitted entirely.

`sensor.conf` now also renders `synapseids_sensor_iface_id` and
`synapseids_sensor_iface_src`, so the resolution is visible rather than inferred.

Three layers then act on that:

- **`rc.d`** refuses to start if `iface_error` is set; refuses if no device
  resolved; and — the important one — runs `ifconfig <dev>` and refuses if the
  resolved device **does not exist**, printing the identifier, the device, the
  lookup used, and `ifconfig -l`.
- **`synapse-sensor doctor`** reports the same as a `[FAIL]` line and lists the
  devices that *do* exist.
- A sensor that would capture nothing therefore never reaches "running".

### 5. `synapse-sensor doctor`, reachable three ways

The checks live in Go — they are unit-testable there, and parsing PEM, proving a
key pair matches and opening a TCP connection are not things to write in `sh`.
Three thin layers expose it:

- `synapse-sensor doctor` (also `selftest`) — the subcommand;
- `service synapseids_sensor selftest` — an `rc.d` `extra_commands` verb that
  passes the box's real paths;
- `configctl synapseidssensor selftest` — a `script_output` action, which is what
  makes the **Run selftest** button on the settings page work.

Nine checks, one line each, `[ OK ]` / `[WARN]` / `[FAIL]` / `[SKIP]`, with the
remedy indented underneath a failure. Exit status 1 if anything failed; a `WARN`
never fails the run. It is strictly read-only and prints no secrets — only paths,
modes and certificate subjects — and the API redacts the configured token from
the response anyway.

`config` runs second rather than in the order issue #102 lists, because every
later check reads its subject out of the rendered configuration.

### 6. Verifying the unverifiable-looking parts anyway

Three harnesses were added under `contrib/opnsense/tools/`, none of them shipped
in the package. They are the reason this change is not another "compile-verified
only" claim:

- **`render-templates.py`** renders every configd template with Jinja2 against a
  mock OPNsense context — 17 scenarios, including the interface lookup in all
  four of its states, a VLAN device name, both transport modes, and a hostile
  config value. It found a real bug: the template's `sh()` escaping macro
  stripped `'`, `"`, `` ` `` and `$` but **not** `;` `|` `&` `<` `>` `\`, so a
  value with a semicolon survived into the file that `rc.d` sources as root. It
  was not exploitable — the same macro removes the quotes needed to escape the
  shell word, and each field's `Mask` already excludes those characters — but it
  was one barrier short of the two the header claims. The macro now strips all of
  them, and `doctor` refuses to parse a `sensor.conf` containing any.
- **`test-sensor-model.php`** exercises `Sensor::performValidation` against real
  generated key material — 25 cases. It found the misleading message on legacy
  encrypted keys described above.
- **`check-plugin.sh`** runs `php -l`, an XML parse, `sh -n`, both harnesses, and
  `+TARGETS` / `pkg-plist` / directory agreement. It caught a `--` inside an XML
  comment that this change introduced into `Sensor.xml`.

On the packaging side, `cmd/synapse-sensor/opnsensepkg_test.go` lifts the naming
and ABI-mapping logic out of **both** `install.sh` and
`scripts/package-opnsense.sh`, runs each under `/bin/sh`, and asserts they agree
for `FreeBSD:{13,14,15}:{amd64,aarch64,arm64}` — because a mismatch there is a
404 that reads like a missing release. `check-install-derivation.sh` does the
same against the real artefacts in `dist/`.

That work found a second real bug, this time in `install.sh`'s SHA256SUMS parser:
`\./\{0,1\}` requires a literal dot and only makes the *slash* optional, so a
`<hash>  <name>` line — the form a hand-rolled LAN mirror produces — matched
nothing and the installer aborted with "no entry in SHA256SUMS". It is now three
plain `-e` expressions instead of one clever pattern, since **every BRE interval
(`\{0,1\}`, `\{1,\}`) contains a comma and comma was the `s,,,` delimiter** — the
combined pattern silently truncated. The package name is also escaped now, so the
dots in a version cannot act as wildcards, and the digest is length-checked.

### 7. `--url` no longer needs the internet

`--url` always overrode the download base, but with no `--version` the installer
still called `api.github.com` to resolve "latest" — which fails on a firewall
being served from a LAN host. It now discovers the version from the mirror's own
`SHA256SUMS`, and says which `--version` to pass if it cannot.

## Consequences

- Nine `TODO(verify)` markers in `contrib/opnsense/src/` are now **one**. Eight
  were resolved; four of those by *removing the dependency* rather than
  confirming it, which is strictly better: `Api\ServiceController` instantiates
  the model directly instead of relying on a base-class `getModel()`; the
  `; exit 0` on `script_output` actions makes configd's non-zero behaviour
  irrelevant; and the interface lookup tries both candidate APIs.
- `make test` now covers the OPNsense packaging contract, which was previously
  only checked by `make opnsense-pkg`.
- The package grew from 15 to 18 payload files. `package-opnsense.sh` fails the
  build if the staged tree and `pkg-plist` disagree, so this is enforced.
- Operators no longer copy PEM files to the firewall by hand, and the private key
  never exists on disk in a world-readable state for longer than it takes
  `fixperms` to run in the same request.

### What remains unverifiable without hardware

This is still a Linux-built, Linux-tested change. No OPNsense MVC runtime has
loaded the PHP, no configd has rendered the templates, and `pkg add` has never
run. Specifically:

1. **`daemon(8)`'s `-f` versus `-S -T`** — the one `TODO(verify)` deliberately
   kept. `-f` sends the *supervisor's* std fds to `/dev/null`; whether it also
   suppresses capture of the *child's* output could not be settled from here, and
   the FreeBSD source is not readable in this environment. `-f` is kept because
   configd reads this script's output to EOF and a supervisor holding that pipe
   open would hang the GUI's Start button. Mitigation: `-o <logdir>/sensor.log`
   was added as a second, independent sink, and `doctor`'s `log-sink` line reports
   whether the file is being written, with the remedy (drop `-f`) inline.
   **Failure mode if wrong: the sensor still captures and still streams; only its
   log is empty.** A diagnosability bug, not a capture bug.
2. **The BPF read path** — unchanged by this ADR and still the biggest unknown.
   No packet has been through `BIOCGDLT` → `read(2)` → `parseBPFChunk` on a real
   kernel. Throughput, drop accounting and timestamp accuracy are unmeasured.
3. **`pkg add` and its `post-install`** — the package is structurally verified
   (member order, per-file sha256 re-extracted, modes, ownership) but `pkg(8)`
   has never parsed it, and nothing has confirmed the `_synapseids` account is
   really created.
4. **That configd exposes `interfaces` at the top level, and that its child key
   is `if`.** The reasoning in §4 is strong — it is the same dict the template
   already reads `OPNsense` out of — but it is reasoning, not observation. If it
   is wrong, path 2 or a hard refusal catches it; the sensor cannot bind to the
   wrong device or to nothing.
5. **`BlankDesc` rendering a blank dropdown entry.** Worst case: "All traffic" is
   not offered and an operator is limited to the four presets. Cosmetic,
   immediately visible, cannot produce a dead sensor.
6. **`saveFormToEndpoint`'s argument order** and the Phalcon `Message` class
   path. Both are current-core conventions; if either is wrong the page fails
   loudly on first use — a dead Save button, or a class-not-found on save — not
   silently.
7. **Whether the GUI surfaces the new Selftest button and the `selftest` configd
   action** without a manual `service configd restart`.

`contrib/opnsense/README.md` lists the commands to close each of these, keyed to
the selftest's output lines.

**Follow-ups:** run the selftest on real hardware and fold the results back into
this ADR; measure the BPF path under WAN load; `GOOS=freebsd` in CI once a runner
exists; consider promoting `check-plugin.sh` into `make lint` once a CI image has
`php` and `jinja2`.
