# 0030 — OPNsense: one sensor process per interface, as a repeating model item

**Status:** Accepted, 2026-08-31

## Context

An operator bringing the plugin up on a live OPNsense 25.1 gateway selected
**WAN, IoT, DMZ and MGMT** in what was then a multi-select interface field, saved,
and got a single VLAN captured. Three segments were believed monitored and were
not, and nothing on the box or in the daemon reported the difference. The model
declared `Multiple=Y` while the configd template read
`node.interface.split(',')[0]`; a control that accepts input and discards it is
worse than one that refuses it (issue #124).

PR #132 made the plugin *honest* — single select, plus a save-time refusal for a
stored multi-value — but honest and limited to one segment. This ADR is the other
half: making the plugin able to do what the operator asked for.

`synapse-sensor` captures exactly one device per process (`--iface` is singular,
and BPF is a per-descriptor attachment), so there were two ways to get four
segments monitored:

1. **One process, several BPF descriptors.** Fewer processes, one identity, one
   connection to the daemon. But two monitored segments that route to each other
   see the same packet twice, and with a single identity the daemon has nowhere
   to record *which* device observed it. The two observations would either merge
   into one flow — losing the fact that the traffic crossed a boundary, which is
   most of what an internal sensor is for — or need a per-observation device tag,
   which is a SYNPOIP protocol change and a `flow-features-v2` conversation.

2. **One process per interface, each with its own sensor identity.** The daemon
   already attributes every flow to a named sensor (ADR 0018), and
   `GET /api/v1/sensors` already lists them. A packet routed between two
   monitored segments is then legitimately reported twice, by two named sensors,
   which is the truth. No protocol change, no schema change, no daemon change.

Option 2 was chosen. The cost is N processes and N TLS connections on the
firewall; the benefit is correct attribution today rather than a protocol
revision first.

## Decision

### Model shape: `ArrayField`, the core idiom

`Sensor.xml` grows a repeating `instances/instance` node of type `ArrayField`,
rendered as a grid with an edit dialog. This is copied from **`OPNsense/Cron`**
(`src/opnsense/mvc/app/models/OPNsense/Cron/Cron.xml` declares `job` exactly this
way, and `System > Settings > Cron` is the resulting page); the API side is the
stock `searchBase` / `getBase` / `addBase` / `setBase` / `delBase` / `toggleBase`
wrappers on `ApiMutableModelControllerBase`. Nothing about the repeating item is
invented here, which is the point: the dialog, the validation highlighting and the
grid all come from the same machinery as the rest of the GUI, so none of it is
ours to get wrong.

The split is **shared transport, per-instance capture**:

| `general` | `instances/instance` |
|---|---|
| `enabled` (master switch), `mode` (listen/connect), `address`, `token`, `verify_peer`, `ca`, `client_cert`, `client_key` | `enabled`, `name`, `interface`, `listen_address`, `filter`, `direction`, `promiscuous`, `snaplen`, `send_mode`, `sensor_id`, `location`, `authorized`, `description` |

There is one collector and one firewall, so one bearer token and one TLS identity;
duplicating them per instance would multiply the secrets on the box for nothing.
The one transport setting that **cannot** be shared is `listen_address`: four
processes cannot bind one port, so in listen mode each instance needs its own and
`performValidation` refuses duplicates. The capture knobs are per instance because
they describe *this* capture — a WAN uplink and an internal SPAN port rarely want
the same direction, the same promiscuity or the same `send_mode`, and putting
`send_mode` on the instance is what lets a sensitive segment be feature-only while
the WAN stays raw.

`name` is restricted to `[a-zA-Z0-9_]{1,32}` because it is not decoration: it is
the rc.d profile name, the rendered file name, the pidfile stem, the log directory
and the column the selftest prints.

### One rendered configuration per instance, from one template

`+TARGETS` gains a destination with a bracketed tag:

```
sensor-instance.conf:/usr/local/etc/synapseids/instances/[OPNsense.SynapseIDSSensor.instances.instance.%.name].conf:/usr/local/etc/synapseids/instances/*.conf
```

That is configd's own repeating-target syntax (`Template.__find_string_tags` /
`__find_filters` in `service/modules/template.py`): the `%` enumerates the
repeating nodes, the trailing `.name` supplies the value that goes into the file
name, and each render receives `TARGET_FILTERS` telling it which instance it is.
The third field is the cleanup glob, because the literal target contains
unresolved brackets and would otherwise match nothing.

**Each instance's file carries exactly the variable names a 1.0.0 `sensor.conf`
carried.** That is deliberate and load-bearing: it means
`synapse-sensor doctor --config /usr/local/etc/synapseids/instances/wan.conf`
needs no change in the Go binary to check one sensor, which is what makes the
per-instance selftest possible without touching the data plane at all.

`sensor.conf` itself becomes the **index**: `synapseids_sensor_profiles` and
`synapseids_sensor_instdir`. It still renders the 1.0.0 variable names, all empty,
with `synapseids_sensor_enable="NO"` — so an old rc.d script left behind by a
partial upgrade declines to start (the safe direction), and a bare
`synapse-sensor doctor` reports a disabled sensor with no interface (a WARN and a
SKIP) rather than a `[FAIL]` about a missing authorisation flag belonging to no
sensor at all.

Two smaller decisions inside the template:

- The `sh()` quoting macro is **duplicated** in both templates rather than
  imported. `{% import %}` would add a cross-template loader dependency to the one
  file whose failure mode is a shell fragment sourced by root; a harness scenario
  asserts the two copies are byte-identical instead.
- Config values are read with **subscripts** (`item['name']`), not dotted access.
  configd hands templates plain dicts and Jinja resolves `a.b` with `getattr`
  first, so a field named `items`, `keys`, `values`, `get`, `copy` or `pop` would
  silently evaluate to a bound method.

### rc.d: the profile-list idiom

`synapseids_sensor` becomes a multi-profile service in the shape `openvpn(8)` and
`nginx` use — a profile list plus per-profile variables — rather than a service
started several times:

```sh
service synapseids_sensor start          # every instance in $synapseids_sensor_profiles
service synapseids_sensor start wan      # just that one
service synapseids_sensor selftest       # every instance, named per line
```

With no profile argument the script **re-executes itself** once per name and
aggregates the exit statuses; with one it sources that instance's rendered file
and runs the ordinary `run_rc_command` machinery. Re-executing rather than looping
in-process is what keeps rc.subr's own state — `rcvar`, `pidfile`, `start_precmd`
— scoped to a single sensor.

Each instance gets its own `pidfile` (`/var/run/synapseids/<name>.pid`, in a
directory the unprivileged user owns, because `daemon(8)` writes it *after*
dropping privileges), its own syslog tag, and its own **log directory**
`/var/log/synapseids/<name>/sensor.log`. The directory rather than a flat
`<name>.log` is not cosmetic: `doctor` looks for `sensor.log` inside whatever
`--log-dir` it is given, so this layout is what lets the unchanged binary check
each instance's log.

`${name}_*` names that rc.subr reserves stay off limits — the reason
`synapseids_sensor_runas` is not `_user` — and a test enumerates them.

The aggregate `stop`/`restart` path additionally **sweeps orphaned pidfiles**:
deleting an instance in the GUI removes it from the profile list, and without the
sweep its process would keep capturing a segment the operator believes they
stopped monitoring. `check_pidfile` confirms the pid really is a `synapse-sensor`
before anything is signalled.

### configd actions take an optional instance

Every lifecycle action gains `parameters:%s`, so
`configctl synapseidssensor restart wan` reaches one sensor and
`configctl synapseidssensor restart` reaches all of them. The `%s` lives only on
`parameters:` lines — never on `command:`, where configd's own substitution would
eat it — and configd single-quotes each parameter before substituting
(`Action._cmd_builder`), so it cannot break out of the command. Compound commands
are written as `/bin/sh -c '...' sh` so the appended parameter lands in `"$1"` in
the middle rather than at the very end.

`fixperms` moved out of a 500-character ini line into
`scripts/OPNsense/SynapseIDSSensor/fixperms.sh`, because the number of files to
clamp is no longer fixed and because a script can be `sh -n`-checked, which an ini
value never was. It also removes `instances/*.conf` files that no longer match a
configured instance.

### Authorisation is per instance and never inherited

PROJECT.md §28.18 makes capturing live traffic an explicit decision. Being
authorised to monitor the WAN uplink says nothing about being authorised to
monitor a tenant VLAN, so `authorized` lives on the instance, is required before
an instance can be enabled, is never copied when an instance is added, and is
never set by the grid's enable toggle — toggling on a row that was never
authorised fails validation and sends the operator into the dialog to make the
assertion explicitly.

### Migration

Model version `1.0.0 → 1.0.1` with `Migrations/M1_0_1.php`, run from the package's
`post-install` via `/usr/local/opnsense/mvc/script/run_migrations.php
OPNsense/SynapseIDSSensor` (`rc.configure_plugins` does **not** run migrations —
it flushes caches and restarts syslog).

- The **first** stored identifier becomes an instance carrying every 1.0.0 value
  verbatim, `enabled` and `authorized` included. A firewall capturing WAN before
  the upgrade is capturing WAN after it.
- **Further** identifiers — which only the pre-#132 multi-select could have
  stored, and which the 1.0.0 template silently discarded — also become
  instances, named and visible, but **disabled and unauthorised**. Turning them
  into running captures on the operator's behalf would be the opposite of the bug
  rather than the fix for it.
- It does nothing when the legacy interface is empty or the instance list is
  non-empty, so it is a no-op on a fresh install and idempotent on re-run.

The ten 1.0.0 leaves stay **declared** in `Sensor.xml` as deprecated
`TextField`/`Required=N` nodes, with no Mask, so that a stored `"wan,opt5,opt4"`
loads without a validation error and the migration can read it through the model.
A model migration can only read what the model declares, and reaching around the
model into `config.xml` would have been a much larger assumption than ten dead
leaves. The migration blanks them once it has copied them.

## Consequences

- Four monitored segments cost four processes, four TLS connections to the
  collector and four listen ports (in listen mode). On a busy firewall that is
  four times the `raw`-mode bandwidth of one sensor; `send_mode` being per
  instance is the lever for that.
- The daemon sees four distinct sensors. A packet routed between two monitored
  segments is reported twice, by two named sensors — correct, and visible as such
  in `GET /api/v1/sensors`, rather than two observations quietly merging.
- The core service widget reduces N processes to one word and reports "stopped"
  as soon as any instance is down. That is the conservative reading and it is
  kept, but the settings page shows a per-instance breakdown from
  `/api/synapseidssensor/service/instances`, because one word about four sensors
  is wrong more often than it is right.
- `synapse-sensor doctor`, `internal/capture/bpf`, SYNPOIP and every schema are
  **unchanged**. This ADR touches the plugin and its packaging only.

## What this found on the way

Two pre-existing bugs, both caught by making the harness match configd instead of
approximating it:

1. **`helpers.physical_interface()` returns its input when it cannot resolve it.**
   The core helper is literally `getNodeByTag('interfaces.'+name+'.if') or name`,
   so an unknown identifier comes back unchanged — and the 1.0.0 template took
   that at face value, which would have put `--iface wan` on the command line: a
   plausible-looking device name that binds to nothing, or to the wrong thing if a
   device of that name ever existed. The template now treats a result equal to the
   identifier as "not found". (The `rc.d` `ifconfig` check would have refused the
   start, so this was a diagnosability bug rather than a silent mis-capture — but
   the message would have been wrong.)
2. **The development harness was rendering with an environment configd does not
   use** — `lstrip_blocks`, `keep_trailing_newline` and `StrictUndefined` on,
   the `do`/`loopcontrols` extensions and configd's own filters absent, and no
   `+TARGETS` expansion at all. It now uses configd's `Environment` verbatim,
   registers the same filters and tests, reproduces the trailing-newline fixup,
   and renders through a reimplementation of `__find_filters` so the
   one-file-per-instance expansion is tested for 0, 1 and 4 instances rather than
   assumed.

And one bug introduced and caught within the hour: a Jinja comment ends at the
first `#}` it contains, so writing that sequence inside the explanatory header
truncated the comment and dumped the remaining prose into the rendered file. The
`/bin/sh` sourcing scenario let it through; the strict `name=value` parser did
not. Both checks earn their place.

## References

- Issue #124 — the multi-select that monitored one interface
- PR #132 — the honest single-select this builds on
- [ADR 0014](0014-freebsd-bpf-capture-and-the-opnsense-sensor-plugin.md) — the plugin's original design
- [ADR 0018](0018-daemon-side-synpoip-collector-and-sensor-identity.md) — sensor identity on the daemon side
- [ADR 0024](0024-sensor-modes-and-synpoip-record-frames.md) — `send_mode`
- [ADR 0028](0028-opnsense-tls-material-and-selftest.md) — rendered TLS material and the selftest
- PROJECT.md §21 (least privilege, authenticated sensor identity), §23
  (configuration), §28.18 (authorised captures)
