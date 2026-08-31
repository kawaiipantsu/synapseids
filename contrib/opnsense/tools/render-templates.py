#!/usr/bin/env python3
"""Render the configd templates the way configd would, and check the results.

This is a development aid, not part of the package (it is deliberately absent
from pkg-plist).  OPNsense's configd renders these templates with Jinja2 against
a context built from config.xml plus a `helpers` object; nothing in this repo can
run configd, so the next best thing is to reproduce its behaviour exactly and
then assert on what comes out.

Three things are reproduced faithfully, because getting each of them wrong has
already shipped a broken plugin:

  1. THE JINJA ENVIRONMENT.  trim_blocks=True and the `do` / `loopcontrols`
     extensions, and NOTHING else -- no lstrip_blocks, no keep_trailing_newline,
     no StrictUndefined.  Rendering with Jinja's defaults instead let a
     whitespace bug through 17 green scenarios; rendering with *stricter*
     settings than configd is just as wrong in the other direction, because it
     hides behaviour this code depends on.  configd's own trailing-newline
     fixup is reproduced too.

  2. THE CONFIG SHAPE.  configd turns config.xml into nested dicts, where a
     repeating tag becomes a LIST but a single occurrence stays a DICT, and an
     empty element disappears entirely.  A plugin with a repeating item that is
     only ever tested with two of them will break on the firewall that has one.

  3. THE +TARGETS EXPANSION.  A destination containing [a.b.%.c] makes configd
     render one file per matching node with TARGET_FILTERS naming which one.
     That is how the sensor plugin gets one configuration file per capture
     instance (issue #124), so the expansion is reimplemented here from
     /usr/local/opnsense/service/modules/template.py rather than assumed.

And the check that matters most: every rendered configuration is SOURCED WITH
/bin/sh, because that is what the rc.d script does with it.

    python3 contrib/opnsense/tools/render-templates.py           # print renders
    python3 contrib/opnsense/tools/render-templates.py --check    # assert only

Exit status is non-zero if any scenario renders something the rc.d script or
`synapse-sensor doctor` would reject.
"""

import argparse
import copy
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile

try:
    import jinja2
except ImportError:  # pragma: no cover - developer convenience only
    print("render-templates: jinja2 is not installed (pip install jinja2)", file=sys.stderr)
    sys.exit(77)

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = (PLUGIN_ROOT / "src/opnsense/service/templates").resolve()
MODULE = "OPNsense/SynapseIDSSensor"
TEMPLATE_DIR = TEMPLATE_ROOT / MODULE


class Node(dict):
    """A config.xml subtree.

    configd exposes the configuration as nested dicts and templates reach into
    it with both dotted attribute access and subscripts, so both must work.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


class Helpers:
    """Stand-in for configd's template helper object.

    Mirrors service/modules/addons/template_helpers.py, including the detail
    that cost a bug: physical_interface() returns the INPUT NAME when it cannot
    resolve it, not an empty string.  A template that trusts the return value is
    therefore capable of binding a sensor to a device called "wan".
    """

    def __init__(self, config):
        self._config = config

    def getNodeByTag(self, tag):
        node = self._config
        for part in tag.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def exists(self, tag):
        return self.getNodeByTag(tag) is not None

    def empty(self, tag):
        node = self.getNodeByTag(tag)
        return node is None or node == "" or node == "0"

    def toList(self, tag, sortBy=None):
        result = self.getNodeByTag(tag)
        if result is None:
            return []
        if not isinstance(result, list):
            result = [result]
        if sortBy is None:
            return result
        return sorted(result, key=lambda d: d[sortBy])

    def physical_interface(self, name):
        # `getNodeByTag('interfaces.'+name+'.if') or name` -- verbatim.
        return self.getNodeByTag("interfaces." + name + ".if") or name


# --------------------------------------------------------------------------
# config.xml -> dict, the way configd's Config._traverse() does it
# --------------------------------------------------------------------------


def prune(node):
    """Drop empty leaves, exactly as _traverse() does.

    An empty XML element has `.text is None`, and configd skips those, so a
    template must never assume a field is present just because the model
    declares it.
    """
    if isinstance(node, dict):
        out = Node()
        for key, value in node.items():
            value = prune(value)
            if value is None or value == "":
                continue
            out[key] = value
        return out or None
    if isinstance(node, list):
        items = [prune(v) for v in node]
        items = [v for v in items if v is not None and v != ""]
        return items or None
    return node


def repeating(items):
    """One item stays a dict; several become a list; none disappears."""
    items = [i for i in (prune(i) for i in items) if i is not None]
    if not items:
        return None
    if len(items) == 1:
        return items[0]
    return items


# --------------------------------------------------------------------------
# +TARGETS expansion, from Template.__find_string_tags / __find_filters
# --------------------------------------------------------------------------


def find_string_tags(instr):
    out = []
    for item in instr.split("["):
        if item.find("]") > -1:
            out.append(item.split("]")[0])
    return out


def find_filters(config, tags):
    """Reimplementation of Template.__find_filters().

    Kept structurally identical to the original so that a future change in core
    is easy to diff against; the important behaviours it encodes are that the
    wildcard enumerates list indices OR dict keys, and that the resulting map is
    keyed by the resolved path and valued by the node's own value.
    """
    result = {}
    for tag in tags:
        result[tag] = {}
        config_ptr = config
        target_keys = []
        for name in tag.split("."):
            if isinstance(config_ptr, dict) and name in config_ptr:
                config_ptr = config_ptr[name]
            elif name == "%":
                if isinstance(config_ptr, dict):
                    target_keys = list(config_ptr)
                else:
                    target_keys = [str(x) for x in range(len(config_ptr))]
            else:
                config_ptr = None
                break
        if len(target_keys) == 0:
            result[tag] = {tag: config_ptr}
            continue
        for target_node in target_keys:
            config_ptr = config
            str_wildcard_loc = len(tag.split("%")[0].split("."))
            filter_target = []
            for name in tag.replace("%", target_node).split("."):
                if isinstance(config_ptr, dict) and name in config_ptr:
                    if isinstance(config_ptr[name], dict):
                        if str_wildcard_loc >= len(filter_target):
                            filter_target.append(name)
                        if str_wildcard_loc == len(filter_target):
                            result[tag][".".join(filter_target)] = name
                        config_ptr = config_ptr[name]
                    elif isinstance(config_ptr[name], list):
                        if str_wildcard_loc >= len(filter_target):
                            filter_target.append(name)
                            filter_target.append(target_node)
                        config_ptr = config_ptr[name][int(target_node)]
                    else:
                        result[tag][".".join(filter_target)] = config_ptr[name]
    return result


def expand_target(config, target):
    """Return [(filename, TARGET_FILTERS)] for one +TARGETS destination."""
    filters = find_filters(config, find_string_tags(target))
    names = {target: {}}
    for tag in list(filters):
        for key in list(filters[tag]):
            for filename in list(names):
                if filters[tag][key] is not None and filename.find("[%s]" % tag) > -1:
                    value = os.path.basename(filters[tag][key])
                    new = os.path.normpath(filename.replace("[%s]" % tag, value))
                    names[new] = copy.deepcopy(names[filename])
                    names[new][key] = filters[tag][key]
    return [
        (name, names[name])
        for name in names
        if not (name.find("[") != -1 and name.find("]") != -1)
    ]


def read_targets():
    """Parse +TARGETS into [(template, destination, cleanup)]."""
    out = []
    for line in (TEMPLATE_DIR / "+TARGETS").read_text().splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[0].strip()[0] != "#":
            src = parts[0].lstrip("!").strip()
            dst = parts[1].strip()
            cleanup = parts[2].strip() if len(parts) > 2 else dst
            out.append((src, dst, cleanup))
    return out


# --------------------------------------------------------------------------
# scenario fixtures
# --------------------------------------------------------------------------


def general(**overrides):
    node = Node(
        enabled="1",
        mode="listen",
        address="",
        token="a-bearer-token",
        verify_peer="1",
        ca="",
        client_cert="",
        client_key="",
    )
    node.update(overrides)
    return node


def instance(name, **overrides):
    node = Node(
        enabled="1",
        name=name,
        interface=name,
        listen_address="0.0.0.0:4789",
        filter="ip-any",
        direction="in",
        promiscuous="1",
        snaplen="262144",
        send_mode="raw",
        sensor_id="opnsense-" + name,
        location="dmz/edge",
        authorized="1",
        description="",
    )
    node.update(overrides)
    return node


CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----"

FOUR = ["wan", "dmz", "iot", "mgmt"]
FOUR_DEVICES = {
    "wan": {"if": "em0"},
    "dmz": {"if": "em1"},
    "iot": {"if": "igb0.20"},
    "mgmt": {"if": "igb0.99"},
}


def config_for(general_node, instances, interfaces=None, with_interfaces=True):
    """Build the whole rendering context the way configd would."""
    sensor = Node()
    if general_node is not None:
        sensor["general"] = prune(general_node) or Node()
    if instances:
        items = repeating(instances)
        if items is not None:
            sensor["instances"] = Node(instance=items)
    config = Node(OPNsense=Node(SynapseIDSSensor=sensor))
    if with_interfaces:
        source = interfaces if interfaces is not None else {"wan": {"if": "em0"}}
        config["interfaces"] = Node({k: Node(v) for k, v in source.items()})
    return config


def context(config, target_filters=None):
    ctx = dict(config)
    ctx["helpers"] = Helpers(config)
    ctx["TARGET_FILTERS"] = target_filters or {}
    return ctx


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def make_env():
    """The environment configd uses, and only that.

    Copied from Template.__init__ in
    /usr/local/opnsense/service/modules/template.py: FileSystemLoader on the
    templates root, trim_blocks, the do and loopcontrols extensions. Everything
    else is Jinja's default, INCLUDING the permissive Undefined -- a template
    that would raise here must be allowed to raise here.
    """
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_ROOT)),
        trim_blocks=True,
        extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
    )
    # The filters and tests configd registers on top of Jinja's own. A template
    # may use these and only these; anything else is a NameError on the box and
    # nowhere else.
    env.filters["decode_idna"] = lambda x: x.decode("idna")
    env.filters["encode_idna"] = lambda x: x
    env.filters["shlex_quote"] = shlex.quote
    env.filters["shlex_split"] = shlex.split
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(
        pattern, replacement, value)
    env.tests["regex_match"] = lambda value, pattern: bool(re.match(pattern, value))
    return env


def render(env, name, ctx):
    """Render one template, including configd's trailing-newline fixup."""
    content = env.get_template("%s/%s" % (MODULE, name)).render(**ctx)
    if len(content) > 1 and content[-1] != "\n":
        src = (TEMPLATE_DIR / name).read_bytes()
        if src[-1:] in (b"\n", b"\r"):
            content += "\n"
    return content


def render_module(env, config):
    """Render every +TARGETS entry, expanded, exactly as _generate() does.

    Returns {absolute destination: rendered text}.
    """
    out = {}
    for src, dst, _cleanup in read_targets():
        for filename, filters in expand_target(config, dst):
            out[filename] = render(env, src, context(config, filters))
    return out


def source_sh(text, names):
    """Source the rendered fragment with /bin/sh and read the variables back.

    This is the only check that tests what actually matters: rc.d does
    `. <file>`, so a variable is set only if the SHELL agrees it is.

    parse_sh() below silently skips comment lines, which is precisely how a real
    bug shipped: whitespace control glued `synapseids_sensor_enable="YES"` onto
    the trailing `# Generated by OPNsense` comment, so sh saw one commented line
    and set nothing, while the harness's own parser -- and the Go doctor's --
    happily reported the value from the args string. The sensor then refused to
    start with "no capture interface is configured" and the cause was three
    layers away from the symptom.
    """
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "sensor.conf")
        with open(f, "w") as fh:
            fh.write(text)
        script = ". " + f + "\n" + "\n".join(
            'printf "%s\\n" "${' + n + '-<<UNSET>>}"' for n in names)
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError("sh could not source the rendered file: " + r.stderr.strip())
        vals = r.stdout.split("\n")
        out = {}
        for name, val in zip(names, vals):
            if val == "<<UNSET>>":
                raise AssertionError(
                    "sh did not set %s -- the rendered file is not sourceable as intended "
                    "(check whitespace control: a '{%%-' after an emitted line eats its newline)"
                    % name)
            out[name] = val
        return out


INSTANCE_VARS = [
    "synapseids_sensor_enable",
    "synapseids_sensor_instance",
    "synapseids_sensor_iface",
    "synapseids_sensor_iface_id",
    "synapseids_sensor_iface_src",
    "synapseids_sensor_iface_error",
    "synapseids_sensor_args",
]

INDEX_VARS = [
    "synapseids_sensor_enable",
    "synapseids_sensor_profiles",
    "synapseids_sensor_instdir",
    "synapseids_sensor_iface",
    "synapseids_sensor_iface_id",
    "synapseids_sensor_iface_src",
    "synapseids_sensor_iface_error",
    "synapseids_sensor_args",
]


def parse_sh(text):
    """Parse the rendered fragment the way the Go doctor does, strictly."""
    out = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise AssertionError(f"line {lineno} is not name=value: {line!r}")
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise AssertionError(f"line {lineno}: bad variable name {name!r}")
        if not (value.startswith('"') and value.endswith('"')):
            raise AssertionError(f"line {lineno}: value is not double quoted: {value!r}")
        inner = value[1:-1]
        if '"' in inner:
            raise AssertionError(f"line {lineno}: embedded double quote: {value!r}")
        for bad in ("$", "`", ";", "|", "&"):
            if bad in inner:
                raise AssertionError(f"line {lineno}: shell metacharacter {bad!r}: {value!r}")
        out[name] = inner
    return out


SCENARIOS = []


def scenario(fn):
    SCENARIOS.append(fn)
    return fn


# --------------------------------------------------------------------------
# the sourceability scenarios, first because they are the ones that matter
# --------------------------------------------------------------------------


@scenario
def every_rendered_file_is_sourceable_by_sh(env):
    """rc.d does `. <file>`; sh must actually set every variable, in all of them."""
    config = config_for(general(), [instance(n) for n in FOUR], interfaces=FOUR_DEVICES)
    files = render_module(env, config)
    checked = []
    for path, text in sorted(files.items()):
        if not path.endswith(".conf"):
            continue
        names = INDEX_VARS if path.endswith("/sensor.conf") else INSTANCE_VARS
        got = source_sh(text, names)
        assert got, path
        checked.append(path)
    assert len(checked) == 5, checked
    return "sh sets every variable in %d rendered files" % len(checked)


@scenario
def four_interfaces_render_four_files(env):
    """The point of issue #124: four selected segments, four sensor processes."""
    config = config_for(general(), [instance(n) for n in FOUR], interfaces=FOUR_DEVICES)
    files = render_module(env, config)
    want = {
        "/usr/local/etc/synapseids/instances/%s.conf" % n for n in FOUR
    } | {
        "/usr/local/etc/synapseids/sensor.conf",
        "/usr/local/etc/synapseids/sensor.token",
        "/usr/local/etc/synapseids/sensor-ca.pem",
        "/usr/local/etc/synapseids/sensor-cert.pem",
        "/usr/local/etc/synapseids/sensor-key.pem",
    }
    assert set(files) == want, sorted(set(files) ^ want)

    index = parse_sh(files["/usr/local/etc/synapseids/sensor.conf"])
    assert index["synapseids_sensor_profiles"] == "wan dmz iot mgmt", index

    devices = {}
    ids = set()
    ports = set()
    for name, device in (("wan", "em0"), ("dmz", "em1"), ("iot", "igb0.20"), ("mgmt", "igb0.99")):
        out = parse_sh(files["/usr/local/etc/synapseids/instances/%s.conf" % name])
        assert out["synapseids_sensor_instance"] == name, out
        assert out["synapseids_sensor_enable"] == "YES", out
        assert out["synapseids_sensor_iface"] == device, out
        assert out["synapseids_sensor_iface_error"] == "", out
        assert "--iface " + device in out["synapseids_sensor_args"], out
        assert "--authorized" in out["synapseids_sensor_args"], out
        assert "--sensor-id 'opnsense-%s'" % name in out["synapseids_sensor_args"], out
        devices[name] = device
        ids.add("opnsense-" + name)
        ports.add(out["synapseids_sensor_args"])
    # Four distinct devices and four distinct identities: the whole reason for
    # running a process per interface.
    assert len(set(devices.values())) == 4, devices
    assert len(ids) == 4, ids
    assert len(ports) == 4, "two instances rendered identical flags"
    return "4 instances -> 4 files, 4 devices, 4 sensor ids"


@scenario
def a_single_instance_is_not_a_special_case(env):
    """config.xml stores ONE repeating item as a dict, not a list.

    A plugin tested only with several instances breaks on the firewall that has
    exactly one -- which is every firewall migrated from the single-sensor
    release.
    """
    config = config_for(general(), [instance("wan")])
    files = render_module(env, config)
    assert "/usr/local/etc/synapseids/instances/wan.conf" in files, sorted(files)
    out = source_sh(files["/usr/local/etc/synapseids/instances/wan.conf"], INSTANCE_VARS)
    assert out["synapseids_sensor_enable"] == "YES", out
    assert out["synapseids_sensor_instance"] == "wan", out
    assert out["synapseids_sensor_iface"] == "em0", out
    assert "--iface em0" in out["synapseids_sensor_args"], out
    index = parse_sh(files["/usr/local/etc/synapseids/sensor.conf"])
    assert index["synapseids_sensor_profiles"] == "wan", index
    return out


@scenario
def no_instances_renders_no_instance_files(env):
    """Before the first instance is added: an index with an empty profile list."""
    config = config_for(general(enabled="0"), [])
    files = render_module(env, config)
    assert not [p for p in files if "/instances/" in p], sorted(files)
    index = source_sh(files["/usr/local/etc/synapseids/sensor.conf"], INDEX_VARS)
    assert index["synapseids_sensor_profiles"] == "", index
    assert index["synapseids_sensor_enable"] == "NO", index
    return index


@scenario
def the_index_never_claims_to_be_a_sensor(env):
    """sensor.conf is the profile list, and must read as switched off.

    A bare `synapse-sensor doctor` uses it as its default --config. With
    enable=NO it reports a disabled sensor with no interface -- a WARN and a
    SKIP -- rather than a [FAIL] about a missing authorisation flag that belongs
    to no sensor at all.
    """
    config = config_for(general(), [instance(n) for n in FOUR], interfaces=FOUR_DEVICES)
    index = parse_sh(render_module(env, config)["/usr/local/etc/synapseids/sensor.conf"])
    assert index["synapseids_sensor_enable"] == "NO", index
    assert index["synapseids_sensor_args"] == "", index
    assert index["synapseids_sensor_iface"] == "", index
    assert index["synapseids_sensor_iface_error"] == "", index
    return index


@scenario
def the_two_macro_blocks_are_identical(env):
    """Both templates carry the same two macros; they must not drift apart.

    They are duplicated rather than imported on purpose: a `{% import %}` would
    add a cross-template loader dependency to the one file whose failure mode is
    a root-sourced shell fragment. Duplication is only safe while the two copies
    are the same, so that is asserted rather than hoped for.
    """
    def macros(name):
        text = (TEMPLATE_DIR / name).read_text()
        m = re.search(
            r"\{%-\s*macro sh\(value\).*?\{%-\s*macro pname\(value\).*?\{%-\s*endmacro\s*-%\}",
            text, re.S)
        assert m, name
        return m.group(0)

    a = macros("sensor.conf")
    b = macros("sensor-instance.conf")
    assert a == b, "the sh()/pname() macros have drifted apart"
    assert "regex_replace" in a, "pname() no longer restricts the instance name"
    return "sh() and pname() are byte-identical in both templates"


# --------------------------------------------------------------------------
# interface resolution
# --------------------------------------------------------------------------


@scenario
def resolved_via_interfaces_node(env):
    """The primary lookup: config.xml's <interfaces><wan><if>em0</if>."""
    config = config_for(general(), [instance("wan")])
    files = render_module(env, config)
    out = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])
    assert out["synapseids_sensor_iface"] == "em0", out
    assert out["synapseids_sensor_iface_id"] == "wan", out
    assert out["synapseids_sensor_iface_src"] == "interfaces.wan.if", out
    assert out["synapseids_sensor_iface_error"] == "", out
    for text in files.values():
        assert "a-bearer-token" not in text or text.strip() == "a-bearer-token", "TOKEN LEAKED"
    return out


@scenario
def resolved_via_helper(env):
    """No `interfaces` node at all: fall back to helpers.physical_interface()."""
    config = config_for(general(), [instance("wan")], with_interfaces=False)
    # The helper reads the same `interfaces` node, so give it one the template's
    # own subscript cannot see -- this is the only way the fallback can ever add
    # anything, and it is exercised here so the branch is not dead code.
    config["interfaces"] = Node(wan=Node({"if": "vtnet0"}))
    ctx_config = Node(config)
    files = {}
    for src, dst, _c in read_targets():
        for filename, filters in expand_target(ctx_config, dst):
            files[filename] = render(env, src, context(ctx_config, filters))
    out = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])
    assert out["synapseids_sensor_iface"] == "vtnet0", out
    return out


@scenario
def the_helper_echoing_the_identifier_is_treated_as_failure(env):
    """helpers.physical_interface() returns its INPUT when it cannot resolve.

    The core helper is `getNodeByTag('interfaces.'+name+'.if') or name`, so an
    unknown identifier comes back unchanged. Taking that at face value would put
    `--iface wan` on the command line: a plausible looking device name that
    binds to nothing, or worse, to the wrong thing if a device of that name ever
    existed. The template must treat it as "not found".
    """
    config = config_for(general(), [instance("wan")], interfaces={"lan": {"if": "em1"}})
    out = parse_sh(render_module(env, config)["/usr/local/etc/synapseids/instances/wan.conf"])
    assert out["synapseids_sensor_iface"] == "", out
    assert out["synapseids_sensor_iface"] != "wan", "fell back to the bare identifier"
    assert "could not be resolved" in out["synapseids_sensor_iface_error"], out
    assert "wan" in out["synapseids_sensor_iface_error"], out
    assert "--iface" not in out["synapseids_sensor_args"], out
    assert out["synapseids_sensor_iface_src"] == "", out
    return out


@scenario
def vlan_device_name(env):
    """A VLAN's device name carries a dot and must survive verbatim."""
    config = config_for(general(), [instance("iot")], interfaces={"iot": {"if": "igb0.10"}})
    out = parse_sh(render_module(env, config)["/usr/local/etc/synapseids/instances/iot.conf"])
    assert out["synapseids_sensor_iface"] == "igb0.10", out
    return out


@scenario
def no_interface_selected(env):
    config = config_for(general(), [instance("wan", interface="")])
    out = parse_sh(render_module(env, config)["/usr/local/etc/synapseids/instances/wan.conf"])
    assert out["synapseids_sensor_iface"] == "", out
    assert out["synapseids_sensor_iface_error"] == "", out
    assert "--iface" not in out["synapseids_sensor_args"], out
    return out


@scenario
def a_stored_multi_value_uses_only_the_first(env):
    """A pre-#132 configuration could store "wan,opt5". Never guess the rest.

    The migration turns each identifier into its own instance; if one somehow
    survives inside a single instance, the template must still resolve exactly
    one device rather than concatenating them into a name that matches nothing.
    """
    config = config_for(
        general(),
        [instance("wan", interface="wan,lan")],
        interfaces={"wan": {"if": "em0"}, "lan": {"if": "em1"}},
    )
    out = parse_sh(render_module(env, config)["/usr/local/etc/synapseids/instances/wan.conf"])
    assert out["synapseids_sensor_iface"] == "em0", out
    return out


# --------------------------------------------------------------------------
# transport and TLS
# --------------------------------------------------------------------------


@scenario
def per_instance_listen_ports(env):
    """Four listening sensors need four ports; the template must not invent one."""
    nodes = [
        instance("wan", listen_address="0.0.0.0:4789"),
        instance("dmz", listen_address="0.0.0.0:4790"),
        instance("iot", listen_address="0.0.0.0:4791"),
        instance("mgmt", listen_address="0.0.0.0:4792"),
    ]
    files = render_module(env, config_for(general(), nodes, interfaces=FOUR_DEVICES))
    ports = []
    for name, port in (("wan", "4789"), ("dmz", "4790"), ("iot", "4791"), ("mgmt", "4792")):
        args = parse_sh(files["/usr/local/etc/synapseids/instances/%s.conf" % name])["synapseids_sensor_args"]
        assert "--listen 0.0.0.0:" + port in args, args
        ports.append(port)
    assert len(set(ports)) == 4, ports
    return "4 distinct listen ports"


@scenario
def connect_mode_shares_one_collector(env):
    """In connect mode every instance dials the same address, with its own id."""
    node = general(mode="connect", address="ids.example.net:4789",
                   ca=CERT, client_cert=CERT, client_key=KEY)
    files = render_module(env, config_for(node, [instance(n) for n in FOUR], interfaces=FOUR_DEVICES))
    for name in FOUR:
        args = parse_sh(files["/usr/local/etc/synapseids/instances/%s.conf" % name])["synapseids_sensor_args"]
        assert "--connect ids.example.net:4789" in args, args
        assert "--cert /usr/local/etc/synapseids/sensor-cert.pem" in args, args
        assert "--key /usr/local/etc/synapseids/sensor-key.pem" in args, args
        assert "--ca /usr/local/etc/synapseids/sensor-ca.pem" in args, args
        assert "--insecure-tls" not in args, args
        assert "--listen" not in args, args
        assert "--sensor-id 'opnsense-%s'" % name in args, args
    return "4 instances, one collector, 4 identities"


@scenario
def listen_mode_with_client_ca(env):
    node = general(mode="listen", ca=CERT, client_cert=CERT, client_key=KEY)
    files = render_module(env, config_for(node, [instance("wan")]))
    args = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])["synapseids_sensor_args"]
    assert "--client-ca /usr/local/etc/synapseids/sensor-ca.pem" in args, args
    assert "--ca " not in args, args
    return args


@scenario
def insecure_tls_only_in_connect_mode(env):
    node = general(mode="connect", address="ids.example.net:4789", verify_peer="0")
    files = render_module(env, config_for(node, [instance("wan")]))
    args = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])["synapseids_sensor_args"]
    assert "--insecure-tls" in args, args
    return args


@scenario
def send_mode_is_per_instance(env):
    """A sensitive segment can be feature-only while the WAN stays raw."""
    nodes = [
        instance("wan", send_mode="raw"),
        instance("iot", send_mode="feature"),
        instance("dmz", send_mode="flow"),
    ]
    files = render_module(env, config_for(general(), nodes, interfaces=FOUR_DEVICES))
    wan = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])["synapseids_sensor_args"]
    iot = parse_sh(files["/usr/local/etc/synapseids/instances/iot.conf"])["synapseids_sensor_args"]
    dmz = parse_sh(files["/usr/local/etc/synapseids/instances/dmz.conf"])["synapseids_sensor_args"]
    assert "--mode" not in wan, wan
    assert "--mode feature" in iot, iot
    assert "--mode flow" in dmz, dmz
    return "raw / feature / flow, per instance"


# --------------------------------------------------------------------------
# authorisation and enablement
# --------------------------------------------------------------------------


@scenario
def authorisation_is_never_inherited(env):
    """An unauthorised instance renders WITHOUT --authorized.

    The model refuses to save that combination, so this is the second barrier:
    even if such a configuration reached the box, synapse-sensor would refuse to
    capture and the selftest would say which instance and why.
    """
    nodes = [instance("wan"), instance("iot", authorized="0")]
    files = render_module(env, config_for(general(), nodes, interfaces=FOUR_DEVICES))
    wan = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])["synapseids_sensor_args"]
    iot = parse_sh(files["/usr/local/etc/synapseids/instances/iot.conf"])["synapseids_sensor_args"]
    assert "--authorized" in wan, wan
    assert "--authorized" not in iot, iot
    return "authorisation follows the instance, not the firewall"


@scenario
def both_switches_must_be_on(env):
    """Plugin-wide off, or instance off, means enable=NO for that instance."""
    nodes = [instance("wan"), instance("dmz", enabled="0")]
    files = render_module(env, config_for(general(), nodes, interfaces=FOUR_DEVICES))
    assert parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])["synapseids_sensor_enable"] == "YES"
    assert parse_sh(files["/usr/local/etc/synapseids/instances/dmz.conf"])["synapseids_sensor_enable"] == "NO"

    files = render_module(env, config_for(general(enabled="0"), nodes, interfaces=FOUR_DEVICES))
    for name in ("wan", "dmz"):
        got = parse_sh(files["/usr/local/etc/synapseids/instances/%s.conf" % name])
        assert got["synapseids_sensor_enable"] == "NO", got

    # A disabled instance is still listed: rc.d needs the name in order to stop
    # it, and the selftest needs it in order to report on it.
    index = parse_sh(files["/usr/local/etc/synapseids/sensor.conf"])
    assert index["synapseids_sensor_profiles"] == "wan dmz", index
    return "enable = plugin AND instance; the profile list carries both"


# --------------------------------------------------------------------------
# hostile input
# --------------------------------------------------------------------------


@scenario
def hostile_config_values_cannot_escape(env):
    """A config value must never break out of the generated shell word."""
    node = instance(
        "wan",
        sensor_id="a'; touch /tmp/pwned; '",
        location='x"$(id)`id`&&whoami|tee>/tmp/x',
        listen_address="0.0.0.0:4789\nsynapseids_sensor_enable=NO",
    )
    files = render_module(env, config_for(general(), [node]))
    out = parse_sh(files["/usr/local/etc/synapseids/instances/wan.conf"])
    args = out["synapseids_sensor_args"]
    for bad in ("'", '"', "`", "$", ";", "|", "&", "<", ">", "\\"):
        # The only quotes left must be the ones the template itself added around
        # --sensor-id / --location values.
        if bad == "'":
            continue
        assert bad not in args, f"{bad!r} survived sh(): {args!r}"
    assert out["synapseids_sensor_enable"] == "YES", "a config value forged an assignment"
    # And the file must still be sourceable, which is the property that counts.
    source_sh(files["/usr/local/etc/synapseids/instances/wan.conf"], INSTANCE_VARS)
    return out


@scenario
def a_hostile_instance_name_cannot_escape_the_path(env):
    """The instance name reaches a FILENAME, so a traversal attempt must not work.

    The model's Mask makes this unreachable through the GUI; this asserts the
    second barrier, in the template, for a config.xml edited by hand.
    """
    node = instance("wan")
    node["name"] = "../../../../etc/rc.conf"
    config = config_for(general(), [node])
    files = render_module(env, config)
    for path in files:
        assert path.startswith("/usr/local/etc/synapseids/"), path
    index = parse_sh(files["/usr/local/etc/synapseids/sensor.conf"])
    assert "/" not in index["synapseids_sensor_profiles"], index
    return index


@scenario
def missing_config_node(env):
    """Before the model has ever been saved: everything empty, service off."""
    config = Node(OPNsense=Node())
    files = render_module(env, config)
    out = parse_sh(files["/usr/local/etc/synapseids/sensor.conf"])
    assert out["synapseids_sensor_enable"] == "NO", out
    assert out["synapseids_sensor_profiles"] == "", out
    assert out["synapseids_sensor_args"] == "", out
    assert not [p for p in files if "/instances/" in p], sorted(files)
    return out


# --------------------------------------------------------------------------
# the secret-bearing targets
# --------------------------------------------------------------------------


@scenario
def token_template_is_the_token_and_nothing_else(env):
    config = config_for(general(), [instance("wan")])
    out = render_module(env, config)["/usr/local/etc/synapseids/sensor.token"]
    assert out.strip() == "a-bearer-token", repr(out)
    assert "#" not in out, "the token file must carry no comment header"
    return out.strip()


@scenario
def token_template_empty_when_unset(env):
    config = config_for(general(token=""), [instance("wan")])
    out = render_module(env, config)["/usr/local/etc/synapseids/sensor.token"]
    assert out.strip() == "", repr(out)
    return "(empty)"


@scenario
def pem_templates_render_the_blobs(env):
    config = config_for(general(ca=CERT, client_cert=CERT, client_key=KEY), [instance("wan")])
    files = render_module(env, config)
    for name, want in (
        ("sensor-ca.pem", CERT),
        ("sensor-cert.pem", CERT),
        ("sensor-key.pem", KEY),
    ):
        out = files["/usr/local/etc/synapseids/" + name]
        assert out.strip() == want, f"{name}: {out!r}"
        assert out.endswith("\n"), f"{name} must end with a newline"
        assert "{" not in out and "#" not in out, f"{name} leaked template text: {out!r}"
    return "3 PEM targets render exactly their blob"


@scenario
def pem_templates_normalise_crlf(env):
    """A blob pasted from a Windows editor must not reach disk with CRLF."""
    config = config_for(general(client_key=KEY.replace("\n", "\r\n")), [instance("wan")])
    out = render_module(env, config)["/usr/local/etc/synapseids/sensor-key.pem"]
    assert "\r" not in out, repr(out)
    assert out.strip() == KEY, repr(out)
    return "CRLF normalised"


@scenario
def pem_templates_empty_when_unset(env):
    config = config_for(general(), [instance("wan")])
    files = render_module(env, config)
    for name in ("sensor-ca.pem", "sensor-cert.pem", "sensor-key.pem"):
        out = files["/usr/local/etc/synapseids/" + name]
        assert out.strip() == "", f"{name}: {out!r}"
    return "3 PEM targets render empty (rc.d then refuses to start if referenced)"


@scenario
def no_rendered_file_carries_a_secret_it_should_not(env):
    """The token and the private key belong in exactly one file each."""
    config = config_for(
        general(token="s3cr3t-token-value", ca=CERT, client_cert=CERT, client_key=KEY),
        [instance(n) for n in FOUR],
        interfaces=FOUR_DEVICES,
    )
    files = render_module(env, config)
    for path, text in files.items():
        if path.endswith("sensor.token"):
            continue
        assert "s3cr3t-token-value" not in text, "TOKEN LEAKED into " + path
        if path.endswith("sensor-key.pem"):
            continue
        assert "PRIVATE KEY" not in text, "PRIVATE KEY LEAKED into " + path
    return "token in sensor.token only, key in sensor-key.pem only"


# --------------------------------------------------------------------------
# packaging agreement
# --------------------------------------------------------------------------


@scenario
def targets_file_covers_every_template(env):
    """+TARGETS, pkg-plist and the template directory must agree."""
    targets = {src: dst for src, dst, _c in read_targets()}

    on_disk = {p.name for p in TEMPLATE_DIR.iterdir() if p.name != "+TARGETS"}
    assert set(targets) == on_disk, f"+TARGETS {sorted(targets)} != directory {sorted(on_disk)}"

    plist = (PLUGIN_ROOT / "pkg-plist").read_text()
    for name in sorted(on_disk | {"+TARGETS"}):
        needle = f"opnsense/service/templates/OPNsense/SynapseIDSSensor/{name}"
        assert needle in plist, f"{needle} is missing from pkg-plist"

    for src, dst, cleanup in read_targets():
        assert dst.startswith("/usr/local/etc/synapseids/"), dst
        assert cleanup.startswith("/usr/local/etc/synapseids/"), cleanup
    return f"{len(targets)} targets, all in pkg-plist"


@scenario
def the_plugin_source_tree_matches_pkg_plist(env):
    """Every file under src/ is packaged, and nothing is listed that is missing."""
    src_root = PLUGIN_ROOT / "src"
    on_disk = sorted(
        str(p.relative_to(src_root)) for p in src_root.rglob("*") if p.is_file()
    )
    listed = sorted(
        line.strip()
        for line in (PLUGIN_ROOT / "pkg-plist").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#") and line.strip() != "bin/synapse-sensor"
    )
    assert on_disk == listed, "pkg-plist drift:\n  only on disk: %s\n  only listed: %s" % (
        sorted(set(on_disk) - set(listed)), sorted(set(listed) - set(on_disk)))
    return f"{len(on_disk)} source files, all in pkg-plist"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="assert only, print no renders")
    args = ap.parse_args()

    env = make_env()

    failures = 0
    for fn in SCENARIOS:
        try:
            result = fn(env)
        except Exception as exc:  # noqa: BLE001 - report every scenario
            failures += 1
            print(f"FAIL  {fn.__name__}: {type(exc).__name__}: {exc}")
            continue
        print(f"ok    {fn.__name__}")
        if not args.check:
            if isinstance(result, dict):
                for k, v in result.items():
                    print(f"          {k}={v!r}")
            else:
                print(f"          {result!r}")

    print(f"\n{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
