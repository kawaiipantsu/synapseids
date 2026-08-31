package main

// The OPNsense plugin runs one synapse-sensor process per captured interface
// (issue #124). The pieces that make that work are spread across a Jinja
// template, an rc.d script, a configd action file, a model migration and this
// binary's `doctor` subcommand, and only the last of those is Go — so these
// tests pin the contracts between them, which is the only place they can be
// pinned from a Linux build host at all.
//
// The failure they exist to prevent is the one the whole change is about: a
// firewall that reports healthy sensors on four interfaces while capturing one
// segment, with nothing anywhere reporting the difference.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	rcScript      = "../../contrib/opnsense/src/etc/rc.d/synapseids_sensor"
	templatesDir  = "../../contrib/opnsense/src/opnsense/service/templates/OPNsense/SynapseIDSSensor"
	targetsFile   = templatesDir + "/+TARGETS"
	instanceTmpl  = templatesDir + "/sensor-instance.conf"
	pkgPlist      = "../../contrib/opnsense/pkg-plist"
	modelDir      = "../../contrib/opnsense/src/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor"
	sensorModel   = modelDir + "/Sensor.xml"
	sensorPHP     = modelDir + "/Sensor.php"
	migrationFile = modelDir + "/Migrations/M1_0_1.php"
)

// One template must emit one configuration file per sensor instance, which
// configd only does when the +TARGETS destination carries a bracketed tag with a
// `%` wildcard. Without it the plugin silently degrades to a single sensor — the
// exact bug issue #124 reports, reintroduced one layer down.
func TestPerInstanceTemplateTargetExpands(t *testing.T) {
	targets := readScript(t, targetsFile)

	var line string
	for _, l := range strings.Split(targets, "\n") {
		if strings.HasPrefix(l, "sensor-instance.conf:") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("+TARGETS has no sensor-instance.conf entry, so no per-instance file is ever rendered")
	}

	parts := strings.Split(line, ":")
	if len(parts) != 3 {
		t.Fatalf("expected template:destination:cleanup, got %d fields: %q", len(parts), line)
	}
	dst, cleanup := parts[1], parts[2]

	if !strings.Contains(dst, "[") || !strings.Contains(dst, "%") {
		t.Errorf("destination %q has no [tag.%%.field], so configd renders ONE file, not one per instance", dst)
	}
	// The wildcard has to land on the repeating node and the tag has to end in
	// the scalar field whose value names the file. Template.__find_filters()
	// returns nothing usable for a bare trailing `.%` on a list, so these are
	// not interchangeable and the difference is zero rendered files.
	if !strings.Contains(dst, "OPNsense.SynapseIDSSensor.instances.instance.%.name") {
		t.Errorf("destination %q does not resolve the instance NAME; "+
			"a wildcard that does not end in a scalar field yields no files at all", dst)
	}
	for _, path := range []string{dst, cleanup} {
		if !strings.HasPrefix(path, "/usr/local/etc/synapseids/instances/") {
			t.Errorf("%q is outside the instances directory", path)
		}
	}
	if !strings.HasSuffix(cleanup, "*.conf") {
		t.Errorf("cleanup target %q is not a glob, so `template cleanup` would try to "+
			"remove a literal path containing [brackets]", cleanup)
	}
}

// The rc.d script must be a multi-profile service in the established FreeBSD
// shape, not one service started several times: its own pidfile, log directory
// and rendered configuration each, or three of four sensors end up unsupervised
// and unattributable.
func TestRCScriptRunsOneProcessPerInstance(t *testing.T) {
	rc := readScript(t, rcScript)

	for _, want := range []string{
		"synapseids_sensor_profiles", // the profile list, openvpn/nginx style
		"synapseids_sensor_instdir",  // where the per-instance files live
		"synapseids_sensor_profile",  // the instance this invocation acts on
	} {
		if !strings.Contains(rc, want) {
			t.Errorf("rc.d script does not mention %s", want)
		}
	}

	// The pidfile, the log directory and the syslog tag must all vary with the
	// profile.
	pid := regexp.MustCompile(`(?m)^pidfile="([^"]+)"`).FindStringSubmatch(rc)
	if pid == nil {
		t.Fatal("rc.d script has no pidfile= assignment")
	}
	if !strings.Contains(pid[1], "synapseids_sensor_profile") {
		t.Errorf("pidfile %q does not vary per instance; four sensors would fight over one file", pid[1])
	}
	if !regexp.MustCompile(`synapseids_sensor_logdir="[^"]*synapseids_sensor_profile`).MatchString(rc) {
		t.Error("the log directory does not vary per instance; four sensors would interleave into one file")
	}

	// The aggregate invocation has to reach every profile. Re-executing this
	// script per profile is what keeps rc.subr's per-instance state (rcvar,
	// pidfile, precmd) scoped to one sensor.
	if !regexp.MustCompile(`for \w+ in \$\{synapseids_sensor_profiles\}`).MatchString(rc) {
		t.Error("rc.d script never iterates the profile list, so `service ... start` starts nothing")
	}

	// Deleting an instance in the GUI removes it from the profile list; without
	// this sweep its process would keep capturing a segment the operator
	// believes they stopped monitoring, until the next reboot.
	if !strings.Contains(rc, "check_pidfile") {
		t.Error("rc.d script does not sweep orphaned pidfiles, so a deleted instance keeps capturing")
	}
}

// `synapse-sensor doctor` checks exactly one rendered configuration and looks
// for sensor.log inside whatever --log-dir it is given. The rc.d script is its
// only caller on a firewall, so that contract is pinned here — it is what lets
// one unchanged Go subcommand produce a per-instance selftest.
func TestSelftestIsPerInstance(t *testing.T) {
	rc := readScript(t, rcScript)

	// --config must point at the instance file, not at the index: the index
	// carries no flags at all, so pointing doctor at it would report every
	// sensor as unconfigured.
	if !strings.Contains(rc, `--config "${_instconf}"`) {
		t.Error("the selftest does not point --config at the per-instance configuration")
	}
	// --log-dir must be the instance's own directory, because checkLogSink()
	// joins "sensor.log" onto it. Passing the shared base directory would warn
	// "sensor.log does not exist yet" against every instance, forever.
	if !strings.Contains(rc, `--log-dir "${_logdir}"`) {
		t.Error("the selftest does not give doctor the instance's own log directory")
	}
	if !strings.Contains(rc, "synapseids_sensor_logbase}/${_profile}") {
		t.Error("the per-instance log directory is not <logbase>/<instance>, which is what " +
			"doctor --log-dir expects to contain sensor.log")
	}
	// One line per check, with the instance in its own column: an operator with
	// four sensors has to be able to see WHICH one is broken, and
	// `selftest | grep FAIL` has to keep working.
	if !strings.Contains(rc, `s/^\(\[[A-Z ]*\]\) /\1 ${_label} /`) {
		t.Error("the selftest does not label each result line with the instance name")
	}
	if !strings.Contains(rc, `printf '%-10.10s'`) {
		t.Error("the instance label is not fixed-width, so the selftest output stops lining up")
	}
	// Running doctor twice to recover its exit status would double every TCP
	// connect it makes and could report two different answers.
	if strings.Count(rc, `"${synapseids_sensor_bin}" doctor`) != 1 {
		t.Error("the selftest invokes doctor more than once per instance")
	}

	// checkLogSink() and the rc.d layout must agree on the file name.
	if !strings.Contains(readScript(t, "doctor.go"), `filepath.Join(env.logDir, "sensor.log")`) {
		t.Error("doctor no longer looks for sensor.log inside --log-dir; the rc.d script's " +
			"per-instance log directory layout depends on it")
	}
}

// Every lifecycle action has to be able to address one instance, and configd can
// only pass a parameter through a `parameters:` template — never through
// `command:`, where its own substitution would eat a stray %.
func TestConfigdActionsAcceptAnInstance(t *testing.T) {
	conf := readScript(t, actionsConf)

	for _, action := range []string{"start", "stop", "restart", "status", "log", "selftest"} {
		block := regexp.MustCompile(`(?ms)^\[` + action + `\]\s*$(.*?)(?:^\[|\z)`).FindStringSubmatch(conf)
		if block == nil {
			t.Errorf("no [%s] action", action)
			continue
		}
		if !strings.Contains(block[1], "\nparameters:%s\n") {
			t.Errorf("[%s] has no `parameters:%%s`, so `configctl synapseidssensor %s wan` "+
				"cannot reach a single sensor", action, action)
		}
	}

	// The instance name reaches a filesystem path in the log action. configd
	// single-quotes parameters, which stops shell injection but not traversal.
	logBlock := regexp.MustCompile(`(?ms)^\[log\]\s*$(.*?)(?:^\[|\z)`).FindStringSubmatch(conf)
	if logBlock == nil {
		t.Fatal("no [log] action")
	}
	if !strings.Contains(logBlock[1], "[!A-Za-z0-9_]") {
		t.Error("[log] builds a path from the instance parameter without validating it")
	}
}

// A model version with no matching migration means BaseModel::runMigrations()
// bumps the stored version and moves nothing: on a real firewall the settings
// page would come up empty after an upgrade and an operator's working sensor
// would look lost.
func TestModelVersionHasAMigrationThatThePackageRuns(t *testing.T) {
	model := readScript(t, sensorModel)
	m := regexp.MustCompile(`<version>([0-9.]+)</version>`).FindStringSubmatch(model)
	if m == nil {
		t.Fatal("Sensor.xml declares no <version>")
	}
	version := m[1]
	if version == "1.0.0" {
		t.Error("the model still claims version 1.0.0, so no migration will ever run")
	}

	wantFile := "M" + strings.ReplaceAll(version, ".", "_") + ".php"
	if !strings.HasSuffix(migrationFile, wantFile) {
		t.Errorf("model version %s needs Migrations/%s", version, wantFile)
	}
	if _, err := os.Stat(migrationFile); err != nil {
		t.Fatalf("%s: %v", migrationFile, err)
	}

	// rc.configure_plugins does NOT run migrations — it flushes caches and
	// restarts syslog — so the post-install has to do it explicitly.
	pkg := readScript(t, packageSh)
	if !strings.Contains(pkg, "run_migrations.php") {
		t.Error("post-install never runs run_migrations.php, so the migration above never executes")
	}
	if !strings.Contains(pkg, "OPNsense/SynapseIDSSensor") {
		t.Error("the migration runner is not scoped to this plugin's models")
	}
}

// The authorisation assertion is per instance and may not be inherited: being
// allowed to monitor the WAN uplink is not being allowed to monitor a tenant
// VLAN (PROJECT.md §28.18). Three places have to agree on that.
func TestAuthorisationIsPerInstance(t *testing.T) {
	model := readScript(t, sensorModel)

	start := strings.Index(model, "<instances>")
	if start < 0 {
		t.Fatal("the model has no <instances> node")
	}
	if !strings.Contains(model[start:], "<authorized type=\"BooleanField\">") {
		t.Error("the authorisation assertion is not declared on the instance")
	}
	if strings.Contains(model[:start], "<authorized type=\"BooleanField\">") {
		t.Error("a plugin-wide authorisation checkbox is back; §28.18 is a per-segment decision")
	}

	if !strings.Contains(readScript(t, sensorPHP), "28.18") {
		t.Error("Sensor::performValidation no longer cites the rule it enforces")
	}

	// The migration must not hand an authorisation made about one interface to
	// the interfaces that were selected but never actually captured.
	mig := readScript(t, migrationFile)
	if !strings.Contains(mig, "$node->authorized = '0';") {
		t.Error("the migration does not leave the previously-discarded interfaces unauthorised")
	}
	if !strings.Contains(mig, "$node->enabled = '0';") {
		t.Error("the migration would start capturing interfaces that were never captured before")
	}
}

// Every file under contrib/opnsense/src is installed by both packaging paths, so
// pkg-plist and the tree must not drift. package-opnsense.sh fails the build on
// drift, but that only runs on `make opnsense-pkg`; this runs in `make test`.
func TestPkgPlistMatchesThePluginSourceTree(t *testing.T) {
	const srcRoot = "../../contrib/opnsense/src"

	var onDisk []string
	err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(srcRoot, path)
		if rerr != nil {
			return rerr
		}
		onDisk = append(onDisk, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", srcRoot, err)
	}

	listed := map[string]bool{}
	for _, line := range strings.Split(readScript(t, pkgPlist), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "bin/synapse-sensor" {
			continue
		}
		listed[line] = true
	}

	for _, f := range onDisk {
		if !listed[f] {
			t.Errorf("pkg-plist is missing %s", f)
		}
		delete(listed, f)
	}
	for f := range listed {
		t.Errorf("pkg-plist lists %s, which is not in the source tree", f)
	}
}

// The per-instance template must emit exactly the variable names `doctor` reads,
// and never a secret. That identity is what lets one unchanged Go subcommand
// check any one of N sensors.
func TestInstanceTemplateRendersWhatDoctorReads(t *testing.T) {
	tmpl := readScript(t, instanceTmpl)

	for _, v := range []string{
		"synapseids_sensor_enable",
		"synapseids_sensor_iface",
		"synapseids_sensor_iface_id",
		"synapseids_sensor_iface_src",
		"synapseids_sensor_iface_error",
		"synapseids_sensor_args",
	} {
		if !strings.Contains(tmpl, v+`="`) {
			t.Errorf("sensor-instance.conf does not render %s, which doctor reads", v)
		}
	}

	// The token and the private key have exactly one rendered file each, and
	// this is not it. Only the PEM *paths* may appear here.
	for _, forbidden := range []string{"general['token']", "node['token']", "general['client_key'] ~"} {
		if strings.Contains(tmpl, forbidden) {
			t.Errorf("sensor-instance.conf interpolates %q; no secret may reach this file", forbidden)
		}
	}

	// Whitespace control below the macro block is what produced a rendered file
	// /bin/sh read as a single comment, setting nothing, while every parser in
	// the tree still reported the right values.
	const endOfMacros = "{%- endmacro -%}"
	i := strings.LastIndex(tmpl, endOfMacros)
	if i < 0 {
		t.Fatal("sensor-instance.conf has no macro block")
	}
	body := tmpl[i+len(endOfMacros):]
	if strings.Contains(body, "{%-") || strings.Contains(body, "-%}") {
		t.Error("sensor-instance.conf uses whitespace control below the macros; with " +
			"trim_blocks that eats the PRECEDING line's newline and glues two assignments together")
	}
}
