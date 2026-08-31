package main

// Tests that the OPNsense package's file name, as *built* by
// scripts/package-opnsense.sh, is byte-for-byte the name
// contrib/opnsense/install.sh *asks for* on the firewall.
//
// A mismatch between those two is the difference between a working install and a
// 404 that reads like the release is missing, and neither side can be exercised
// from Go directly — one runs on a Linux build host, the other on FreeBSD. So
// these tests do the next best thing: they lift the actual derivation logic out
// of both shell scripts and run it under /bin/sh, then compare. Editing either
// script's naming or architecture mapping without editing the other fails here.
//
// Also covered: the SHA256SUMS line parser in install.sh, which must accept both
// forms sha256sum(1) emits — it previously required the leading "./" and
// silently rejected a bare name.

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const (
	installSh   = "../../contrib/opnsense/install.sh"
	packageSh   = "../../scripts/package-opnsense.sh"
	pkgBaseName = "os-synapseids-sensor"
)

func readScript(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// runSh executes a script fragment with /bin/sh and returns its trimmed stdout.
func runSh(t *testing.T, script string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	cmd := exec.Command("sh", "-c", script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// extractCase pulls a `case "$var" in ... esac` block out of a shell script.
func extractCase(t *testing.T, script, variable string) string {
	t.Helper()
	// Both scripts indent differently (install.sh at column 0,
	// package-opnsense.sh inside a for loop), so leading whitespace is optional.
	re := regexp.MustCompile(`(?s)case "\$` + regexp.QuoteMeta(variable) + `" in\n(.*?)\n[ \t]*esac`)
	m := re.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no `case \"$%s\" in ... esac` block found; did the script change shape?", variable)
	}
	return "case \"$" + variable + "\" in\n" + m[1] + "\nesac"
}

// ---------------------------------------------------------------- name shape

// Both scripts must build the name from the same pieces in the same order. The
// variable *names* differ between the scripts, so they are normalised to
// placeholders before comparison.
func TestOPNsensePackageFilenameFormatsAgree(t *testing.T) {
	install := readScript(t, installSh)
	pkg := readScript(t, packageSh)

	installLine := regexp.MustCompile(`(?m)^PKGFILE="([^"]+)"`).FindStringSubmatch(install)
	if installLine == nil {
		t.Fatal("install.sh: no PKGFILE= assignment found")
	}
	pkgLine := regexp.MustCompile(`(?m)^\s*out="\$DIST/([^"]+)"`).FindStringSubmatch(pkg)
	if pkgLine == nil {
		t.Fatal("package-opnsense.sh: no out=\"$DIST/...\" assignment found")
	}

	normalise := func(s string) string {
		for _, pair := range [][2]string{
			{"${PKGNAME}", "<name>"},
			{"${VER}", "<ver>"},
			{"${FBSD_MAJOR}", "<major>"},
			{"${major}", "<major>"},
			{"${GOARCH}", "<goarch>"},
			{"${goarch}", "<goarch>"},
		} {
			s = strings.ReplaceAll(s, pair[0], pair[1])
		}
		return s
	}

	gotInstall, gotPkg := normalise(installLine[1]), normalise(pkgLine[1])
	if gotInstall != gotPkg {
		t.Errorf("package file name formats disagree:\n  install.sh builds:            %s\n  package-opnsense.sh builds:  %s",
			gotInstall, gotPkg)
	}
	const want = "<name>-<ver>-freebsd<major>-<goarch>.pkg"
	if gotInstall != want {
		t.Errorf("name format = %q, want %q", gotInstall, want)
	}
}

// ---------------------------------------------------------------- abi mapping

// The one thing that could differ without either script looking wrong: the
// mapping from a pkg(8) architecture to a GOARCH. `pkg config abi` reports
// aarch64 on arm64 hardware, and both scripts must land on "arm64" in the file
// name.
func TestOPNsensePackageABIDerivation(t *testing.T) {
	installCase := extractCase(t, readScript(t, installSh), "PKG_ARCH")
	pkgCase := extractCase(t, readScript(t, packageSh), "pkgarch")

	for _, tc := range []struct {
		abi      string // what `pkg config abi` reports
		wantName string
	}{
		{"FreeBSD:14:amd64", pkgBaseName + "-0.2.0-freebsd14-amd64.pkg"},
		{"FreeBSD:14:aarch64", pkgBaseName + "-0.2.0-freebsd14-arm64.pkg"},
		{"FreeBSD:14:arm64", pkgBaseName + "-0.2.0-freebsd14-arm64.pkg"},
		{"FreeBSD:15:amd64", pkgBaseName + "-0.2.0-freebsd15-amd64.pkg"},
		{"FreeBSD:13:amd64", pkgBaseName + "-0.2.0-freebsd13-amd64.pkg"},
	} {
		t.Run(tc.abi, func(t *testing.T) {
			// The installer side, verbatim from install.sh.
			installScript := `
set -eu
err() { echo "UNSUPPORTED: $*"; exit 1; }
ABI="` + tc.abi + `"
PKGNAME="` + pkgBaseName + `"
VER="0.2.0"
FBSD_MAJOR="$(echo "$ABI" | cut -d: -f2)"
PKG_ARCH="$(echo "$ABI" | cut -d: -f3)"
` + installCase + `
echo "${PKGNAME}-${VER}-freebsd${FBSD_MAJOR}-${GOARCH}.pkg"
`
			gotInstall, err := runSh(t, installScript)
			if err != nil {
				t.Fatalf("install.sh derivation failed for %s: %v\n%s", tc.abi, err, gotInstall)
			}
			if gotInstall != tc.wantName {
				t.Errorf("install.sh would request %q, want %q", gotInstall, tc.wantName)
			}

			// The build side, verbatim from package-opnsense.sh.
			buildScript := `
set -eu
err() { echo "UNSUPPORTED: $*"; exit 1; }
abi="` + tc.abi + `"
PKGNAME="` + pkgBaseName + `"
VER="0.2.0"
major="$(echo "$abi" | cut -d: -f2)"
pkgarch="$(echo "$abi" | cut -d: -f3)"
` + pkgCase + `
echo "${PKGNAME}-${VER}-freebsd${major}-${goarch}.pkg"
`
			gotBuild, err := runSh(t, buildScript)
			if err != nil {
				t.Fatalf("package-opnsense.sh derivation failed for %s: %v\n%s", tc.abi, err, gotBuild)
			}
			if gotBuild != tc.wantName {
				t.Errorf("package-opnsense.sh would build %q, want %q", gotBuild, tc.wantName)
			}
			if gotInstall != gotBuild {
				t.Errorf("MISMATCH for %s: build produces %q, installer requests %q",
					tc.abi, gotBuild, gotInstall)
			}
		})
	}
}

// An architecture the plugin does not ship must be refused with a clear message,
// not turned into a URL that 404s.
func TestOPNsensePackageRejectsUnknownArch(t *testing.T) {
	installCase := extractCase(t, readScript(t, installSh), "PKG_ARCH")
	out, err := runSh(t, `
err() { echo "UNSUPPORTED: $*"; exit 1; }
PKG_ARCH="powerpc64"
`+installCase+`
echo "accepted GOARCH=$GOARCH"
`)
	if err == nil {
		t.Errorf("an unshipped architecture was accepted: %s", out)
	}
	if !strings.Contains(out, "UNSUPPORTED") {
		t.Errorf("output = %q, want the err() message", out)
	}
}

// ------------------------------------------------------------- SHA256SUMS

// install.sh refuses to install a package it cannot verify, so its SHA256SUMS
// parser has to accept every form the release file actually contains. This runs
// the two shipped lines against a fixture.
func TestInstallShSHA256SUMSParser(t *testing.T) {
	install := readScript(t, installSh)

	reLine := regexp.MustCompile(`(?m)^\s*(pkgfile_re="[^\n]+")`).FindStringSubmatch(install)
	if reLine == nil {
		t.Fatal("install.sh: no pkgfile_re= assignment found")
	}
	// The `want=` assignment is wrapped across several lines with backslashes.
	wantLine := regexp.MustCompile(`(?s)(want="\$\(sed -n \\\n.*?\| head -1\)")`).FindStringSubmatch(install)
	if wantLine == nil {
		t.Fatal("install.sh: no want=\"$(sed ...)\" assignment found")
	}

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const other = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	pkgfile := pkgBaseName + "-0.2.0-freebsd14-amd64.pkg"

	for _, tc := range []struct {
		name string
		sums string
		want string
	}{
		{
			// What `sha256sum ./*.pkg` produces, which is how
			// package-opnsense.sh appends to the release SHA256SUMS.
			name: "leading ./ (sha256sum ./*.pkg)",
			sums: other + "  ./synapseids_0.2.0_linux_amd64.tar.gz\n" + hash + "  ./" + pkgfile + "\n",
			want: hash,
		},
		{
			// What `sha256sum <name>` produces, and what a hand-made or
			// differently-generated mirror index looks like.
			name: "bare name (sha256sum <name>)",
			sums: other + "  synapseids_0.2.0_linux_amd64.tar.gz\n" + hash + "  " + pkgfile + "\n",
			want: hash,
		},
		{
			name: "binary mode asterisk",
			sums: hash + " *" + pkgfile + "\n",
			want: hash,
		},
		{
			name: "single space separator (FreeBSD sha256 -r style)",
			sums: hash + " " + pkgfile + "\n",
			want: hash,
		},
		{
			name: "entry absent",
			sums: other + "  ./some-other-file.pkg\n",
			want: "",
		},
		{
			// A dot in the version must not act as a regex wildcard and match a
			// neighbouring build.
			name: "version dots are not wildcards",
			sums: hash + "  ./" + pkgBaseName + "-0X2.0-freebsd14-amd64.pkg\n",
			want: "",
		},
		{
			name: "arm64 entry must not satisfy an amd64 request",
			sums: hash + "  ./" + pkgBaseName + "-0.2.0-freebsd14-arm64.pkg\n",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sumsPath := filepath.Join(dir, "SHA256SUMS")
			if err := os.WriteFile(sumsPath, []byte(tc.sums), 0o600); err != nil {
				t.Fatal(err)
			}
			script := `
set -u
TMP="` + dir + `"
PKGFILE="` + pkgfile + `"
` + reLine[1] + `
` + wantLine[1] + `
printf '%s' "$want"
`
			got, err := runSh(t, script)
			if err != nil {
				t.Fatalf("parser fragment failed: %v\n%s", err, got)
			}
			if got != tc.want {
				t.Errorf("want=%q, expected %q\nSHA256SUMS:\n%s", got, tc.want, tc.sums)
			}
		})
	}
}

// The rendered file list the package installs must include every configd
// template in the source tree, or `template reload` silently does not produce
// the file the flags reference. package-opnsense.sh fails the build on drift,
// but that only runs on `make opnsense-pkg`; this runs in `make test`.
func TestOPNsensePkgPlistCoversTemplates(t *testing.T) {
	const (
		templateDir = "../../contrib/opnsense/src/opnsense/service/templates/OPNsense/SynapseIDSSensor"
		plistPath   = "../../contrib/opnsense/pkg-plist"
	)
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		t.Fatalf("read %s: %v", templateDir, err)
	}
	plist := readScript(t, plistPath)

	var seen int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seen++
		want := "opnsense/service/templates/OPNsense/SynapseIDSSensor/" + e.Name()
		if !strings.Contains(plist, want) {
			t.Errorf("pkg-plist is missing %s", want)
		}
	}
	// +TARGETS, sensor.conf, sensor.token and the three PEM targets.
	if seen < 6 {
		t.Errorf("found only %d template files; expected at least 6 (+TARGETS, sensor.conf, sensor.token, 3 PEMs)", seen)
	}

	// Everything +TARGETS maps must exist on disk, or configd logs an error and
	// the destination file is never written.
	targets := readScript(t, filepath.Join(templateDir, "+TARGETS"))
	for _, line := range strings.Split(targets, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		src, dst, ok := strings.Cut(line, ":")
		if !ok {
			t.Errorf("+TARGETS line is not src:dst: %q", line)
			continue
		}
		if _, err := os.Stat(filepath.Join(templateDir, src)); err != nil {
			t.Errorf("+TARGETS maps %q but that template does not exist: %v", src, err)
		}
		if !strings.HasPrefix(dst, "/usr/local/etc/synapseids/") {
			t.Errorf("+TARGETS destination %q is outside /usr/local/etc/synapseids/", dst)
		}
	}
}

// The rc.d script and the doctor subcommand must agree on the paths and on the
// shell variable names the template renders, since the template is the only
// thing that writes them and neither can be run here.
func TestRCScriptAndDoctorAgreeOnPaths(t *testing.T) {
	const rcPath = "../../contrib/opnsense/src/etc/rc.d/synapseids_sensor"
	rc := readScript(t, rcPath)

	// Every variable the doctor reads out of sensor.conf must be defaulted in
	// the rc.d script too, or an old rendered file breaks the start.
	for _, v := range []string{
		"synapseids_sensor_enable",
		"synapseids_sensor_iface",
		"synapseids_sensor_iface_id",
		"synapseids_sensor_iface_src",
		"synapseids_sensor_iface_error",
		"synapseids_sensor_args",
	} {
		if !strings.Contains(rc, v) {
			t.Errorf("rc.d script does not mention %s, which sensor.conf renders", v)
		}
	}

	for _, pem := range []string{"sensor-ca.pem", "sensor-cert.pem", "sensor-key.pem"} {
		if !strings.Contains(rc, pem) {
			t.Errorf("rc.d script does not reference %s", pem)
		}
	}
	// The old name must be gone everywhere, or rc.d would clamp and check a file
	// configd never writes.
	if strings.Contains(rc, "peer-ca.pem") {
		t.Error("rc.d script still references the old peer-ca.pem path")
	}

	// The selftest verb is the documented entry point.
	if !strings.Contains(rc, "extra_commands=\"selftest\"") {
		t.Error("rc.d script does not declare the selftest verb")
	}
	if !strings.Contains(rc, "doctor") {
		t.Error("rc.d selftest verb does not invoke `synapse-sensor doctor`")
	}

	// selftest must be dispatched BEFORE run_rc_command, because rc.subr gates
	// verbs behind the rcvar and a disabled sensor is exactly when the selftest
	// is needed. If run_rc_command came first, the most useful command on the box
	// would print nothing in the case it exists for.
	dispatch := strings.Index(rc, "selftest | oneselftest)")
	runRC := strings.LastIndex(rc, "run_rc_command")
	switch {
	case dispatch < 0:
		t.Error("rc.d does not dispatch selftest ahead of run_rc_command")
	case runRC < 0:
		t.Error("rc.d never calls run_rc_command")
	case dispatch > runRC:
		t.Error("rc.d dispatches selftest after run_rc_command, so rc.subr's rcvar gate applies")
	}

	// The BPF check must be able to fail the start: a sensor that cannot read
	// /dev/bpf* captures nothing.
	if !strings.Contains(rc, "synapseids_sensor_check_iface") {
		t.Error("rc.d does not check that the resolved capture device exists")
	}
	if !strings.Contains(rc, "ifconfig") {
		t.Error("rc.d does not verify the capture device with ifconfig")
	}
}

func TestOPNsenseScriptsAreShellCheckable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX sh")
	}
	// shellcheck is not available in this environment; `sh -n` is the syntax
	// check that is.
	for _, p := range []string{installSh, "../../contrib/opnsense/tools/check-plugin.sh"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out, err := runSh(t, "sh -n "+p)
		if err != nil {
			t.Errorf("sh -n %s failed: %v\n%s", p, err, out)
		}
	}
}

// ---------------------------------------------------------------- post-install

// The post-install script must be able to create the service account on a stock
// FreeBSD system. It once ran `pw useradd -G net`, and because FreeBSD base
// ships the group as "network" (gid 69) and not "net", that command failed --
// which under the script's `set -e` aborted everything after it. The observed
// result on a real OPNsense 25.1 gateway was a created group, NO ACCOUNT, no log
// directory, and an unregistered plugin: the sensor could not start at all and
// the reason was several steps removed from the symptom.
//
// These assertions pin the shape of the fix rather than the wording.
func TestPostInstallCreatesAccountIndependentlyOfTheBPFGroup(t *testing.T) {
	pkg := readScript(t, packageSh)

	useradd := regexp.MustCompile(`(?s)pw useradd _synapseids(.*?)\n`).FindStringSubmatch(pkg)
	if useradd == nil {
		t.Fatal("package-opnsense.sh: no `pw useradd _synapseids` found in the post-install script")
	}
	// The account creation must not depend on any supplementary group existing.
	if strings.Contains(useradd[1], "-G ") {
		t.Errorf("pw useradd still passes a supplementary group (-G): %q\n"+
			"a missing group must not be able to fail account creation", useradd[1])
	}

	// The bpf group has to be discovered, and both candidate names considered.
	for _, want := range []string{"pw groupshow", "network", "net"} {
		if !strings.Contains(pkg, want) {
			t.Errorf("post-install does not mention %q — the bpf group must be detected, not assumed", want)
		}
	}

	// Adding the account to the bpf group must be best-effort.
	groupmod := regexp.MustCompile(`pw groupmod "?\$?\{?bpf_group\}?"? -m _synapseids[^\n]*`).FindString(pkg)
	if groupmod == "" {
		t.Fatal("post-install does not add _synapseids to the detected bpf group")
	}
	if !strings.Contains(groupmod, "|| true") {
		t.Errorf("group membership is not best-effort: %q", groupmod)
	}
}

// A repository-dependent remedy is useless on the box that needs it: a stale pkg
// database is itself a common reason the install went wrong ("Repository OPNsense
// has a wrong packagesite"), and the plugin is normally installed from a local
// file with `pkg add`. No selftest remedy may route through `pkg install`.
func TestRemediesDoNotRequireAPackageRepository(t *testing.T) {
	for _, path := range []string{"doctor.go", "../../contrib/opnsense/src/etc/rc.d/synapseids_sensor"} {
		// Only what the tool actually prints counts. Commentary is allowed to
		// name the rejected command in order to explain why it is rejected.
		for i, line := range strings.Split(readScript(t, path), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "pkg install") {
				t.Errorf("%s:%d suggests `pkg install`, which needs a working repository; "+
					"use `pkg add -f <file>` or direct pw(8) commands instead\n\t%s",
					path, i+1, trimmed)
			}
		}
	}
}

// ---------------------------------------------------------------- configd actions

const actionsConf = "../../contrib/opnsense/src/opnsense/service/conf/actions.d/actions_synapseidssensor.conf"

// Saving the settings page with the sensor disabled runs the [stop] action.
// rc.subr's default stop warns "not running? (check <pidfile>)" and returns 1 on
// an already-stopped service, and configd renders a non-zero exit from a
// type:script action as the GUI's "Unexpected error, check log for details" --
// so on a real gateway EVERY save failed, while the configuration had in fact
// been written and the template rendered. Stopping a stopped service is a no-op,
// not a failure; both lifecycle actions must tolerate it.
func TestStopAndRestartActionsToleratePreStoppedService(t *testing.T) {
	conf := readScript(t, actionsConf)

	for _, action := range []string{"stop", "restart"} {
		cmd := configdActionCommand(t, conf, action)
		if !strings.Contains(cmd, "onestatus") {
			t.Errorf("[%s] command does not check onestatus first, so it fails on an "+
				"already-stopped sensor:\n\t%s", action, cmd)
		}
	}

	// configd applies parameter substitution to command:, so a stray % would be
	// eaten. Assert it for every action, not just the two edited here.
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "command:") && strings.Contains(line, "%") {
			t.Errorf("action command contains %%, which configd will substitute:\n\t%s", line)
		}
	}
}

// configdActionCommand returns the command: line of the named [action] block.
func configdActionCommand(t *testing.T, conf, action string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^\[` + regexp.QuoteMeta(action) + `\]\s*$(.*?)(?:^\[|\z)`)
	m := re.FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("no [%s] action block found in %s", action, actionsConf)
	}
	for _, line := range strings.Split(m[1], "\n") {
		if strings.HasPrefix(line, "command:") {
			return strings.TrimPrefix(line, "command:")
		}
	}
	t.Fatalf("[%s] has no command: line", action)
	return ""
}

// setModelNodes() does not exist on OPNsense's ApiMutableModelControllerBase.
// Calling it made every POST to settings/set fail with "Call to undefined
// method" -> HTTP 500 -> the GUI's generic "Unexpected error", while GET kept
// working because getModelNodes() IS real. The settings page therefore looked
// entirely healthy and Save silently never wrote config.xml -- found only on a
// live gateway, after the plugin had passed every local check.
//
// This guard is deliberately crude: there is no way to resolve OPNsense core's
// class hierarchy from this repo, so it pins the one name that burned us.
func TestControllersDoNotCallNonexistentBaseMethods(t *testing.T) {
	const controllers = "../../contrib/opnsense/src/opnsense/mvc/app/controllers/OPNsense/SynapseIDSSensor"
	banned := map[string]string{
		"setModelNodes": "does not exist on ApiMutableModelControllerBase; " +
			"use $this->getModel()->setNodes(...) followed by $this->save()",
	}
	err := filepath.WalkDir(controllers, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".php") {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			// Comments may name the method in order to explain the trap.
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
				strings.HasPrefix(trimmed, "/*") {
				continue
			}
			for name, why := range banned {
				if strings.Contains(trimmed, name+"(") {
					t.Errorf("%s:%d calls %s(), which %s\n\t%s",
						filepath.Base(path), i+1, name, why, trimmed)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", controllers, err)
	}
}
