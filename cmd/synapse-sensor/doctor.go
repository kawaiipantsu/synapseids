package main

// doctor is the on-box selftest for a deployed sensor — in practice the
// OPNsense plugin, where `service synapseids_sensor selftest` and
// `configctl synapseidssensor selftest` both land here (issue #102).
//
// The point is to turn a remote debugging session into one command. Every check
// prints one line, in a fixed order, with the remedy inlined on failure. The
// checks deliberately overlap the invariants the rc.d script enforces at start
// (token mode, PEM presence, BPF access) so an operator can see *why* a start
// was refused without reading a log, and they add the two things rc.d cannot
// answer — does the resolved capture device actually exist, and does the far end
// answer a TCP connect.
//
// Everything here is read-only: doctor never writes, chowns or chmods anything.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

// Default on-box locations, matching contrib/opnsense (+TARGETS, the rc.d
// script and actions_synapseidssensor.conf). They are struct fields rather than
// constants so the tests can point the whole selftest at a temporary tree.
const (
	defaultEtcDir      = "/usr/local/etc/synapseids"
	defaultLogDir      = "/var/log/synapseids"
	defaultServiceUser = "_synapseids"
)

// checkStatus is the verdict of one selftest line.
type checkStatus int

const (
	statusPass checkStatus = iota
	statusWarn
	statusFail
	statusSkip
)

// label is the fixed-width prefix each result line starts with, so the output
// can be grepped (`selftest | grep FAIL`) and read down a column.
func (s checkStatus) label() string {
	switch s {
	case statusPass:
		return "[ OK ]"
	case statusWarn:
		return "[WARN]"
	case statusFail:
		return "[FAIL]"
	default:
		return "[SKIP]"
	}
}

// checkResult is one line of output plus, when something is wrong, the exact
// commands that fix it.
type checkResult struct {
	name   string
	status checkStatus
	detail string
	remedy []string
}

func pass(name, format string, a ...any) checkResult {
	return checkResult{name: name, status: statusPass, detail: fmt.Sprintf(format, a...)}
}

func skip(name, format string, a ...any) checkResult {
	return checkResult{name: name, status: statusSkip, detail: fmt.Sprintf(format, a...)}
}

func warn(name, detail string, remedy ...string) checkResult {
	return checkResult{name: name, status: statusWarn, detail: detail, remedy: remedy}
}

func fail(name, detail string, remedy ...string) checkResult {
	return checkResult{name: name, status: statusFail, detail: detail, remedy: remedy}
}

// doctorEnv is everything the selftest touches. Defaulted from the constants
// above by runDoctor; overridden wholesale by the tests.
type doctorEnv struct {
	confPath  string
	etcDir    string
	logDir    string
	user      string
	bpfDevs   []string
	timeout   time.Duration
	skipDial  bool
	buildInfo string
	goos      string
}

func (e doctorEnv) etc(name string) string { return filepath.Join(e.etcDir, name) }

// runDoctor is the `synapse-sensor doctor` entry point.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("synapse-sensor doctor", flag.ContinueOnError)
	conf := fs.String("config", filepath.Join(defaultEtcDir, "sensor.conf"),
		"rendered sensor configuration to check (the configd template output)")
	svcUser := fs.String("user", defaultServiceUser, "unprivileged user the sensor runs as")
	etcDir := fs.String("etc-dir", defaultEtcDir, "directory holding sensor.token and the PEM material")
	logDir := fs.String("log-dir", defaultLogDir, "directory the sensor log is written to")
	timeout := fs.Duration("timeout", 5*time.Second, "per-check network timeout")
	skipDial := fs.Bool("skip-dial", false, "do not attempt the TCP reachability check")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Check a deployed SynapseIDS sensor: binary, privileges, capture device,")
		fmt.Fprintln(os.Stderr, "rendered configuration, secrets, TLS material and collector reachability.")
		fmt.Fprintln(os.Stderr, "\nOne line per check; exit status 1 if any check failed.")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  synapse-sensor doctor")
		fmt.Fprintln(os.Stderr, "  service synapseids_sensor selftest        # on OPNsense")
		fmt.Fprintln(os.Stderr, "  configctl synapseidssensor selftest       # same, through configd")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	env := doctorEnv{
		confPath:  *conf,
		etcDir:    *etcDir,
		logDir:    *logDir,
		user:      *svcUser,
		bpfDevs:   []string{"/dev/bpf", "/dev/bpf0"},
		timeout:   *timeout,
		skipDial:  *skipDial,
		buildInfo: version.String("synapse-sensor"),
		goos:      runtime.GOOS,
	}
	return reportDoctor(os.Stdout, runChecks(env))
}

// reportDoctor prints the result lines and the one-line summary, and returns the
// process exit status: 0 when nothing failed, 1 otherwise. A WARN never fails
// the run — it flags something an operator should look at, not something that
// stops the sensor working.
func reportDoctor(w io.Writer, results []checkResult) int {
	var passed, warned, failed, skipped int
	for _, r := range results {
		fmt.Fprintf(w, "%s %-13s %s\n", r.status.label(), r.name, r.detail)
		for _, line := range r.remedy {
			fmt.Fprintf(w, "       %s\n", line)
		}
		switch r.status {
		case statusPass:
			passed++
		case statusWarn:
			warned++
		case statusFail:
			failed++
		case statusSkip:
			skipped++
		}
	}
	fmt.Fprintf(w, "\nsummary: %d checks, %d passed, %d warned, %d failed, %d skipped\n",
		len(results), passed, warned, failed, skipped)
	if failed > 0 {
		fmt.Fprintln(w, "selftest: FAILED — the sensor will not capture until the [FAIL] lines above are fixed")
		return 1
	}
	fmt.Fprintln(w, "selftest: PASSED")
	return 0
}

// runChecks executes every check in a fixed order.
//
// `config` runs second rather than in the order issue #102 lists it, because
// every check after it — the capture device, the token path, the PEM paths, the
// collector address — is read out of the rendered configuration.
func runChecks(env doctorEnv) []checkResult {
	results := []checkResult{checkBinary(env)}

	conf, confResult := checkConfig(env)
	results = append(results, confResult)
	results = append(results,
		checkServiceUser(env),
		checkBPFAccess(env),
		checkInterface(conf),
		checkTokenFile(env, conf),
	)
	results = append(results, checkTLSMaterial(env, conf)...)
	results = append(results, checkLogSink(env), checkCollector(env, conf))
	return results
}

// ---------------------------------------------------------------- binary

// checkBinary reports the build stamp. It cannot really fail: the fact that this
// code is executing *is* the check that the cross-compiled binary runs on this
// kernel, which on FreeBSD/arm64 is not a given.
func checkBinary(env doctorEnv) checkResult {
	return pass("binary", "%s %s/%s", strings.TrimSpace(env.buildInfo), env.goos, runtime.GOARCH)
}

// ---------------------------------------------------------------- config

// checkConfig parses the configd-rendered sensor.conf.
func checkConfig(env doctorEnv) (sensorConf, checkResult) {
	raw, err := os.ReadFile(env.confPath)
	if err != nil {
		return sensorConf{}, fail("config", fmt.Sprintf("%s: %v", env.confPath, err),
			"the configd template has never been rendered. In the web UI press Save on",
			"Services > SynapseIDS Sensor, or run:",
			"    configctl template reload OPNsense/SynapseIDSSensor && configctl synapseidssensor fixperms")
	}
	conf, err := parseSensorConf(strings.NewReader(string(raw)))
	if err != nil {
		return conf, fail("config", fmt.Sprintf("%s: %v", env.confPath, err),
			"this file is sourced by /usr/local/etc/rc.d/synapseids_sensor as root.",
			"Re-render it rather than editing it by hand:",
			"    configctl template reload OPNsense/SynapseIDSSensor")
	}

	args := conf.args()
	detail := fmt.Sprintf("%s: enable=%s, %d flags, transport=%s",
		env.confPath, conf.enabledWord(), len(args), conf.transport())
	if !conf.enabled() {
		return conf, warn("config", detail,
			"the sensor is configured but not enabled, so it will not be started at boot.",
			"Tick Enable on Services > SynapseIDS Sensor.")
	}
	if f := flagValue(args, "--filter"); f != "" && !capture.FilterKnown(f) {
		return conf, fail("config", detail,
			fmt.Sprintf("--filter %q is not a built-in preset. Valid: %s",
				f, strings.Join(capture.BuiltinFilters(), ", ")))
	}
	if !hasFlag(args, "--authorized") {
		return conf, fail("config", detail,
			"--authorized is absent, and synapse-sensor refuses to capture live traffic",
			"without it (PROJECT.md §28.18). Tick the authorisation checkbox and save.")
	}
	return conf, pass("config", "%s", detail)
}

// ---------------------------------------------------------------- privileges

// checkServiceUser confirms the unprivileged account the package's post-install
// creates is actually there. If pkg(8) skipped the script, everything else fails
// in a confusing way and this is the reason.
func checkServiceUser(env doctorEnv) checkResult {
	u, err := user.Lookup(env.user)
	if err != nil {
		// Do NOT suggest `pkg install -f`: that resolves through the configured
		// repository, which is exactly what is broken on a box whose pkg
		// database is stale, and the plugin is normally installed from a local
		// file anyway. Give commands that need no repository at all.
		return fail("service-user", fmt.Sprintf("%s: %v", env.user, err),
			"the package's post-install script did not finish. Create the account",
			"directly -- no repository needed:",
			"    pw groupadd "+env.user,
			"    pw useradd "+env.user+" -g "+env.user+" -d /nonexistent -s /usr/sbin/nologin",
			"    pw groupmod "+bpfGroupName()+" -m "+env.user,
			"then re-render the configuration:",
			"    configctl template reload OPNsense/SynapseIDSSensor && configctl synapseidssensor fixperms")
	}
	groups := groupNames(u)
	detail := fmt.Sprintf("%s uid=%s gid=%s groups=%s", u.Username, u.Uid, u.Gid, strings.Join(groups, ","))
	if bpf := bpfGroupName(); !contains(groups, bpf) {
		return warn("service-user", detail,
			"not a member of group "+bpf+", which is the group the documented devfs",
			"rule grants /dev/bpf* to. Fix with:  pw groupmod "+bpf+" -m "+env.user)
	}
	return pass("service-user", "%s", detail)
}

// checkBPFAccess inspects a BPF device the way the kernel would: owner, group
// and mode against the service user's identity. There is no portable way to
// attempt an open "as another user" from here, and doctor deliberately does not
// try to become root.
func checkBPFAccess(env doctorEnv) checkResult {
	if env.goos != "freebsd" {
		return skip("bpf-access", "/dev/bpf* is a FreeBSD interface; this build is %s", env.goos)
	}
	dev := ""
	for _, cand := range env.bpfDevs {
		if _, err := os.Stat(cand); err == nil {
			dev = cand
			break
		}
	}
	if dev == "" {
		return fail("bpf-access", fmt.Sprintf("none of %s exists", strings.Join(env.bpfDevs, ", ")),
			"the bpf(4) device is missing entirely. Confirm the kernel has BPF:",
			"    kldstat -m bpf || sysctl net.bpf")
	}

	owner, group, mode, err := ownerGroupMode(dev)
	if err != nil {
		return warn("bpf-access", fmt.Sprintf("%s: %v", dev, err))
	}
	detail := fmt.Sprintf("%s mode %04o %s:%s", dev, mode, owner, group)

	u, err := user.Lookup(env.user)
	if err != nil {
		return warn("bpf-access", detail+fmt.Sprintf(" (cannot resolve %s: %v)", env.user, err))
	}
	switch {
	case owner == env.user && mode&0o400 != 0:
		return pass("bpf-access", "%s — readable by the owner %s", detail, env.user)
	case mode&0o040 != 0 && contains(groupNames(u), group):
		return pass("bpf-access", "%s — readable by group %s, which %s is in", detail, group, env.user)
	case mode&0o004 != 0:
		return warn("bpf-access", detail+" — world readable, which is broader than necessary",
			"the documented rule is  mode 0640 group "+bpfGroupName()+".")
	}
	return fail("bpf-access", detail+fmt.Sprintf(" — %s cannot read it, so the sensor will capture nothing", env.user),
		"grant it with the devfs rule the plugin documents:",
		"    printf \"[synapseids_bpf=10]\\nadd path 'bpf*' mode 0640 group "+bpfGroupName()+"\\n\" >> /etc/devfs.rules",
		"    sysrc devfs_system_ruleset=synapseids_bpf && service devfs restart",
		"or re-run the installer with --grant-bpf.")
}

// ---------------------------------------------------------------- interface

// checkInterface is the check that matters most (issue #102): the model stores
// an OPNsense interface *identifier* ("wan"), the sensor needs a kernel device
// name ("em0"), and a sensor bound to a device that does not exist reports
// "running" while capturing zero packets. So the resolution is reported in full
// — identifier, resolved device, and how the template resolved it — and a device
// that is not present is a hard failure with the available devices listed.
func checkInterface(conf sensorConf) checkResult {
	if lookupErr := conf.get("synapseids_sensor_iface_error"); lookupErr != "" {
		return fail("interface", "the configd template could not resolve the interface: "+lookupErr,
			"the sensor is deliberately not started in this state rather than binding to",
			"nothing. Re-select the interface on Services > SynapseIDS Sensor and save.")
	}

	dev := conf.get("synapseids_sensor_iface")
	if dev == "" {
		dev = flagValue(conf.args(), "--iface")
	}
	ident := conf.get("synapseids_sensor_iface_id")
	via := conf.get("synapseids_sensor_iface_src")

	if dev == "" {
		if !conf.enabled() {
			return skip("interface", "no capture interface configured (sensor is disabled)")
		}
		return fail("interface", "no capture interface in the rendered configuration",
			"pick the interface to capture from on Services > SynapseIDS Sensor.")
	}

	resolution := dev
	if ident != "" && ident != dev {
		resolution = fmt.Sprintf("%s -> %s", ident, dev)
	}
	if via != "" {
		resolution += " (via " + via + ")"
	}

	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return fail("interface", fmt.Sprintf("%s — device %q does not exist on this host", resolution, dev),
			"a sensor bound to a missing device captures nothing, so it is refused.",
			"Devices present: "+strings.Join(interfaceNames(), ", "),
			"If the identifier resolved to the wrong name, check  ifconfig -l  and the",
			"Interfaces > Assignments page, then re-save the sensor settings.")
	}
	detail := fmt.Sprintf("%s — exists, flags %s", resolution, iface.Flags.String())
	if iface.Flags&net.FlagUp == 0 {
		return warn("interface", detail,
			"the device is down; BPF will attach but see no traffic until it comes up.")
	}
	return pass("interface", "%s", detail)
}

// ---------------------------------------------------------------- secrets

// checkTokenFile verifies the bearer token file the rc.d script passes as
// --token-file: present, non-empty, 0400, owned by the service user. Its
// *contents* are never read, printed or hashed here (PROJECT.md §21).
func checkTokenFile(env doctorEnv, conf sensorConf) checkResult {
	path := flagValue(conf.args(), "--token-file")
	if path == "" {
		path = env.etc("sensor.token")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fail("token-file", fmt.Sprintf("%s: %v", path, err),
			"render it from the token stored in the OPNsense configuration:",
			"    configctl template reload OPNsense/SynapseIDSSensor",
			"    configctl synapseidssensor fixperms")
	}
	owner, group, mode, err := ownerGroupMode(path)
	if err != nil {
		return warn("token-file", fmt.Sprintf("%s: %v", path, err))
	}
	detail := fmt.Sprintf("%s mode %04o %s:%s, %d bytes", path, mode, owner, group, fi.Size())

	if fi.Size() == 0 {
		return fail("token-file", detail+" — empty, so the sensor would accept any peer that completes the handshake",
			"enter the bearer token on Services > SynapseIDS Sensor and save.")
	}
	if mode&0o077 != 0 {
		return fail("token-file", detail+" — readable by more than the owner",
			"the token must be 0400. Close the window configd's umask opens:",
			"    configctl synapseidssensor fixperms")
	}
	if owner != env.user {
		return fail("token-file", detail+fmt.Sprintf(" — owned by %s, not %s, so the sensor cannot read it", owner, env.user),
			"    configctl synapseidssensor fixperms")
	}
	return pass("token-file", "%s", detail)
}

// ---------------------------------------------------------------- TLS

// checkTLSMaterial parses whatever PEM the rendered flags reference. Since #104
// these files are produced by configd templates rather than placed by hand, so a
// parse failure here means the config store holds something that is not PEM —
// which Sensor::performValidation should have refused at save time.
//
// It returns one line for the key pair and one for the trust bundle, so an
// operator can see which half is wrong.
func checkTLSMaterial(env doctorEnv, conf sensorConf) []checkResult {
	args := conf.args()
	certPath := flagValue(args, "--cert")
	keyPath := flagValue(args, "--key")
	caPath := flagValue(args, "--ca")
	if caPath == "" {
		caPath = flagValue(args, "--client-ca")
	}

	var out []checkResult

	switch {
	case certPath == "" && keyPath == "":
		out = append(out, skip("tls-identity", "no --cert/--key configured (no certificate is presented)"))
	case certPath == "" || keyPath == "":
		out = append(out, fail("tls-identity", "half a key pair: --cert and --key must both be set",
			"enter both the certificate and its private key, or neither."))
	default:
		out = append(out, checkKeyPair(env, certPath, keyPath))
	}

	if caPath == "" {
		if hasFlag(args, "--insecure-tls") {
			out = append(out, warn("tls-trust", "--insecure-tls: the collector's certificate is NOT verified",
				"the stream is encrypted but open to interception. Paste the collector CA",
				"under Verify peer / CA and untick 'do not verify' as soon as you can."))
		} else if conf.transport() == "connect" {
			out = append(out, warn("tls-trust", "no --ca: the collector is verified against the system root store",
				"a private collector certificate will be rejected. Paste its CA on the settings page."))
		} else {
			out = append(out, skip("tls-trust", "no --client-ca: any peer completing the handshake is accepted (bearer token only)"))
		}
		return out
	}
	out = append(out, checkCABundle(caPath))
	return out
}

func checkKeyPair(env doctorEnv, certPath, keyPath string) checkResult {
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			return fail("tls-identity", fmt.Sprintf("%s: %v", p, err),
				"the configd template renders this file from the OPNsense configuration:",
				"    configctl template reload OPNsense/SynapseIDSSensor",
				"    configctl synapseidssensor fixperms",
				"A missing PEM is a hard start failure by design — the sensor never falls",
				"back to an unverified transport.")
		}
	}

	// The private key must not be readable by anyone but the service user. This
	// is the property the fixperms action and the rc.d start_precmd enforce; the
	// selftest is where an operator can see that it actually holds.
	owner, group, mode, err := ownerGroupMode(keyPath)
	if err == nil {
		if mode&0o077 != 0 {
			return fail("tls-identity", fmt.Sprintf("%s mode %04o %s:%s — the private key is readable by more than its owner",
				keyPath, mode, owner, group),
				"    configctl synapseidssensor fixperms")
		}
		if owner != env.user {
			return fail("tls-identity", fmt.Sprintf("%s is owned by %s, not %s, so the sensor cannot read its own key",
				keyPath, owner, env.user),
				"    configctl synapseidssensor fixperms")
		}
	}

	// X509KeyPair parses both halves and proves they belong together, which is
	// the mistake a copy-paste into two textareas actually makes.
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fail("tls-identity", fmt.Sprintf("%s + %s: %v", certPath, keyPath, err),
			"the certificate and key do not parse, or do not match each other.",
			"Re-paste both on Services > SynapseIDS Sensor; the model rejects a blob",
			"that is not PEM, an encrypted key, and a pair that does not match.")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fail("tls-identity", fmt.Sprintf("%s: %v", certPath, err))
	}
	detail := fmt.Sprintf("%s + %s: pair matches, subject %q, expires %s",
		filepath.Base(certPath), filepath.Base(keyPath),
		leaf.Subject.String(), leaf.NotAfter.UTC().Format(time.RFC3339))
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fail("tls-identity", detail+" — EXPIRED", "issue a new certificate; the handshake will be rejected.")
	}
	if now.Before(leaf.NotBefore) {
		return fail("tls-identity", detail+fmt.Sprintf(" — not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339)),
			"check the firewall's clock:  date; service ntpd status")
	}
	if now.Add(14 * 24 * time.Hour).After(leaf.NotAfter) {
		return warn("tls-identity", detail+" — expires within 14 days")
	}
	return pass("tls-identity", "%s", detail)
}

func checkCABundle(path string) checkResult {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail("tls-trust", fmt.Sprintf("%s: %v", path, err),
			"the configd template renders this from the CA field:",
			"    configctl template reload OPNsense/SynapseIDSSensor")
	}
	if len(raw) == 0 {
		return fail("tls-trust", path+" is empty, so no peer certificate can ever verify",
			"paste the peer CA bundle on Services > SynapseIDS Sensor and save.")
	}

	var subjects []string
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fail("tls-trust", fmt.Sprintf("%s contains a %q block, which is not a certificate", path, block.Type),
				"this field takes a CA certificate bundle. A private key here would be a",
				"serious mistake — check you pasted into the right box.")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fail("tls-trust", fmt.Sprintf("%s: certificate %d does not parse: %v", path, len(subjects)+1, err))
		}
		// A CA generated by `synapse-sensor gen-cert` has no CN, only an O, so
		// fall back to the whole subject rather than printing an empty name.
		name := c.Subject.CommonName
		if name == "" {
			name = c.Subject.String()
		}
		subjects = append(subjects, name)
	}
	if len(subjects) == 0 {
		return fail("tls-trust", path+" holds no PEM certificate block",
			"expected \"-----BEGIN CERTIFICATE-----\" ... blocks.")
	}
	return pass("tls-trust", "%s: %d certificate(s), subject %s",
		filepath.Base(path), len(subjects), strings.Join(subjects, "; "))
}

// ---------------------------------------------------------------- log sink

// checkLogSink exists because one assumption in the rc.d script could not be
// settled without a FreeBSD box: whether daemon(8)'s `-f` suppresses the `-S -T`
// syslog capture. The script now also passes `-o <logdir>/sensor.log`, so there
// are two independent sinks — and this check is how an operator finds out
// whether either of them is actually producing output.
func checkLogSink(env doctorEnv) checkResult {
	path := filepath.Join(env.logDir, "sensor.log")
	di, err := os.Stat(env.logDir)
	if err != nil {
		return fail("log-sink", fmt.Sprintf("%s: %v", env.logDir, err),
			"    configctl synapseidssensor fixperms")
	}
	if !di.IsDir() {
		return fail("log-sink", env.logDir+" is not a directory")
	}
	owner, group, mode, err := ownerGroupMode(env.logDir)
	if err != nil {
		return warn("log-sink", fmt.Sprintf("%s: %v", env.logDir, err))
	}
	dirDetail := fmt.Sprintf("%s mode %04o %s:%s", env.logDir, mode, owner, group)

	fi, err := os.Stat(path)
	if err != nil {
		return warn("log-sink", dirDetail+fmt.Sprintf("; %s does not exist yet", filepath.Base(path)),
			"normal before the first start. If it stays absent while the service runs,",
			"daemon(8)'s -f is suppressing output: drop -f from command_args in",
			"/usr/local/etc/rc.d/synapseids_sensor, or point syslogd at this path.")
	}
	detail := fmt.Sprintf("%s; %s %d bytes, modified %s",
		dirDetail, filepath.Base(path), fi.Size(), fi.ModTime().UTC().Format(time.RFC3339))
	if fi.Size() == 0 {
		return warn("log-sink", detail+" — empty",
			"if the sensor is running and this stays empty, its output is going nowhere:",
			"drop -f from command_args in /usr/local/etc/rc.d/synapseids_sensor.")
	}
	return pass("log-sink", "%s", detail)
}

// ---------------------------------------------------------------- collector

// checkCollector is a TCP connect and nothing more: no TLS handshake, no token,
// no SYNPOIP frame. It answers the one question a firewall operator cannot
// answer from the box — is there a path to the daemon at all — without
// presenting credentials to whatever is on the other end.
func checkCollector(env doctorEnv, conf sensorConf) checkResult {
	args := conf.args()
	if addr := flagValue(args, "--connect"); addr != "" {
		if env.skipDial {
			return skip("collector", "--skip-dial: not connecting to %s", addr)
		}
		start := time.Now()
		c, err := net.DialTimeout("tcp", addr, env.timeout)
		if err != nil {
			return fail("collector", fmt.Sprintf("%s: %v", addr, err),
				"the sensor dials the daemon in connect mode, so this must succeed.",
				"Check that synapsed has a capture.collector block listening, that the",
				"firewall permits the outbound connection, and that the address is right.")
		}
		_ = c.Close()
		return pass("collector", "%s: TCP connect succeeded in %s (no TLS handshake attempted)",
			addr, time.Since(start).Round(time.Millisecond))
	}

	addr := flagValue(args, "--listen")
	if addr == "" {
		return skip("collector", "neither --connect nor --listen is configured")
	}
	// listen mode: the daemon dials us. "Reachable" therefore means the socket is
	// bindable, or already bound by the running sensor.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if isAddrInUse(err) {
			return pass("collector", "%s: already bound — the sensor is listening and the daemon must dial in", addr)
		}
		return fail("collector", fmt.Sprintf("cannot bind %s: %v", addr, err),
			"in listen mode the daemon dials the firewall. Fix the listen address on",
			"Services > SynapseIDS Sensor, and remember a WAN-side firewall rule is",
			"needed for the daemon to reach it (or switch to connect mode, which is the",
			"better posture behind NAT).")
	}
	_ = ln.Close()
	return warn("collector", fmt.Sprintf("%s: bindable but nothing is listening — the sensor is not running", addr),
		"start it:  service synapseids_sensor start   (or from the web UI)")
}

func isAddrInUse(err error) bool {
	// Matched on the message rather than syscall.EADDRINUSE so this file needs no
	// per-platform errno import; the string is stable across Unix.
	return strings.Contains(err.Error(), "address already in use")
}

// ---------------------------------------------------------------- helpers

func interfaceNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"(cannot enumerate: " + err.Error() + ")"}
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	sort.Strings(names)
	return names
}

func groupNames(u *user.User) []string {
	ids, err := u.GroupIds()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ids))
	for _, gid := range ids {
		if g, err := user.LookupGroupId(gid); err == nil {
			names = append(names, g.Name)
			continue
		}
		names = append(names, gid)
	}
	return names
}

// bpfGroupName returns the group a devfs rule should grant bpf* to, resolved
// against the running system rather than assumed.
//
// FreeBSD base ships "network" (gid 69). A lot of documentation says "net",
// which does not exist on a stock system -- and this package used to hardcode
// it, which made `pw useradd -G net` fail and, under the post-install script's
// `set -e`, silently cost us the whole service account. Every remedy line the
// selftest prints goes through here so a wrong guess cannot be baked into
// advice again.
func bpfGroupName() string {
	for _, name := range []string{"network", "net"} {
		if _, err := user.LookupGroup(name); err == nil {
			return name
		}
	}
	return "network" // documented default when neither resolves
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
