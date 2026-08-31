package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultIsLoopback(t *testing.T) {
	c := Default()
	if !c.LoopbackOnly() {
		t.Fatalf("default listen %q must be loopback", c.Server.Listen)
	}
}

func TestLoadFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"server":{"listen":"0.0.0.0:9000"},"capture":{"flow_idle_timeout":"15s","flow_max_lifetime":"2m","snapshot_interval":"30s","max_flows":1000},"live":{"websocket_batch":"200ms","client_queue_size":10}}`))

	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Listen != "0.0.0.0:9000" {
		t.Fatalf("listen not read from file: %q", c.Server.Listen)
	}
	if c.Capture.FlowIdleTimeout.D() != 15*time.Second {
		t.Fatalf("idle timeout: %v", c.Capture.FlowIdleTimeout.D())
	}
	if c.LoopbackOnly() {
		t.Fatalf("0.0.0.0 must not be reported as loopback")
	}

	t.Setenv("SYNAPSE_LISTEN", "127.0.0.1:7777")
	c, err = Load(p)
	if err != nil {
		t.Fatalf("Load w/ env: %v", err)
	}
	if c.Server.Listen != "127.0.0.1:7777" {
		t.Fatalf("env override ignored: %q", c.Server.Listen)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"no-colon":    `{"server":{"listen":"localhost"}}`,
		"bad-driver":  `{"storage":{"driver":"redis"}}`,
		"sqlite-todo": `{"storage":{"driver":"sqlite"}}`,
		"zero-idle":   `{"capture":{"flow_idle_timeout":"0s"}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCaptureSourcesLoadAndValidate(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, []byte(`{"capture":{"sources":[
		{"name":"wan","kind":"nic","interface":"eth0","promiscuous":true,"filter":"ip-any"},
		{"name":"lo","kind":"nic","interface":"lo"}
	]}}`))
	c, err := Load(good)
	if err != nil {
		t.Fatalf("Load good sources: %v", err)
	}
	if len(c.Capture.Sources) != 2 || c.Capture.Sources[0].Filter != "ip-any" || !c.Capture.Sources[0].Promiscuous {
		t.Fatalf("sources not parsed: %+v", c.Capture.Sources)
	}

	for name, body := range map[string]string{
		"empty-name":   `{"capture":{"sources":[{"name":"","kind":"nic","interface":"eth0"}]}}`,
		"dup-name":     `{"capture":{"sources":[{"name":"a","kind":"nic","interface":"eth0"},{"name":"a","kind":"nic","interface":"eth1"}]}}`,
		"bad-kind":     `{"capture":{"sources":[{"name":"a","kind":"tap","interface":"eth0"}]}}`,
		"no-interface": `{"capture":{"sources":[{"name":"a","kind":"nic","interface":""}]}}`,
		"bad-snaplen":  `{"capture":{"sources":[{"name":"a","kind":"nic","interface":"eth0","snaplen":9999999}]}}`,
		"unknown-filt": `{"capture":{"sources":[{"name":"a","kind":"nic","interface":"eth0","filter":"tcp port 80"}]}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCaptureSourceTcpdumpAndSSH(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, []byte(`{"capture":{"sources":[
		{"name":"span","kind":"tcpdump","interface":"eth0","filter":"tcp port 80 or udp","snaplen":65535},
		{"name":"edge","kind":"ssh","destination":"sensor@10.0.0.9","interface":"eth1","filter":"not port 22","authorized":true,"known_hosts":"accept-new","identity_file":"/keys/id"}
	]}}`))
	c, err := Load(good)
	if err != nil {
		t.Fatalf("Load good tcpdump/ssh sources: %v", err)
	}
	if c.Capture.Sources[0].Kind != "tcpdump" || c.Capture.Sources[0].Filter != "tcp port 80 or udp" {
		t.Fatalf("tcpdump source not parsed: %+v", c.Capture.Sources[0])
	}
	if s := c.Capture.Sources[1]; s.Destination != "sensor@10.0.0.9" || !s.Authorized || s.KnownHosts != "accept-new" {
		t.Fatalf("ssh source not parsed: %+v", s)
	}

	for name, body := range map[string]string{
		"tcpdump-no-interface": `{"capture":{"sources":[{"name":"a","kind":"tcpdump","filter":"ip"}]}}`,
		"ssh-no-destination":   `{"capture":{"sources":[{"name":"a","kind":"ssh","interface":"eth0","authorized":true}]}}`,
		"ssh-no-interface":     `{"capture":{"sources":[{"name":"a","kind":"ssh","destination":"h","authorized":true}]}}`,
		"ssh-not-authorized":   `{"capture":{"sources":[{"name":"a","kind":"ssh","destination":"h","interface":"eth0"}]}}`,
		"ssh-authorized-false": `{"capture":{"sources":[{"name":"a","kind":"ssh","destination":"h","interface":"eth0","authorized":false}]}}`,
		"ssh-bad-known-hosts":  `{"capture":{"sources":[{"name":"a","kind":"ssh","destination":"h","interface":"eth0","authorized":true,"known_hosts":"no"}]}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCaptureSSHAuthorizationMessage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"capture":{"sources":[{"name":"edge","kind":"ssh","destination":"sensor@host","interface":"eth0"}]}}`))
	_, err := Load(p)
	if err == nil {
		t.Fatal("unauthorized ssh source must be rejected")
	}
	for _, want := range []string{`"authorized": true`, "authorised to monitor sensor@host", "§28.18"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestValidateCaptureSourceMatchesWholeFile asserts the exported single-source
// validator and the whole-file validate() agree for representative good and bad
// entries of every kind — no rule drift between the file path and the runtime
// POST /api/v1/captures path (issue #32).
func TestValidateCaptureSourceMatchesWholeFile(t *testing.T) {
	cases := map[string]CaptureSource{
		"nic ok":              {Name: "a", Kind: "nic", Interface: "eth0", Filter: "ip-any"},
		"nic no iface":        {Name: "a", Kind: "nic"},
		"nic bad filter":      {Name: "a", Kind: "nic", Interface: "eth0", Filter: "tcp port 80"},
		"nic bad snaplen":     {Name: "a", Kind: "nic", Interface: "eth0", Snaplen: 9_999_999},
		"tcpdump ok":          {Name: "a", Kind: "tcpdump", Interface: "eth0", Filter: "tcp port 80 or udp"},
		"tcpdump no iface":    {Name: "a", Kind: "tcpdump"},
		"ssh ok":              {Name: "a", Kind: "ssh", Destination: "h", Interface: "eth0", Authorized: true, KnownHosts: "accept-new"},
		"ssh no auth":         {Name: "a", Kind: "ssh", Destination: "h", Interface: "eth0"},
		"ssh no dest":         {Name: "a", Kind: "ssh", Interface: "eth0", Authorized: true},
		"ssh bad known_hosts": {Name: "a", Kind: "ssh", Destination: "h", Interface: "eth0", Authorized: true, KnownHosts: "no"},
		"poip ok tokenfile":   {Name: "a", Kind: "pcap-over-ip", Addr: "127.0.0.1:4789", TokenFile: "/etc/x.tok"},
		"poip ok remote auth": {Name: "a", Kind: "pcap-over-ip", Addr: "sensor.hq:4789", Authorized: true, InsecureTLS: true},
		"poip no addr":        {Name: "a", Kind: "pcap-over-ip"},
		"poip inline token":   {Name: "a", Kind: "pcap-over-ip", Addr: "127.0.0.1:1", Token: "secret"},
		"poip remote no auth": {Name: "a", Kind: "pcap-over-ip", Addr: "10.0.0.5:4789", TokenFile: "t"},
		"poip half mtls":      {Name: "a", Kind: "pcap-over-ip", Addr: "127.0.0.1:1", TokenFile: "t", ClientCertFile: "c"},
		"unknown kind":        {Name: "a", Kind: "tap", Interface: "eth0"},
		"empty name":          {Kind: "nic", Interface: "eth0"},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			single := ValidateCaptureSource(s) == nil
			c := Default()
			c.Capture.Sources = []CaptureSource{s}
			whole := c.validate() == nil
			if single != whole {
				t.Fatalf("disagreement: ValidateCaptureSource ok=%t, validate() ok=%t (%+v)", single, whole, s)
			}
		})
	}
}

func TestCaptureIfaceEnvAddsSource(t *testing.T) {
	t.Setenv("SYNAPSE_CAPTURE_IFACE", "eth9")
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !hasNICInterface(c.Capture.Sources, "eth9") {
		t.Fatalf("SYNAPSE_CAPTURE_IFACE did not add a source: %+v", c.Capture.Sources)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"server":{"listen":"127.0.0.1:8080"},"nope":1}`))
	if _, err := Load(p); err == nil {
		t.Fatalf("unknown field should be rejected")
	}
}
func TestDatasetsDirectory(t *testing.T) {
	if got := Default().Datasets.Directory; got != "./data/datasets" {
		t.Fatalf("default datasets.directory = %q, want ./data/datasets", got)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"datasets":{"directory":"/srv/synapse/datasets"}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Datasets.Directory != "/srv/synapse/datasets" {
		t.Fatalf("datasets.directory not read from file: %q", c.Datasets.Directory)
	}

	t.Setenv("SYNAPSE_DATASETS_DIR", "/env/datasets")
	if c, err = Load(p); err != nil {
		t.Fatalf("Load w/ env: %v", err)
	}
	if c.Datasets.Directory != "/env/datasets" {
		t.Fatalf("SYNAPSE_DATASETS_DIR ignored: %q", c.Datasets.Directory)
	}

	// The env override also applies with no file at all.
	if c, err = Load(""); err != nil {
		t.Fatalf(`Load(""): %v`, err)
	}
	if c.Datasets.Directory != "/env/datasets" {
		t.Fatalf("SYNAPSE_DATASETS_DIR ignored with no file: %q", c.Datasets.Directory)
	}
}

func TestTrainingDirectory(t *testing.T) {
	if got := Default().Training.Directory; got != "./data/training" {
		t.Fatalf("default training.directory = %q, want ./data/training", got)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"training":{"directory":"/srv/synapse/training"}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Training.Directory != "/srv/synapse/training" {
		t.Fatalf("training.directory not read from file: %q", c.Training.Directory)
	}

	t.Setenv("SYNAPSE_TRAINING_DIR", "/env/training")
	if c, err = Load(p); err != nil {
		t.Fatalf("Load w/ env: %v", err)
	}
	if c.Training.Directory != "/env/training" {
		t.Fatalf("SYNAPSE_TRAINING_DIR ignored: %q", c.Training.Directory)
	}

	if c, err = Load(""); err != nil {
		t.Fatalf(`Load(""): %v`, err)
	}
	if c.Training.Directory != "/env/training" {
		t.Fatalf("SYNAPSE_TRAINING_DIR ignored with no file: %q", c.Training.Directory)
	}
}

// The human review directory (PROJECT.md §16; ADR 0021).
func TestReviewDirectory(t *testing.T) {
	if got := Default().Review.Directory; got != "./data/review" {
		t.Fatalf("default review.directory = %q, want ./data/review", got)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"review":{"directory":"/srv/synapse/review"}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Review.Directory != "/srv/synapse/review" {
		t.Fatalf("review.directory not read from file: %q", c.Review.Directory)
	}

	t.Setenv("SYNAPSE_REVIEW_DIR", "/env/review")
	if c, err = Load(p); err != nil {
		t.Fatalf("Load w/ env: %v", err)
	}
	if c.Review.Directory != "/env/review" {
		t.Fatalf("SYNAPSE_REVIEW_DIR ignored: %q", c.Review.Directory)
	}

	if c, err = Load(""); err != nil {
		t.Fatalf(`Load(""): %v`, err)
	}
	if c.Review.Directory != "/env/review" {
		t.Fatalf("SYNAPSE_REVIEW_DIR ignored with no file: %q", c.Review.Directory)
	}
}

func TestReviewDirectoryMustNotBeEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"review":{"directory":"   "}}`))
	_, err := Load(p)
	if err == nil {
		t.Fatal("an empty review.directory must be rejected")
	}
	if !strings.Contains(err.Error(), "review.directory") {
		t.Fatalf("error does not name the field: %v", err)
	}
}

func TestTrainingDirectoryMustNotBeEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"training":{"directory":"   "}}`))
	_, err := Load(p)
	if err == nil {
		t.Fatal("an empty training.directory must be rejected")
	}
	if !strings.Contains(err.Error(), "training.directory") {
		t.Fatalf("error does not name the field: %v", err)
	}
}

func TestDatasetsDirectoryMustNotBeEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"datasets":{"directory":"   "}}`))
	_, err := Load(p)
	if err == nil {
		t.Fatal("an empty datasets.directory must be rejected")
	}
	if !strings.Contains(err.Error(), "datasets.directory") {
		t.Fatalf("error does not name the field: %v", err)
	}
}

func TestPCAPOverIPSourceLoadAndValidate(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, []byte(`{"capture":{"sources":[
		{"name":"hq","kind":"pcap-over-ip","addr":"127.0.0.1:4789","token_file":"/etc/synapse/poip.tok"},
		{"name":"remote","kind":"pcap-over-ip","addr":"sensor.hq:4789","authorized":true,"insecure_tls":true}
	]}}`))
	c, err := Load(good)
	if err != nil {
		t.Fatalf("Load good pcap-over-ip sources: %v", err)
	}
	if len(c.Capture.Sources) != 2 || c.Capture.Sources[0].Addr != "127.0.0.1:4789" || !c.Capture.Sources[1].Authorized {
		t.Fatalf("sources not parsed: %+v", c.Capture.Sources)
	}

	for name, body := range map[string]string{
		"no-addr":         `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip"}]}}`,
		"addr-no-port":    `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"sensor","authorized":true}]}}`,
		"inline-token":    `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"127.0.0.1:1","token":"secret"}]}}`,
		"insecure-noauth": `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"127.0.0.1:1","token_file":"t","insecure_tls":true}]}}`,
		"remote-noauth":   `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"10.0.0.5:4789","token_file":"t"}]}}`,
		"no-token-noauth": `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"127.0.0.1:1"}]}}`,
		"half-mtls":       `{"capture":{"sources":[{"name":"a","kind":"pcap-over-ip","addr":"127.0.0.1:1","token_file":"t","client_cert_file":"c"}]}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}
