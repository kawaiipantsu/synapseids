package config

import (
	"os"
	"path/filepath"
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

func TestContribExampleConfigsLoad(t *testing.T) {
	for _, f := range []string{
		"../../contrib/config/synapse.json",
		"../../contrib/config/synapse.pcap-over-ip.json",
	} {
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
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
