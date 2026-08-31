package config

import (
	"path/filepath"
	"testing"
)

func TestCollectorLoadAndValidate(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, []byte(`{"capture":{"collector":{
		"listen":"0.0.0.0:4789",
		"cert_file":"/etc/synapse/collector.crt",
		"key_file":"/etc/synapse/collector.key",
		"token_file":"/etc/synapse/collector.token",
		"client_ca_file":"/etc/synapse/sensors-ca.pem",
		"max_sensors":8,
		"authorized":true
	}}}`))
	c, err := Load(good)
	if err != nil {
		t.Fatalf("Load good collector: %v", err)
	}
	if c.Capture.Collector.Listen != "0.0.0.0:4789" || c.Capture.Collector.MaxSensors != 8 || !c.Capture.Collector.Authorized {
		t.Fatalf("collector not parsed: %+v", c.Capture.Collector)
	}

	// An empty listen address means "disabled" — nothing else is required.
	disabled := filepath.Join(dir, "disabled.json")
	mustWrite(t, disabled, []byte(`{"capture":{"collector":{"cert_file":"x"}}}`))
	if _, err := Load(disabled); err != nil {
		t.Fatalf("a collector with no listen address should load as disabled: %v", err)
	}

	for name, body := range map[string]string{
		"no-cert":        `{"capture":{"collector":{"listen":"127.0.0.1:4789","key_file":"k","authorized":true}}}`,
		"no-key":         `{"capture":{"collector":{"listen":"127.0.0.1:4789","cert_file":"c","authorized":true}}}`,
		"inline-token":   `{"capture":{"collector":{"listen":"127.0.0.1:4789","cert_file":"c","key_file":"k","token":"secret","authorized":true}}}`,
		"no-authorized":  `{"capture":{"collector":{"listen":"127.0.0.1:4789","cert_file":"c","key_file":"k"}}}`,
		"listen-no-port": `{"capture":{"collector":{"listen":"host","cert_file":"c","key_file":"k","authorized":true}}}`,
		"negative-max":   `{"capture":{"collector":{"listen":"127.0.0.1:4789","cert_file":"c","key_file":"k","max_sensors":-1,"authorized":true}}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestCollectorListenEnvOverride(t *testing.T) {
	t.Setenv("SYNAPSE_COLLECTOR_LISTEN", "192.0.2.1:5000")
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"capture":{"collector":{"listen":"127.0.0.1:4789","cert_file":"c","key_file":"k","authorized":true}}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Capture.Collector.Listen != "192.0.2.1:5000" {
		t.Fatalf("env override not applied: %q", c.Capture.Collector.Listen)
	}
}
