package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
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
	mustWrite(t, p, []byte(`{"server":{"listen":"0.0.0.0:9000"},"capture":{"flow_idle_timeout":"15s","flow_max_lifetime":"2m","snapshot_interval":"30s","max_flows":1000},"live":{"websocket_batch":"200ms","client_queue_size":10}}`), 0o644)

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
		mustWrite(t, p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	mustWrite(t, p, []byte(`{"server":{"listen":"127.0.0.1:8080"},"nope":1}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatalf("unknown field should be rejected")
	}
}
