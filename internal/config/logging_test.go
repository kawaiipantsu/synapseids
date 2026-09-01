package config

import (
	"path/filepath"
	"testing"
)

func TestLoggingDefaults(t *testing.T) {
	l := Default().Logging
	if l.Format != "text" || l.Level != "info" {
		t.Errorf("logging default = %+v, want {text info}", l)
	}
	if err := ValidateLogging(l); err != nil {
		t.Errorf("default logging block does not validate: %v", err)
	}
}

func TestLoggingLoadFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"logging":{"format":"json","level":"debug"}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Logging.Format != "json" || c.Logging.Level != "debug" {
		t.Errorf("logging = %+v", c.Logging)
	}
}

func TestLoggingValidationRejectsNonsense(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bad-format": `{"logging":{"format":"yaml"}}`,
		"bad-level":  `{"logging":{"level":"chatty"}}`,
	} {
		p := filepath.Join(dir, name+".json")
		mustWrite(t, p, []byte(body))
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestLoggingEnvOverride(t *testing.T) {
	t.Setenv("SYNAPSE_LOG_FORMAT", "json")
	t.Setenv("SYNAPSE_LOG_LEVEL", "warn")
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Logging.Format != "json" || c.Logging.Level != "warn" {
		t.Errorf("env override not applied: %+v", c.Logging)
	}
}

// An empty logging block is valid — both fields fall back to the Default().
func TestLoggingEmptyBlockIsValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"logging":{}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Logging.Format != "text" || c.Logging.Level != "info" {
		t.Errorf("empty logging block did not keep the defaults: %+v", c.Logging)
	}
}
