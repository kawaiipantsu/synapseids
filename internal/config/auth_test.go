package config

import (
	"path/filepath"
	"testing"
)

func TestAuthDefaults(t *testing.T) {
	a := Default().Auth
	if a.Enabled {
		t.Error("auth.enabled default = true, want false")
	}
	if !a.AllowLoopback {
		t.Error("auth.allow_loopback default = false, want true")
	}
	if err := ValidateAuth(a); err != nil {
		t.Errorf("default auth block does not validate: %v", err)
	}
}

func TestAuthLoadFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"auth":{"enabled":true,"tokens_file":"/etc/synapseids/tokens","allow_loopback":false}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Auth.Enabled || c.Auth.TokensFile != "/etc/synapseids/tokens" || c.Auth.AllowLoopback {
		t.Errorf("auth not parsed: %+v", c.Auth)
	}
}

func TestAuthValidationRejectsEnabledWithoutFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"auth":{"enabled":true}}`))
	if _, err := Load(p); err == nil {
		t.Fatal("auth.enabled without tokens_file must be rejected")
	}
	// Blank string is the same as absent.
	mustWrite(t, p, []byte(`{"auth":{"enabled":true,"tokens_file":"   "}}`))
	if _, err := Load(p); err == nil {
		t.Fatal("auth.enabled with a blank tokens_file must be rejected")
	}
}

func TestAuthEnvOverridesTokensFile(t *testing.T) {
	t.Setenv("SYNAPSE_AUTH_TOKENS_FILE", "/run/secrets/synapse-tokens")
	p := filepath.Join(t.TempDir(), "c.json")
	mustWrite(t, p, []byte(`{"auth":{"enabled":true,"tokens_file":"/placeholder"}}`))
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Auth.TokensFile != "/run/secrets/synapse-tokens" {
		t.Errorf("env override not applied: %q", c.Auth.TokensFile)
	}
}
