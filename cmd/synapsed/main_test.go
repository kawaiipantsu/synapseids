package main

import "testing"

func TestVersionFlag(t *testing.T) {
	if code := run([]string{"--version"}); code != 0 {
		t.Fatalf("synapsed --version exit = %d", code)
	}
}

func TestBadConfigPath(t *testing.T) {
	if code := run([]string{"--config", "/nonexistent/synapse.json"}); code != 1 {
		t.Fatalf("missing config exit = %d, want 1", code)
	}
}
