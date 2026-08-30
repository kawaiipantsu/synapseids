package main

import "testing"

func TestVersionVerb(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("synapse version exit = %d", code)
	}
}

func TestUnknownVerb(t *testing.T) {
	if code := run([]string{"frobnicate"}); code != 2 {
		t.Fatalf("unknown verb exit = %d, want 2", code)
	}
}

func TestNoArgs(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("no args exit = %d, want 2", code)
	}
}
