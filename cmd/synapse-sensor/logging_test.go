package main

import (
	"bytes"
	"log"
	"os"
	"testing"
)

func TestParseLogVerbosity(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    logVerbosity
		wantErr bool
	}{
		{"", logNormal, false},
		{"normal", logNormal, false},
		{"NORMAL", logNormal, false},
		{" verbose ", logVerbose, false},
		{"debug", logVerbose, false},
		{"errors", logErrorsOnly, false},
		{"error", logErrorsOnly, false},
		{"loud", logNormal, true},
		{"trace", logNormal, true},
	} {
		got, err := parseLogVerbosity(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseLogVerbosity(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Fatalf("parseLogVerbosity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The three helpers must gate on currentLogVerbosity: errors-only suppresses
// info and verbose; normal suppresses only verbose; verbose shows everything;
// and logErrorf is never suppressed.
func TestLogLevelGating(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags | log.LUTC)
		currentLogVerbosity = logNormal
	})

	cases := []struct {
		level                     logVerbosity
		wantErr, wantInfo, wantVb bool
	}{
		{logErrorsOnly, true, false, false},
		{logNormal, true, true, false},
		{logVerbose, true, true, true},
	}
	for _, c := range cases {
		buf.Reset()
		currentLogVerbosity = c.level
		logErrorf("E")
		logInfof("I")
		logVerbosef("V")
		out := buf.String()
		if got := bytes.Contains(buf.Bytes(), []byte("E\n")); got != c.wantErr {
			t.Fatalf("level %v: err line present=%v want %v (%q)", c.level, got, c.wantErr, out)
		}
		if got := bytes.Contains(buf.Bytes(), []byte("I\n")); got != c.wantInfo {
			t.Fatalf("level %v: info line present=%v want %v (%q)", c.level, got, c.wantInfo, out)
		}
		if got := bytes.Contains(buf.Bytes(), []byte("V\n")); got != c.wantVb {
			t.Fatalf("level %v: verbose line present=%v want %v (%q)", c.level, got, c.wantVb, out)
		}
	}
}

// infoLogf() returns a working callback at normal+ and a no-op at errors-only,
// for the capture adapters that take a Logf.
func TestInfoLogfCallback(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags | log.LUTC)
		currentLogVerbosity = logNormal
	})

	currentLogVerbosity = logErrorsOnly
	infoLogf()("hushed %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("infoLogf() at errors-only wrote %q", buf.String())
	}
	currentLogVerbosity = logNormal
	infoLogf()("spoken %d", 2)
	if !bytes.Contains(buf.Bytes(), []byte("spoken 2")) {
		t.Fatalf("infoLogf() at normal did not write: %q", buf.String())
	}
}

// --log-level is parsed into sensorOpts and an unknown value is a usage error.
func TestSensorFlagsLogLevel(t *testing.T) {
	log.SetOutput(&bytes.Buffer{})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	o, code := parseSensorFlags([]string{"--from", "x.pcap", "--log-level", "verbose"})
	if o == nil || code != 0 {
		t.Fatalf("parseSensorFlags(--log-level verbose) = %v, %d", o, code)
	}
	if o.logVerbosity != logVerbose {
		t.Fatalf("logVerbosity = %v, want verbose", o.logVerbosity)
	}
	if _, code := parseSensorFlags([]string{"--from", "x.pcap", "--log-level", "shout"}); code != 2 {
		t.Fatalf("bad --log-level exit = %d, want 2", code)
	}
}
