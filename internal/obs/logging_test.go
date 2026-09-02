package obs_test

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/obs"
)

func TestSetupLoggingText(t *testing.T) {
	var buf bytes.Buffer
	lg, err := obs.SetupLogging(&buf, "text", "info")
	if err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	lg.Info("hello", "n", 3)
	out := buf.String()
	if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "n=3") || !strings.Contains(out, "level=INFO") {
		t.Errorf("text output not slog key=value: %q", out)
	}
}

func TestSetupLoggingJSON(t *testing.T) {
	var buf bytes.Buffer
	lg, err := obs.SetupLogging(&buf, "json", "warn")
	if err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	lg.Info("below the bar") // dropped at warn level
	lg.Warn("kept", "code", 7)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly the warn line, got %d line(s): %q", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, lines[0])
	}
	if rec["msg"] != "kept" || rec["level"] != "WARN" || rec["code"] != float64(7) {
		t.Errorf("json record = %v", rec)
	}
}

func TestSetLevelIsLive(t *testing.T) {
	var buf bytes.Buffer
	lg, _ := obs.SetupLogging(&buf, "text", "info")
	lg.Debug("hidden at info")
	if strings.Contains(buf.String(), "hidden at info") {
		t.Fatal("debug line leaked at info level")
	}
	if err := lg.SetLevel("debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	lg.Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Error("SetLevel(debug) did not take effect")
	}
	if lg.Level() != "debug" {
		t.Errorf("Level() = %q, want debug", lg.Level())
	}
	if err := lg.SetLevel("nonsense"); err == nil {
		t.Error("SetLevel accepted a bad level")
	}
}

func TestStdLogBridge(t *testing.T) {
	var buf bytes.Buffer
	if _, err := obs.SetupLogging(&buf, "text", "info"); err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	log.Printf("plain %d", 1)
	log.Print("WARNING: careful")
	out := buf.String()
	if !strings.Contains(out, `msg="plain 1"`) {
		t.Errorf("std log not bridged as info: %q", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "msg=careful") {
		t.Errorf("WARNING: prefix not promoted to warn level: %q", out)
	}
}

func TestSetupLoggingRejectsBadValues(t *testing.T) {
	var buf bytes.Buffer
	if _, err := obs.SetupLogging(&buf, "toml", "info"); err == nil {
		t.Error("bad format accepted")
	}
	if _, err := obs.SetupLogging(&buf, "text", "loud"); err == nil {
		t.Error("bad level accepted")
	}
}

// TestLoggingValuesMatchConfig is the drift guard: config carries its own copy
// of the valid format/level lists (it must not import obs), so every value
// config.ValidateLogging accepts must be one obs.SetupLogging understands, and
// vice versa.
func TestLoggingValuesMatchConfig(t *testing.T) {
	var buf bytes.Buffer
	for _, f := range obs.LogFormats {
		if err := config.ValidateLogging(config.Logging{Format: f, Level: "info"}); err != nil {
			t.Errorf("config rejects format %q that obs lists: %v", f, err)
		}
		if _, err := obs.SetupLogging(&buf, f, "info"); err != nil {
			t.Errorf("obs rejects its own listed format %q: %v", f, err)
		}
	}
	lg, _ := obs.SetupLogging(&buf, "text", "info")
	for _, l := range obs.LogLevels {
		if err := config.ValidateLogging(config.Logging{Format: "text", Level: l}); err != nil {
			t.Errorf("config rejects level %q that obs lists: %v", l, err)
		}
		if err := lg.SetLevel(l); err != nil {
			t.Errorf("obs rejects its own listed level %q: %v", l, err)
		}
	}
	// A value neither side lists must be rejected by both.
	if config.ValidateLogging(config.Logging{Format: "xml"}) == nil {
		t.Error("config accepted format xml")
	}
}
