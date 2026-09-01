package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/alert"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/obs"
)

func testReloader(t *testing.T, path string, initial config.Config) (*reloader, *bytes.Buffer, *alert.Store) {
	t.Helper()
	var buf bytes.Buffer
	lg, err := obs.SetupLogging(&buf, "text", "info")
	if err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	pol, err := alertPolicy(initial.Alerts)
	if err != nil {
		t.Fatalf("alertPolicy: %v", err)
	}
	st := alert.New(pol, alert.Options{})
	t.Cleanup(func() { _ = st.Close() })
	return newReloader(path, lg, st, initial), &buf, st
}

func writeCfg(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const baseCfg = `{
  "server": {"listen": "127.0.0.1:8080"},
  "logging": {"format": "text", "level": "info"},
  "alerts": {"enabled": true, "min_confidence": 0.7,
    "per_class_min_confidence": {"suspicious": 0.85},
    "alert_on_disagreement": true, "max_recent": 1000, "dedup_window_sec": 60,
    "suppress": []}
}`

func TestReloadAppliesLevelAndPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeCfg(t, path, baseCfg)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, buf, st := testReloader(t, path, cfg)

	writeCfg(t, path, strings.NewReplacer(
		`"level": "info"`, `"level": "debug"`,
		`"min_confidence": 0.7`, `"min_confidence": 0.9`,
	).Replace(baseCfg))
	r.reload()

	out := buf.String()
	if !strings.Contains(out, "config reloaded") || !strings.Contains(out, "logging.level=debug") || !strings.Contains(out, "alerts.policy") {
		t.Fatalf("reload log missing applied items:\n%s", out)
	}
	if r.logger.Level() != "debug" {
		t.Errorf("log level = %q, want debug", r.logger.Level())
	}
	if got := st.Stats(); got.Enabled != true {
		t.Errorf("alert store still enabled? %+v", got)
	}
	// The swapped policy took: a 0.85 scan is now below the 0.9 floor.
	if th := r.cur.Alerts.MinConfidence; th != 0.9 {
		t.Errorf("reloader.cur not updated: min_confidence = %v", th)
	}
}

func TestReloadRestartOnlyChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeCfg(t, path, baseCfg)
	cfg, _ := config.Load(path)
	r, buf, _ := testReloader(t, path, cfg)

	writeCfg(t, path, strings.Replace(baseCfg, `"listen": "127.0.0.1:8080"`, `"listen": "127.0.0.1:9999"`, 1))
	r.reload()

	out := buf.String()
	if !strings.Contains(out, "restart_required=[server]") {
		t.Fatalf("a server.listen change was not flagged restart-required:\n%s", out)
	}
	if strings.Contains(out, "applied=[logging") || strings.Contains(out, "alerts.policy") {
		t.Errorf("nothing should have been applied live:\n%s", out)
	}
}

func TestReloadRejectsBadFileAndKeepsRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeCfg(t, path, baseCfg)
	cfg, _ := config.Load(path)
	r, buf, _ := testReloader(t, path, cfg)
	before := r.cur

	writeCfg(t, path, `{"logging": {"level": "chatty"}}`)
	r.reload()

	out := buf.String()
	if !strings.Contains(out, "config reload failed") {
		t.Fatalf("a bad file was not reported as a failed reload:\n%s", out)
	}
	if r.cur.Logging.Level != before.Logging.Level {
		t.Error("the running configuration changed despite an invalid reload")
	}
	if r.logger.Level() != "info" {
		t.Errorf("log level moved to %q on a failed reload", r.logger.Level())
	}
}

func TestReloadNoConfigFile(t *testing.T) {
	r, buf, _ := testReloader(t, "", config.Default())
	r.reload()
	if !strings.Contains(buf.String(), "SIGHUP ignored: no --config file") {
		t.Errorf("SIGHUP with no config file: %s", buf.String())
	}
}

func TestReloadNoChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeCfg(t, path, baseCfg)
	cfg, _ := config.Load(path)
	r, buf, _ := testReloader(t, path, cfg)

	r.reload() // same file, unchanged
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("an unchanged reload did not say so:\n%s", buf.String())
	}
}
