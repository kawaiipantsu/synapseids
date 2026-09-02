package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func loadYAML(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	mustWrite(t, p, []byte(body))
	return Load(p)
}

// TestYAMLEquivalentToJSON is the load-bearing test: a config expressed in YAML
// must produce exactly the same Config as the equivalent JSON, through the same
// validate().
func TestYAMLEquivalentToJSON(t *testing.T) {
	jsonBody := `{
	  "server": {"listen": "0.0.0.0:9000", "web_root": "/srv/ui"},
	  "storage": {"driver": "memory", "max_flows": 12345},
	  "capture": {
	    "flow_idle_timeout": "15s", "flow_max_lifetime": "2m",
	    "snapshot_interval": "30s", "max_flows": 1000,
	    "sources": [
	      {"name": "wan", "kind": "nic", "interface": "eth0", "promiscuous": true, "filter": "ip-any"},
	      {"name": "dmz", "kind": "tcpdump", "interface": "eth1", "filter": "tcp port 80"}
	    ]
	  },
	  "alerts": {
	    "enabled": true, "min_confidence": 0.8,
	    "per_class_min_confidence": {"suspicious": 0.9, "scan": 0.75},
	    "alert_on_disagreement": false, "max_recent": 500, "dedup_window_sec": 120
	  },
	  "live": {"websocket_batch": "250ms", "client_queue_size": 42}
	}`
	yamlBody := `
server:
  listen: 0.0.0.0:9000
  web_root: /srv/ui
storage:
  driver: memory
  max_flows: 12345
capture:
  flow_idle_timeout: 15s
  flow_max_lifetime: 2m
  snapshot_interval: 30s
  max_flows: 1000
  sources:
    - name: wan
      kind: nic
      interface: eth0
      promiscuous: true
      filter: ip-any
    - name: dmz
      kind: tcpdump
      interface: eth1
      filter: "tcp port 80"
alerts:
  enabled: true
  min_confidence: 0.8
  per_class_min_confidence:
    suspicious: 0.9
    scan: 0.75
  alert_on_disagreement: false
  max_recent: 500
  dedup_window_sec: 120
live:
  websocket_batch: 250ms
  client_queue_size: 42
`
	dir := t.TempDir()
	jp := filepath.Join(dir, "c.json")
	yp := filepath.Join(dir, "c.yaml")
	mustWrite(t, jp, []byte(jsonBody))
	mustWrite(t, yp, []byte(yamlBody))

	fromJSON, err := Load(jp)
	if err != nil {
		t.Fatalf("Load JSON: %v", err)
	}
	fromYAML, err := Load(yp)
	if err != nil {
		t.Fatalf("Load YAML: %v", err)
	}
	if !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Fatalf("YAML and JSON configs differ:\n JSON: %+v\n YAML: %+v", fromJSON, fromYAML)
	}
}

func TestYAMLUnknownKeyRejected(t *testing.T) {
	if _, err := loadYAML(t, "server:\n  listen: 127.0.0.1:8080\n  nonsense: 1\n"); err == nil {
		t.Fatal("an unknown key in YAML was accepted")
	}
}

func TestYAMLRejectsUnsupportedFeatures(t *testing.T) {
	cases := map[string]string{
		"tab indent":    "server:\n\tlisten: x\n",
		"flow mapping":  "server: {listen: x}\n",
		"flow sequence": "alerts:\n  suppress: [1, 2]\n",
		"anchor":        "base: &b\n  listen: x\nserver: *b\n",
		"tag":           "server:\n  listen: !!str 8080\n",
		"block scalar":  "server:\n  listen: |\n    x\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil {
				t.Errorf("YAML accepted an unsupported feature (%s)", name)
			}
		})
	}
}

func TestYAMLScalars(t *testing.T) {
	c, err := loadYAML(t, `
server:
  listen: "127.0.0.1:8080"
storage:
  driver: memory
  max_flows: 7000
alerts:
  enabled: false
  min_confidence: 0.55
  # a comment on its own line
  alert_on_disagreement: true   # and a trailing one
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Listen != "127.0.0.1:8080" {
		t.Errorf("quoted string: %q", c.Server.Listen)
	}
	if c.Storage.MaxFlows != 7000 {
		t.Errorf("int: %d", c.Storage.MaxFlows)
	}
	if c.Alerts.Enabled {
		t.Error("bool false not parsed")
	}
	if c.Alerts.MinConfidence != 0.55 {
		t.Errorf("float: %v", c.Alerts.MinConfidence)
	}
	if !c.Alerts.AlertOnDisagreement {
		t.Error("trailing comment ate the value")
	}
}

func TestYAMLHashInsideValueKept(t *testing.T) {
	// A '#' not preceded by whitespace is part of the value, not a comment.
	c, err := loadYAML(t, "server:\n  listen: 127.0.0.1:8080\n  web_root: /srv/c#1\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.WebRoot != "/srv/c#1" {
		t.Errorf("web_root = %q, want /srv/c#1", c.Server.WebRoot)
	}
}

func TestYAMLEmptyAndComments(t *testing.T) {
	// A file that is only comments loads the defaults.
	c, err := loadYAML(t, "# just a comment\n---\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Listen != Default().Server.Listen {
		t.Errorf("comment-only YAML did not fall back to defaults")
	}
}

func TestYAMLDuplicateKey(t *testing.T) {
	if _, err := loadYAML(t, "server:\n  listen: a\n  listen: b\n"); err == nil {
		t.Fatal("a duplicate key was accepted")
	}
}

func TestYAMLValidationStillRuns(t *testing.T) {
	// storage.driver sqlite is parsed fine but rejected by validate().
	if _, err := loadYAML(t, "storage:\n  driver: sqlite\n"); err == nil {
		t.Fatal("validate() was skipped for a YAML config")
	}
}
