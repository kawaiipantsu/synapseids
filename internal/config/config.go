// Package config loads the synapsed configuration: one explicit JSON file plus
// environment-variable overrides for deployment and secret concerns (PROJECT.md §23).
//
// Native YAML support is tracked separately; JSON keeps the Phase 1 build free of
// third-party dependencies.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that round-trips through JSON as a Go duration
// string ("30s", "5m").
type Duration time.Duration

// UnmarshalJSON parses a duration string or a plain number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		p, err := time.ParseDuration(x)
		if err != nil {
			return err
		}
		*d = Duration(p)
	case float64:
		*d = Duration(time.Duration(x))
	default:
		return fmt.Errorf("config: invalid duration %v", v)
	}
	return nil
}

// MarshalJSON writes the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the full daemon configuration.
type Config struct {
	Server    Server    `json:"server"`
	Storage   Storage   `json:"storage"`
	Capture   Capture   `json:"capture"`
	Models    Models    `json:"models"`
	Live      Live      `json:"live"`
	Retention Retention `json:"retention"`
}

// Server holds the HTTP/WebSocket listener settings.
type Server struct {
	Listen  string `json:"listen"`
	WebRoot string `json:"web_root"` // static assets to serve at /; empty = built-in page
}

// Storage selects and configures the persistence backend.
type Storage struct {
	Driver   string `json:"driver"`    // "memory" (Phase 1); "sqlite" tracked
	Path     string `json:"path"`      // for file-backed drivers
	MaxFlows int    `json:"max_flows"` // ring capacity for the memory driver
}

// Capture holds flow-engine timing (PROJECT.md §7).
type Capture struct {
	FlowIdleTimeout  Duration `json:"flow_idle_timeout"`
	FlowMaxLifetime  Duration `json:"flow_max_lifetime"`
	SnapshotInterval Duration `json:"snapshot_interval"`
	MaxFlows         int      `json:"max_flows"` // upper bound on the live flow table
}

// Models points at the model directory and names the primary model.
type Models struct {
	Directory string `json:"directory"`
	Primary   string `json:"primary"`
}

// Live tunes the WebSocket fan-out (PROJECT.md §18, §22).
type Live struct {
	WebSocketBatch  Duration `json:"websocket_batch"`
	ClientQueueSize int      `json:"client_queue_size"`
}

// Retention holds per-category history windows (PROJECT.md §20).
type Retention struct {
	Flows           Duration `json:"flows"`
	Classifications Duration `json:"classifications"`
}

// Default returns the built-in configuration. The management listener binds to
// loopback so a fresh install is not exposed on the network (PROJECT.md §21).
func Default() Config {
	return Config{
		Server:  Server{Listen: "127.0.0.1:8080"},
		Storage: Storage{Driver: "memory", Path: "./data/synapse.db", MaxFlows: 50000},
		Capture: Capture{
			FlowIdleTimeout:  Duration(30 * time.Second),
			FlowMaxLifetime:  Duration(5 * time.Minute),
			SnapshotInterval: Duration(60 * time.Second),
			MaxFlows:         200000,
		},
		Models: Models{Directory: "./data/models"},
		Live:   Live{WebSocketBatch: Duration(100 * time.Millisecond), ClientQueueSize: 5000},
		Retention: Retention{
			Flows:           Duration(30 * 24 * time.Hour),
			Classifications: Duration(90 * 24 * time.Hour),
		},
	}
}

// Load reads the configuration from path (JSON), overlaying it on Default. An
// empty path returns Default with environment overrides applied. Environment
// variables (SYNAPSE_LISTEN, SYNAPSE_STORAGE_DRIVER, SYNAPSE_STORAGE_PATH,
// SYNAPSE_MODELS_DIR, SYNAPSE_WEB_ROOT) always win so secrets and deployment
// paths stay out of the file.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: %w", err)
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("SYNAPSE_LISTEN"); v != "" {
		c.Server.Listen = v
	}
	if v := os.Getenv("SYNAPSE_WEB_ROOT"); v != "" {
		c.Server.WebRoot = v
	}
	if v := os.Getenv("SYNAPSE_STORAGE_DRIVER"); v != "" {
		c.Storage.Driver = v
	}
	if v := os.Getenv("SYNAPSE_STORAGE_PATH"); v != "" {
		c.Storage.Path = v
	}
	if v := os.Getenv("SYNAPSE_MODELS_DIR"); v != "" {
		c.Models.Directory = v
	}
	if v := os.Getenv("SYNAPSE_MAX_FLOWS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Capture.MaxFlows = n
		}
	}
}

func (c Config) validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("config: server.listen is empty")
	}
	if !strings.Contains(c.Server.Listen, ":") {
		return fmt.Errorf("config: server.listen %q must be host:port", c.Server.Listen)
	}
	switch c.Storage.Driver {
	case "memory", "sqlite":
	default:
		return fmt.Errorf("config: unknown storage.driver %q (want memory or sqlite)", c.Storage.Driver)
	}
	if c.Storage.Driver == "sqlite" {
		return fmt.Errorf("config: storage.driver=sqlite is not implemented yet (tracked); use memory")
	}
	if c.Capture.FlowIdleTimeout <= 0 || c.Capture.FlowMaxLifetime <= 0 {
		return fmt.Errorf("config: capture timeouts must be positive")
	}
	if c.Capture.MaxFlows < 1 {
		return fmt.Errorf("config: capture.max_flows must be >= 1")
	}
	if c.Live.ClientQueueSize < 1 {
		return fmt.Errorf("config: live.client_queue_size must be >= 1")
	}
	return nil
}

// LoopbackOnly reports whether the management listener is bound to a loopback
// address. The daemon warns on startup when it is not (PROJECT.md §21).
func (c Config) LoopbackOnly() bool {
	host := c.Server.Listen
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return strings.HasPrefix(host, "127.")
	}
}
