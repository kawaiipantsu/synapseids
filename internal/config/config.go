// Package config loads the synapsed configuration: one explicit JSON file plus
// environment-variable overrides for deployment and secret concerns (PROJECT.md §23).
//
// Native YAML support is tracked separately; JSON keeps the Phase 1 build free of
// third-party dependencies.
package config

import (
	"encoding/json"
	"fmt"
	"net"
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

// Capture holds flow-engine timing (PROJECT.md §7) and the live capture sources
// (PROJECT.md §6, §19.14).
type Capture struct {
	FlowIdleTimeout  Duration        `json:"flow_idle_timeout"`
	FlowMaxLifetime  Duration        `json:"flow_max_lifetime"`
	SnapshotInterval Duration        `json:"snapshot_interval"`
	MaxFlows         int             `json:"max_flows"` // upper bound on the live flow table
	Sources          []CaptureSource `json:"sources"`   // live inputs opened at startup
}

// CaptureSource declares one live capture input. Phase 3 supports kind "nic"
// (a local AF_PACKET interface) and kind "pcap-over-ip" (a framed, authenticated
// TLS stream from a remote sensor, PROJECT.md §6); tcpdump/SSH kinds are tracked
// separately.
type CaptureSource struct {
	Name        string `json:"name"`        // unique label, shown in /api/v1/captures
	Kind        string `json:"kind"`        // "nic" | "pcap-over-ip"
	Interface   string `json:"interface"`   // NIC name for kind "nic" (e.g. "eth0", "lo")
	Promiscuous bool   `json:"promiscuous"` // needs CAP_NET_ADMIN
	Snaplen     int    `json:"snaplen"`     // per-frame bytes; 0 = default (262144)
	Filter      string `json:"filter"`      // "" or a capture.BuiltinFilters name

	// pcap-over-ip fields. The bearer token is never inline (§23): use
	// token_file or the SYNAPSE_POIP_TOKEN environment variable.
	Addr           string `json:"addr,omitempty"`             // sensor host:port
	Token          string `json:"token,omitempty"`            // rejected by validate() — kept only to give a clear error
	TokenFile      string `json:"token_file,omitempty"`       // path to a file holding the bearer token
	ServerName     string `json:"server_name,omitempty"`      // TLS SNI / cert name to verify (default: host of addr)
	CAFile         string `json:"ca_file,omitempty"`          // PEM bundle verifying the sensor cert ("" = system roots)
	ClientCertFile string `json:"client_cert_file,omitempty"` // optional mutual-TLS client certificate
	ClientKeyFile  string `json:"client_key_file,omitempty"`  // optional mutual-TLS client key
	InsecureTLS    bool   `json:"insecure_tls,omitempty"`     // skip sensor cert verification; requires authorized
	Authorized     bool   `json:"authorized,omitempty"`       // operator asserts authority to monitor addr (§21) and accepts insecure/token-less choices (§28.18)
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
// SYNAPSE_MODELS_DIR, SYNAPSE_WEB_ROOT, SYNAPSE_MAX_FLOWS, SYNAPSE_CAPTURE_IFACE)
// always win so secrets and deployment paths stay out of the file.
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
	// SYNAPSE_CAPTURE_IFACE adds one promiscuous NIC source unless the interface
	// is already configured, so a deployment can enable live capture without
	// editing the file (PROJECT.md §23).
	if v := os.Getenv("SYNAPSE_CAPTURE_IFACE"); v != "" {
		if !hasNICInterface(c.Capture.Sources, v) {
			c.Capture.Sources = append(c.Capture.Sources, CaptureSource{
				Name: v, Kind: "nic", Interface: v, Promiscuous: true,
			})
		}
	}
}

// hasNICInterface reports whether srcs already contains a "nic" source bound to
// iface.
func hasNICInterface(srcs []CaptureSource, iface string) bool {
	for _, s := range srcs {
		if s.Kind == "nic" && s.Interface == iface {
			return true
		}
	}
	return false
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
	seen := make(map[string]bool, len(c.Capture.Sources))
	for i, s := range c.Capture.Sources {
		switch {
		case s.Name == "":
			return fmt.Errorf("config: capture.sources[%d].name is empty", i)
		case seen[s.Name]:
			return fmt.Errorf("config: capture.sources[%d]: duplicate name %q", i, s.Name)
		}
		switch s.Kind {
		case "nic":
			if err := validateNICSource(i, s); err != nil {
				return err
			}
		case "pcap-over-ip":
			if err := validatePCAPOverIPSource(i, s); err != nil {
				return err
			}
		default:
			return fmt.Errorf("config: capture.sources[%d] (%s): unknown kind %q (want \"nic\" or \"pcap-over-ip\")", i, s.Name, s.Kind)
		}
		seen[s.Name] = true
	}
	return nil
}

func validateNICSource(i int, s CaptureSource) error {
	switch {
	case s.Interface == "":
		return fmt.Errorf("config: capture.sources[%d] (%s): interface is required for kind \"nic\"", i, s.Name)
	case s.Snaplen < 0 || s.Snaplen > maxCaptureSnaplen:
		return fmt.Errorf("config: capture.sources[%d] (%s): snaplen %d out of range [0,%d]", i, s.Name, s.Snaplen, maxCaptureSnaplen)
	case !captureFilterKnown(s.Filter):
		return fmt.Errorf("config: capture.sources[%d] (%s): unknown filter %q (want \"\" or one of %v)", i, s.Name, s.Filter, captureFilterNames)
	}
	return nil
}

// validatePCAPOverIPSource enforces the security posture of a remote sensor
// stream (PROJECT.md §21, §28.18): a real addr, no secret in the file, and an
// explicit authorized:true for any non-loopback, insecure-TLS or token-less
// configuration.
func validatePCAPOverIPSource(i int, s CaptureSource) error {
	switch {
	case s.Addr == "":
		return fmt.Errorf("config: capture.sources[%d] (%s): addr is required for kind \"pcap-over-ip\"", i, s.Name)
	case !strings.Contains(s.Addr, ":"):
		return fmt.Errorf("config: capture.sources[%d] (%s): addr %q must be host:port", i, s.Name, s.Addr)
	case s.Token != "":
		return fmt.Errorf("config: capture.sources[%d] (%s): an inline token is not allowed — use token_file or the SYNAPSE_POIP_TOKEN env var (PROJECT.md §23)", i, s.Name)
	case (s.ClientCertFile == "") != (s.ClientKeyFile == ""):
		return fmt.Errorf("config: capture.sources[%d] (%s): client_cert_file and client_key_file must be set together", i, s.Name)
	case s.InsecureTLS && !s.Authorized:
		return fmt.Errorf("config: capture.sources[%d] (%s): insecure_tls requires authorized: true (PROJECT.md §21, §28.18)", i, s.Name)
	case !hostIsLoopback(s.Addr) && !s.Authorized:
		return fmt.Errorf("config: capture.sources[%d] (%s): a non-loopback sensor addr %q requires authorized: true — you are asserting you are authorized to monitor it (PROJECT.md §21)", i, s.Name, s.Addr)
	case s.TokenFile == "" && !s.Authorized:
		return fmt.Errorf("config: capture.sources[%d] (%s): set token_file (or authorized: true to connect without a bearer token)", i, s.Name)
	}
	return nil
}

// maxCaptureSnaplen and captureFilterNames mirror capture.DefaultSnaplen and
// capture.BuiltinFilters. They are duplicated here on purpose: config is a leaf
// package that must not import capture (see docs/architecture.md). Keep the two
// in sync.
const maxCaptureSnaplen = 262144

var captureFilterNames = []string{"ip", "ip6", "ip-any", "not-arp"}

func captureFilterKnown(name string) bool {
	if name == "" {
		return true
	}
	for _, f := range captureFilterNames {
		if f == name {
			return true
		}
	}
	return false
}

// LoopbackOnly reports whether the management listener is bound to a loopback
// address. The daemon warns on startup when it is not (PROJECT.md §21).
func (c Config) LoopbackOnly() bool { return hostIsLoopback(c.Server.Listen) }

// hostIsLoopback reports whether the host part of a host:port (or a bare host)
// is a loopback address or the name "localhost". A missing/empty host (e.g.
// ":8080", "0.0.0.0:8080") is not loopback.
func hostIsLoopback(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
