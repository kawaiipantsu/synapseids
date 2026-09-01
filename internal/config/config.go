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
	"net/netip"
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
	Datasets  Datasets  `json:"datasets"`
	Training  Training  `json:"training"`
	Review    Review    `json:"review"`
	Alerts    Alerts    `json:"alerts"`
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
	Collector        Collector       `json:"collector"` // daemon-side listener for reverse-connecting sensors (§5.3)
}

// Collector configures the daemon-side SYNPOIP listener that accepts
// reverse-connecting sensors (`synapse-sensor pcap-over-ip --connect`), one
// capture source per accepted peer (PROJECT.md §5.3, §6; ADR 0018). It is a
// listener, not a dialled target, so it is its own block rather than a
// capture.sources[] kind. An empty listen address disables it.
//
// The bearer token is never inline (§23): use token_file or the
// SYNAPSE_COLLECTOR_TOKEN environment variable. The daemon presents that token
// in its ClientHello and the sensor verifies it; the collector authenticates the
// sensor with mutual TLS (client_ca_file), so mTLS is strongly recommended for
// any non-loopback listener.
type Collector struct {
	Listen       string `json:"listen"`                   // TLS listen host:port; "" disables the collector
	CertFile     string `json:"cert_file"`                // daemon server certificate PEM (required)
	KeyFile      string `json:"key_file"`                 // daemon server private key PEM (required)
	Token        string `json:"token,omitempty"`          // rejected by validate() — kept only to give a clear error
	TokenFile    string `json:"token_file,omitempty"`     // path to a file holding the bearer token
	ClientCAFile string `json:"client_ca_file,omitempty"` // PEM bundle; when set, mutual TLS is required
	MaxSensors   int    `json:"max_sensors,omitempty"`    // cap on concurrent accepted sensors; 0 = 32
	// Authorized must be true to enable the collector: the operator asserts they
	// are authorised to ingest traffic from the sensors that will connect
	// (PROJECT.md §21, §28.18).
	Authorized bool `json:"authorized"`
}

// CaptureSource declares one live capture input. Phase 3 supports kind "nic"
// (a local AF_PACKET interface), "tcpdump" (a local `tcpdump -w -` subprocess),
// "ssh" (an authorized remote `ssh <host> tcpdump -w -`) and "pcap-over-ip" (a
// framed, authenticated TLS stream from a remote sensor) (PROJECT.md §6).
type CaptureSource struct {
	Name        string `json:"name"`        // unique label, shown in /api/v1/captures
	Kind        string `json:"kind"`        // "nic" | "tcpdump" | "ssh" | "pcap-over-ip"
	Interface   string `json:"interface"`   // local NIC for "nic"/"tcpdump"; the remote NIC for "ssh"
	Promiscuous bool   `json:"promiscuous"` // kind "nic" only; needs CAP_NET_ADMIN
	Snaplen     int    `json:"snaplen"`     // per-frame bytes; 0 = default
	// Filter's meaning is per-kind: for "nic" it is "" or a capture.BuiltinFilters
	// preset name (a cBPF program); for "tcpdump"/"ssh" it is a raw tcpdump
	// filter expression, tokenised on whitespace and passed as trailing argv
	// elements — never shell-interpolated (§28.18).
	Filter string `json:"filter"`

	// tcpdump / ssh:
	Binary    string   `json:"binary"`     // "tcpdump" binary (kind "tcpdump") or "ssh" binary (kind "ssh"); "" = the obvious default
	ExtraArgs []string `json:"extra_args"` // kind "tcpdump": extra tcpdump args before the filter tokens

	// ssh only:
	Destination  string   `json:"destination"`    // "user@host" or an ssh_config alias
	Port         int      `json:"port"`           // SSH port; 0 = ssh default
	IdentityFile string   `json:"identity_file"`  // ssh -i private-key path
	RemoteBinary string   `json:"remote_binary"`  // remote tcpdump binary; "" = "tcpdump"
	KnownHosts   string   `json:"known_hosts"`    // "strict" (default) | "accept-new"
	ExtraSSHArgs []string `json:"extra_ssh_args"` // extra ssh args before the destination

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

	// Authorized must be true for kind "ssh" and for any non-loopback,
	// insecure-TLS or token-less "pcap-over-ip" source: the operator asserts they
	// are authorised to monitor the target (§28.18, PROJECT.md §21).
	Authorized bool `json:"authorized"`
}

// Models points at the model directory and names the primary model.
type Models struct {
	Directory string `json:"directory"`
	Primary   string `json:"primary"`
}

// Datasets points at the root of the on-disk dataset tree. Each dataset version
// is an immutable directory below it holding dataset.csv + manifest.json
// (PROJECT.md §14; ADR 0015).
type Datasets struct {
	Directory string `json:"directory"`
}

// Training points at the directory where the daemon mirrors external training
// runs, one JSON file per run (PROJECT.md §19.8; ADR 0019). The daemon never
// launches a trainer — synapse-trainer reports progress here over HTTP.
type Training struct {
	Directory string `json:"directory"`
}

// Review points at the directory holding human review records, one JSON file
// per reviewed flow (PROJECT.md §16; ADR 0021). Reviews are operator-created and
// therefore human-paced, so unlike the flow and classification stores this one
// is not capped — a hand-labelled decision is the most expensive datum in the
// system and is never evicted.
type Review struct {
	Directory string `json:"directory"`
}

// Alerts configures the detection policy and the bounded detection store behind
// GET /api/v1/detections (issue #117; ADR 0027).
//
// Severity is NOT configurable here. It is derived from the traffic class in
// internal/alert, because a severity table is a small closed set that must cover
// the frozen traffic-classes-v1 list exactly — a per-deployment override would
// let an operator create a class with no severity, which no filter could select.
type Alerts struct {
	// Enabled false stops every detection. The store still runs and still
	// reports counters, so /api/v1/status can say alerting is off rather than
	// looking like nothing has happened. Default: true.
	Enabled bool `json:"enabled"`
	// MinConfidence is the global floor a verdict must clear, in [0,1].
	// Default: 0.70.
	MinConfidence float64 `json:"min_confidence"`
	// PerClassMinConfidence overrides MinConfidence for one traffic-classes-v1
	// class. Keys are validated against the frozen class list; "normal" is
	// rejected because it never alerts. Default: {"suspicious": 0.85}.
	//
	// A non-nil value from the file REPLACES the default map rather than merging
	// into it — that is how encoding/json unmarshals a map, and it is the
	// behaviour an operator writing an explicit table expects.
	PerClassMinConfidence map[string]float64 `json:"per_class_min_confidence"`
	// AlertOnDisagreement raises a detection for a below-threshold verdict when
	// the models disagreed (PROJECT.md §12). Default: true.
	AlertOnDisagreement bool `json:"alert_on_disagreement"`
	// MaxRecent bounds the retained detections; the oldest is evicted first and
	// counted. Default: 1000.
	MaxRecent int `json:"max_recent"`
	// DedupWindowSec is how long one (src, dst, class) detection keeps absorbing
	// further occurrences before a fresh detection is opened. Default: 60.
	DedupWindowSec int `json:"dedup_window_sec"`
	// Suppress is the expected-behaviour layer between classification and
	// detection (issue #133). A verdict that clears its threshold but matches a
	// rule here is still recorded as a classification and stays visible in the
	// flow log — it is simply not raised as a detection, because the traffic is
	// correctly identified and legitimately expected (a DarkWeb monitor's
	// outbound lookups, a vulnerability scanner, backup replication, CDN
	// health-checks). Suppression is a reporting decision, never a modelling
	// one: the classifier keeps scoring honestly. Default: no rules.
	Suppress []SuppressRule `json:"suppress"`
}

// SuppressRule is one expected-behaviour rule (issue #133). It matches on stable
// attributes only — a per-flow rule that had to name the ephemeral port would be
// useless — and every field left empty is a wildcard. At least one of Src, Dst,
// DstPort or Class must be set, or the rule would suppress every detection;
// Note is required so a rule that turns out to match nothing can be found and
// removed rather than silently doing nothing. All of these are enforced at load.
type SuppressRule struct {
	// Src / Dst are an IP address or CIDR the flow's initiator / responder must
	// fall within. "" matches any. A bare address is treated as a single-host
	// prefix. Which of the two you pin is how you express direction: Src set to
	// your own edge address suppresses outbound, Dst set to it suppresses
	// inbound.
	Src string `json:"src"`
	Dst string `json:"dst"`
	// DstPort is the responder (destination) port. 0 matches any.
	DstPort int `json:"dst_port"`
	// Class is a traffic-classes-v1 class name. "" matches any alertable class.
	// "normal" is rejected: it never becomes a detection, so suppressing it is a
	// no-op and almost certainly a mistake.
	Class string `json:"class"`
	// Note is a required free-text explanation of why this traffic is expected.
	// It is echoed in the /api/v1/status suppression counters.
	Note string `json:"note"`
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
		Models:   Models{Directory: "./data/models"},
		Datasets: Datasets{Directory: "./data/datasets"},
		Training: Training{Directory: "./data/training"},
		Review:   Review{Directory: "./data/review"},
		Alerts: Alerts{
			Enabled:               true,
			MinConfidence:         0.70,
			PerClassMinConfidence: map[string]float64{"suspicious": 0.85},
			AlertOnDisagreement:   true,
			MaxRecent:             1000,
			DedupWindowSec:        60,
		},
		Live: Live{WebSocketBatch: Duration(100 * time.Millisecond), ClientQueueSize: 5000},
		Retention: Retention{
			Flows:           Duration(30 * 24 * time.Hour),
			Classifications: Duration(90 * 24 * time.Hour),
		},
	}
}

// Load reads the configuration from path (JSON), overlaying it on Default. An
// empty path returns Default with environment overrides applied. Environment
// variables (SYNAPSE_LISTEN, SYNAPSE_STORAGE_DRIVER, SYNAPSE_STORAGE_PATH,
// SYNAPSE_MODELS_DIR, SYNAPSE_DATASETS_DIR, SYNAPSE_TRAINING_DIR,
// SYNAPSE_REVIEW_DIR, SYNAPSE_WEB_ROOT, SYNAPSE_MAX_FLOWS,
// SYNAPSE_CAPTURE_IFACE) always win so secrets and deployment paths stay out of
// the file.
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
	if v := os.Getenv("SYNAPSE_DATASETS_DIR"); v != "" {
		c.Datasets.Directory = v
	}
	if v := os.Getenv("SYNAPSE_TRAINING_DIR"); v != "" {
		c.Training.Directory = v
	}
	if v := os.Getenv("SYNAPSE_REVIEW_DIR"); v != "" {
		c.Review.Directory = v
	}
	if v := os.Getenv("SYNAPSE_MAX_FLOWS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Capture.MaxFlows = n
		}
	}
	// SYNAPSE_COLLECTOR_LISTEN overrides the daemon-side sensor collector's listen
	// address (the accepted bearer token is SYNAPSE_COLLECTOR_TOKEN, resolved in
	// internal/capturewire so config stays a leaf).
	if v := os.Getenv("SYNAPSE_COLLECTOR_LISTEN"); v != "" {
		c.Capture.Collector.Listen = v
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
	if strings.TrimSpace(c.Datasets.Directory) == "" {
		return fmt.Errorf("config: datasets.directory is empty")
	}
	if strings.TrimSpace(c.Training.Directory) == "" {
		return fmt.Errorf("config: training.directory is empty")
	}
	if strings.TrimSpace(c.Review.Directory) == "" {
		return fmt.Errorf("config: review.directory is empty")
	}
	if err := ValidateAlerts(c.Alerts); err != nil {
		return fmt.Errorf("config: alerts: %w", err)
	}
	seen := make(map[string]bool, len(c.Capture.Sources))
	for i, s := range c.Capture.Sources {
		if s.Name == "" {
			return fmt.Errorf("config: capture.sources[%d].name is empty", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("config: capture.sources[%d]: duplicate name %q", i, s.Name)
		}
		if err := ValidateCaptureSource(s); err != nil {
			return fmt.Errorf("config: capture.sources[%d]: %w", i, err)
		}
		seen[s.Name] = true
	}
	if err := ValidateCollector(c.Capture.Collector); err != nil {
		return fmt.Errorf("config: capture.collector: %w", err)
	}
	return nil
}

// ValidateAlerts checks the alerts block. It rejects nonsense at load rather
// than clamping it: a threshold of 7 or a per-class override for a class that
// does not exist is a typo, and silently correcting it would leave the operator
// believing something is being alerted on when it is not.
func ValidateAlerts(a Alerts) error {
	if a.MinConfidence < 0 || a.MinConfidence > 1 {
		return fmt.Errorf("min_confidence %g is out of range [0,1]", a.MinConfidence)
	}
	if a.MaxRecent < 1 {
		return fmt.Errorf("max_recent must be >= 1 (got %d)", a.MaxRecent)
	}
	if a.DedupWindowSec < 1 {
		return fmt.Errorf("dedup_window_sec must be >= 1 (got %d)", a.DedupWindowSec)
	}
	for name, v := range a.PerClassMinConfidence {
		if !alertClassKnown(name) {
			return fmt.Errorf("per_class_min_confidence: %q is not a traffic-classes-v1 class (want one of %v)", name, alertClassNames)
		}
		if name == alertClassNormal {
			return fmt.Errorf("per_class_min_confidence: %q never alerts, so a threshold for it has no effect — remove it", name)
		}
		if v < 0 || v > 1 {
			return fmt.Errorf("per_class_min_confidence[%q] = %g is out of range [0,1]", name, v)
		}
	}
	for i, r := range a.Suppress {
		if err := validateSuppressRule(r); err != nil {
			return fmt.Errorf("suppress[%d]: %w", i, err)
		}
	}
	return nil
}

// validateSuppressRule rejects a suppression rule that is malformed or that
// would quietly do nothing — a typo in a rule an operator believes is hiding
// noise is worse than a load error (issue #133).
func validateSuppressRule(r SuppressRule) error {
	if strings.TrimSpace(r.Note) == "" {
		return fmt.Errorf("needs a note explaining why this traffic is expected")
	}
	if r.Src == "" && r.Dst == "" && r.DstPort == 0 && r.Class == "" {
		return fmt.Errorf("has no matchers (src, dst, dst_port, class all empty), so it would suppress every detection")
	}
	if r.Src != "" {
		if err := checkHostOrPrefix(r.Src); err != nil {
			return fmt.Errorf("src %q: %w", r.Src, err)
		}
	}
	if r.Dst != "" {
		if err := checkHostOrPrefix(r.Dst); err != nil {
			return fmt.Errorf("dst %q: %w", r.Dst, err)
		}
	}
	if r.DstPort < 0 || r.DstPort > 65535 {
		return fmt.Errorf("dst_port %d is out of range [0,65535]", r.DstPort)
	}
	if r.Class != "" {
		if !alertClassKnown(r.Class) {
			return fmt.Errorf("class %q is not a traffic-classes-v1 class (want one of %v)", r.Class, alertClassNames)
		}
		if r.Class == alertClassNormal {
			return fmt.Errorf("class %q never becomes a detection, so suppressing it has no effect — remove it", r.Class)
		}
	}
	return nil
}

// checkHostOrPrefix accepts either a CIDR ("10.0.0.0/8") or a bare address
// ("10.0.0.1"). internal/alert.parseHostOrPrefix compiles the same syntax into a
// matcher; config stays a leaf package (docs/architecture.md) and carries only
// the validation half. TestSuppressRuleParsingMatchesConfig in internal/alert
// fails if the two ever disagree on what parses.
func checkHostOrPrefix(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return fmt.Errorf("not an IP address or CIDR")
	}
	return nil
}

// alertClassNames mirrors the class names in schemas/outputs/traffic-classes-v1.json.
// Like maxCaptureSnaplen and captureFilterNames above, it is duplicated on
// purpose: config is a leaf package that must not import schema
// (docs/architecture.md). traffic-classes-v1 is frozen (PROJECT.md §9), so this
// list cannot drift in practice — and TestConfigAlertClassNamesMatchSchema in
// internal/alert, which legitimately imports both packages, fails if it does.
var alertClassNames = []string{
	"normal", "scan", "dos_ddos", "brute_force", "botnet_c2", "web_attack", "suspicious",
}

// alertClassNormal is the class that never alerts.
const alertClassNormal = "normal"

func alertClassKnown(name string) bool {
	for _, c := range alertClassNames {
		if c == name {
			return true
		}
	}
	return false
}

// ValidateCollector enforces the collector block's security posture (PROJECT.md
// §21, §23, §28.18). An empty listen address means "disabled" and everything
// else is skipped.
func ValidateCollector(c Collector) error {
	if c.Listen == "" {
		return nil
	}
	switch {
	case !strings.Contains(c.Listen, ":"):
		return fmt.Errorf("listen %q must be host:port", c.Listen)
	case c.CertFile == "" || c.KeyFile == "":
		return fmt.Errorf("cert_file and key_file are required to run the collector")
	case c.Token != "":
		return fmt.Errorf("an inline token is not allowed — use token_file or the SYNAPSE_COLLECTOR_TOKEN env var (PROJECT.md §23)")
	case c.MaxSensors < 0:
		return fmt.Errorf("max_sensors must be >= 0 (0 = default)")
	case !c.Authorized:
		return fmt.Errorf("the collector ingests traffic from remote sensors and requires \"authorized\": true — you are asserting you are authorised to monitor them (PROJECT.md §21, §28.18)")
	}
	return nil
}

// ValidateCaptureSource runs the per-source rules the config loader applies to
// every capture.sources[] entry: a non-empty name, an in-range snaplen and the
// per-kind required fields and §28.18 authorization gate. The runtime
// POST /api/v1/captures handler calls this exact function so the file path and
// the API path can never drift (issue #32). Cross-source concerns (duplicate
// names, array index in the message) stay in validate().
func ValidateCaptureSource(s CaptureSource) error {
	if s.Name == "" {
		return fmt.Errorf("capture source: name is required")
	}
	if s.Snaplen < 0 || s.Snaplen > maxCaptureSnaplen {
		return fmt.Errorf("capture source %q: snaplen %d out of range [0,%d]", s.Name, s.Snaplen, maxCaptureSnaplen)
	}
	return validateCaptureKind(s)
}

// validateCaptureKind enforces the per-kind required fields (PROJECT.md §6,
// §28.18).
func validateCaptureKind(s CaptureSource) error {
	switch s.Kind {
	case "nic":
		if s.Interface == "" {
			return fmt.Errorf("capture source %q: interface is required for kind \"nic\"", s.Name)
		}
		if !captureFilterKnown(s.Filter) {
			return fmt.Errorf("capture source %q: unknown filter %q (want \"\" or one of %v)", s.Name, s.Filter, captureFilterNames)
		}
	case "tcpdump":
		if s.Interface == "" {
			return fmt.Errorf("capture source %q: interface is required for kind \"tcpdump\"", s.Name)
		}
	case "ssh":
		if s.Destination == "" {
			return fmt.Errorf("capture source %q: destination is required for kind \"ssh\"", s.Name)
		}
		if s.Interface == "" {
			return fmt.Errorf("capture source %q: interface is required for kind \"ssh\"", s.Name)
		}
		if !s.Authorized {
			return fmt.Errorf("capture source %q: remote capture requires \"authorized\": true — you must be authorised to monitor %s (PROJECT.md §28.18)", s.Name, s.Destination)
		}
		switch s.KnownHosts {
		case "", "strict", "accept-new":
		default:
			return fmt.Errorf("capture source %q: known_hosts %q must be \"strict\" or \"accept-new\"", s.Name, s.KnownHosts)
		}
	case "pcap-over-ip":
		return validatePCAPOverIPSource(s)
	default:
		return fmt.Errorf("capture source %q: unknown kind %q (want \"nic\", \"tcpdump\", \"ssh\" or \"pcap-over-ip\")", s.Name, s.Kind)
	}
	return nil
}

// validatePCAPOverIPSource enforces the security posture of a remote sensor
// stream (PROJECT.md §21, §28.18): a real addr, no secret in the file, and an
// explicit authorized:true for any non-loopback, insecure-TLS or token-less
// configuration.
func validatePCAPOverIPSource(s CaptureSource) error {
	switch {
	case s.Addr == "":
		return fmt.Errorf("capture source %q: addr is required for kind \"pcap-over-ip\"", s.Name)
	case !strings.Contains(s.Addr, ":"):
		return fmt.Errorf("capture source %q: addr %q must be host:port", s.Name, s.Addr)
	case s.Token != "":
		return fmt.Errorf("capture source %q: an inline token is not allowed — use token_file or the SYNAPSE_POIP_TOKEN env var (PROJECT.md §23)", s.Name)
	case (s.ClientCertFile == "") != (s.ClientKeyFile == ""):
		return fmt.Errorf("capture source %q: client_cert_file and client_key_file must be set together", s.Name)
	case s.InsecureTLS && !s.Authorized:
		return fmt.Errorf("capture source %q: insecure_tls requires authorized: true (PROJECT.md §21, §28.18)", s.Name)
	case !hostIsLoopback(s.Addr) && !s.Authorized:
		return fmt.Errorf("capture source %q: a non-loopback sensor addr %q requires authorized: true — you are asserting you are authorized to monitor it (PROJECT.md §21)", s.Name, s.Addr)
	case s.TokenFile == "" && !s.Authorized:
		return fmt.Errorf("capture source %q: set token_file (or authorized: true to connect without a bearer token)", s.Name)
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
