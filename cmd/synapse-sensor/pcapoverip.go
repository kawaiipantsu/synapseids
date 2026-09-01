package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/version"
)

// runPCAPOverIP serves the SYNPOIP protocol over TLS. It returns a process exit
// code.
func runPCAPOverIP(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runPCAPOverIPCtx(ctx, args, nil)
}

// sensorOpts is the parsed command line. It is a struct so the validation and
// wiring below stay readable as the flag set grows.
type sensorOpts struct {
	// Transport posture: exactly one of these decides who dials.
	listen  string
	connect string

	// Capture source: exactly one of these.
	from  string // classic .pcap file to replay
	iface string // live NIC

	// Live capture tuning.
	device    string
	filter    string
	direction string
	promisc   bool
	snaplen   int
	bpfBuffer int // FreeBSD BPF store-buffer bytes (BIOCSBLEN); 0 = default

	// Sensor identity, echoed into the daemon's capture-sources view.
	sensorID string
	location string

	// mode is what this sensor puts on the wire: raw, flow or feature.
	mode pcapoverip.Mode
	// Flow-table lifecycle for the flow/feature modes. The defaults mirror
	// synapsed's own (internal/config), so the same capture yields the same flows
	// on either side.
	flowIdle     time.Duration
	flowMaxLife  time.Duration
	flowSnapshot time.Duration
	flowMax      int

	authorized bool
	speed      float64
	token      string

	// TLS. In --listen mode cert/key are the sensor's *server* certificate and
	// clientCA turns on mutual TLS. In --connect mode the sensor is the TLS
	// client, so cert/key become the *client* certificate it presents and
	// caFile/serverName/insecureTLS govern how it verifies the daemon.
	certFile    string
	keyFile     string
	clientCA    string
	caFile      string
	serverName  string
	insecureTLS bool

	retryMin time.Duration
	retryMax time.Duration
}

// runPCAPOverIPCtx is the testable core: it stops when ctx is cancelled and, in
// --listen mode, invokes ready (if non-nil) with the bound listener address.
func runPCAPOverIPCtx(ctx context.Context, args []string, ready func(net.Addr)) int {
	log.SetFlags(log.LstdFlags | log.LUTC)

	opts, code := parseSensorFlags(args)
	if opts == nil {
		return code
	}

	stream, link, drops, err := openSource(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 1
	}

	// Sensor identity travels in the ServerAccept session id (PROTOCOL.md §6): on
	// both postures the sensor answers the daemon's ClientHello, so it cannot use
	// the hello metadata. FormatSessionPrefix packs id + location + agent version
	// + os/arch; the daemon collector unpacks it for /api/v1/sensors and the
	// SensorConnected event. No wire change — the session id is already free-form.
	ident := pcapoverip.SensorIdentity{
		SensorID:     opts.sensorID,
		Location:     opts.location,
		AgentVersion: version.Version,
		OSArch:       runtime.GOOS + "/" + runtime.GOARCH,
	}
	log.Printf("pcap-over-ip: sensor identity id=%q location=%q agent=%s os=%s",
		ident.SensorID, ident.Location, ident.AgentVersion, ident.OSArch)

	srvCfg := pcapoverip.ServerConfig{
		Token:         opts.token,
		LinkType:      link,
		Mode:          opts.mode,
		Flow:          opts.flowOptions(),
		Filter:        opts.filterLabel(),
		Drops:         drops,
		SessionPrefix: pcapoverip.FormatSessionPrefix(ident),
		Logf:          log.Printf,
	}
	switch opts.mode {
	case pcapoverip.ModeRaw:
		log.Printf("pcap-over-ip: mode raw — every captured frame is streamed to the daemon (SYNPOIP v1 compatible)")
	case pcapoverip.ModeFlow:
		log.Printf("pcap-over-ip: mode flow — flows are aggregated here and shipped as %s records; the daemon does not rebuild them (needs SYNPOIP v2)",
			pcapoverip.FlowRecordSchema)
	case pcapoverip.ModeFeature:
		log.Printf("pcap-over-ip: mode feature — only %s vectors are shipped; NO packet content leaves this host (needs SYNPOIP v2)",
			pcapoverip.FeatureRecordSchema)
	}

	if opts.connect != "" {
		return runConnect(ctx, opts, srvCfg, stream)
	}
	return runListen(ctx, opts, srvCfg, stream, ready)
}

func parseSensorFlags(args []string) (*sensorOpts, int) {
	fs := flag.NewFlagSet("synapse-sensor pcap-over-ip", flag.ContinueOnError)
	o := &sensorOpts{}
	var speedStr, tokenFile, tokenLiteral, modeStr string

	fs.StringVar(&o.listen, "listen", ":4789", "TLS listen address (host:port); the daemon dials in")
	fs.StringVar(&o.connect, "connect", "", "dial this synapsed collector (host:port) instead of listening — for a sensor behind NAT")

	fs.StringVar(&o.from, "from", "", "classic .pcap file to replay over the wire")
	fs.StringVar(&o.iface, "iface", "", "live network interface to capture from (AF_PACKET on Linux, /dev/bpf on FreeBSD)")

	fs.StringVar(&o.device, "bpf-device", "", "explicit BPF device for --iface (FreeBSD only, e.g. /dev/bpf4); empty probes")
	fs.StringVar(&o.filter, "filter", "", "built-in capture filter preset: "+strings.Join(capture.BuiltinFilters(), ", "))
	fs.StringVar(&o.direction, "direction", "", "traffic direction for --iface: in, out or inout (FreeBSD only)")
	fs.BoolVar(&o.promisc, "promisc", false, "put --iface into promiscuous mode")
	fs.IntVar(&o.snaplen, "snaplen", 0, "bytes captured per frame (0 = default)")
	fs.IntVar(&o.bpfBuffer, "bpf-buffer", 0, "BPF store-buffer bytes for --iface (FreeBSD only; 0 = default 512 KiB). "+
		"The kernel clamps this to net.bpf.maxbufsize; the granted size is logged at start")

	fs.StringVar(&o.sensorID, "sensor-id", "", "sensor identifier, shown in the daemon's capture-sources view")
	fs.StringVar(&o.location, "location", "", "sensor location label, shown in the daemon's capture-sources view")

	fs.StringVar(&modeStr, "mode", "", "what to send: raw (every frame), flow (locally aggregated flow records) "+
		"or feature (only the 48 computed features — no packet content leaves this host); default raw, or $SYNAPSE_SENSOR_MODE")
	fs.DurationVar(&o.flowIdle, "flow-idle-timeout", 30*time.Second, "--mode flow/feature: close a flow after this much inactivity")
	fs.DurationVar(&o.flowMaxLife, "flow-max-lifetime", 5*time.Minute, "--mode flow/feature: close a flow after this long")
	fs.DurationVar(&o.flowSnapshot, "flow-snapshot-interval", time.Minute, "--mode flow/feature: emit a snapshot record this often for long flows (0 disables)")
	fs.IntVar(&o.flowMax, "flow-max", 200000, "--mode flow/feature: cap on the live flow table")
	fs.BoolVar(&o.authorized, "authorized", false,
		"assert you are authorized to monitor this traffic; required for live capture and for --insecure-tls")

	fs.StringVar(&tokenFile, "token-file", "", "file holding the bearer token")
	fs.StringVar(&tokenLiteral, "token", "", "bearer token literal (prefer --token-file); empty accepts any peer")
	fs.StringVar(&speedStr, "speed", "1", "replay speed for --from: 0.5, 1, 2, 10, or max")

	fs.StringVar(&o.certFile, "cert", "", "certificate PEM: the server cert with --listen, the client cert with --connect")
	fs.StringVar(&o.keyFile, "key", "", "private key PEM (required with --cert)")
	fs.StringVar(&o.clientCA, "client-ca", "", "--listen only: PEM bundle requiring and verifying a client certificate (mutual TLS)")
	fs.StringVar(&o.caFile, "ca", "", "--connect only: PEM bundle used to verify the collector; empty uses the system roots")
	fs.StringVar(&o.serverName, "server-name", "", "--connect only: expected TLS server name; empty uses the --connect host")
	fs.BoolVar(&o.insecureTLS, "insecure-tls", false, "--connect only: skip collector certificate verification (needs --authorized)")

	fs.DurationVar(&o.retryMin, "retry-min", 2*time.Second, "--connect only: initial reconnect delay")
	fs.DurationVar(&o.retryMax, "retry-max", 60*time.Second, "--connect only: maximum reconnect delay")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Stream captured traffic to synapsed over the framed, authenticated SYNPOIP transport.")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  # the daemon dials this sensor (needs an inbound hole in the firewall)")
		fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --listen :4789 --iface em0 --authorized --token-file tok")
		fmt.Fprintln(os.Stderr, "  # the sensor dials the daemon (works behind NAT; needs a daemon-side collector)")
		fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --connect ids.example:4789 --iface em0 --authorized --token-file tok")
		fmt.Fprintln(os.Stderr, "  # replay a capture file instead of a live NIC")
		fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --listen :4789 --from capture.pcap")
		fmt.Fprintln(os.Stderr, "  # aggregate flows here and ship records, not frames (much less bandwidth)")
		fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --connect ids.example:4789 --iface em0 --authorized --mode flow")
		fmt.Fprintln(os.Stderr, "  # ship only the 48 computed features: no packet content leaves this host")
		fmt.Fprintln(os.Stderr, "  synapse-sensor pcap-over-ip --connect ids.example:4789 --iface em0 --authorized --mode feature")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, 0
		}
		return nil, 2
	}

	speed, err := parseSpeed(speedStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return nil, 2
	}
	o.speed = speed

	// Precedence matches the identity flags: flag, then environment, then the
	// default (PROJECT.md §23).
	if modeStr == "" {
		modeStr = strings.TrimSpace(os.Getenv("SYNAPSE_SENSOR_MODE"))
	}
	mode, merr := pcapoverip.ParseMode(strings.ToLower(strings.TrimSpace(modeStr)))
	if merr != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", merr)
		return nil, 2
	}
	o.mode = mode

	if code := validateSensorOpts(o); code != 0 {
		return nil, code
	}

	resolveSensorIdentity(o)

	tok := strings.TrimSpace(tokenLiteral)
	if tokenFile != "" {
		b, rerr := os.ReadFile(tokenFile) //nolint:gosec // the operator names the token file
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "pcap-over-ip: --token-file:", rerr)
			return nil, 1
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		log.Printf("pcap-over-ip: WARNING no token configured — every peer that completes TLS is accepted")
	}
	o.token = tok

	return o, 0
}

// resolveSensorIdentity fills sensor-id and location from the environment and a
// stable host-derived default when the flags were not given (PROJECT.md §5.3
// "identify their location and sensor ID"). Precedence: flag, then
// SYNAPSE_SENSOR_ID / SYNAPSE_SENSOR_LOCATION, then the hostname for the id.
func resolveSensorIdentity(o *sensorOpts) {
	if o.sensorID == "" {
		o.sensorID = strings.TrimSpace(os.Getenv("SYNAPSE_SENSOR_ID"))
	}
	if o.sensorID == "" {
		if h, err := os.Hostname(); err == nil {
			o.sensorID = strings.TrimSpace(h)
		}
	}
	if o.sensorID == "" {
		o.sensorID = "sensor"
	}
	if o.location == "" {
		o.location = strings.TrimSpace(os.Getenv("SYNAPSE_SENSOR_LOCATION"))
	}
}

// validateSensorOpts enforces the mutually exclusive choices and the
// authorization gate. It returns 0 when the options are usable.
func validateSensorOpts(o *sensorOpts) int {
	reject := func(msg string) int {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", msg)
		return 2
	}

	switch {
	case o.from == "" && o.iface == "":
		return reject("give a capture source: --from <capture.pcap> or --iface <interface>")
	case o.from != "" && o.iface != "":
		return reject("--from and --iface are mutually exclusive")
	}
	if (o.certFile == "") != (o.keyFile == "") {
		return reject("--cert and --key must be given together")
	}
	if !capture.FilterKnown(o.filter) {
		return reject(fmt.Sprintf("unknown --filter %q (want empty or one of %s)",
			o.filter, strings.Join(capture.BuiltinFilters(), ", ")))
	}

	if o.connect != "" {
		if o.clientCA != "" {
			return reject("--client-ca applies to --listen only; in --connect mode the collector is the TLS server")
		}
		if o.insecureTLS && !o.authorized {
			return reject("--insecure-tls disables collector certificate verification; pass --authorized to acknowledge it")
		}
	} else {
		if o.caFile != "" || o.serverName != "" || o.insecureTLS {
			return reject("--ca, --server-name and --insecure-tls apply to --connect only")
		}
	}

	// PROJECT.md §21 and §28.18: capturing live traffic is an authorization
	// decision, not a default. Replaying a file the operator already has is not.
	if o.iface != "" && !o.authorized {
		return reject("capturing live traffic from " + o.iface + " requires --authorized: " +
			"the operator must assert they are authorized to monitor this network")
	}
	if o.iface == "" && (o.promisc || o.device != "" || o.direction != "") {
		return reject("--promisc, --bpf-device and --direction apply to --iface only")
	}

	if o.mode != pcapoverip.ModeRaw {
		if o.flowIdle <= 0 || o.flowMaxLife <= 0 {
			return reject("--flow-idle-timeout and --flow-max-lifetime must be positive in --mode " + o.mode.String())
		}
		if o.flowMax < 1 {
			return reject("--flow-max must be at least 1 in --mode " + o.mode.String())
		}
		if o.flowSnapshot < 0 {
			return reject("--flow-snapshot-interval cannot be negative")
		}
	}
	return 0
}

// flowOptions is the flow-table lifecycle for the flow/feature modes. IDGen is
// left nil: the sensor's per-process counter is only ever provenance metadata,
// because the daemon remaps every arriving record through its own globally
// unique allocator (issue #45, CLAUDE.md).
func (o *sensorOpts) flowOptions() flow.Options {
	return flow.Options{
		IdleTimeout:      o.flowIdle,
		MaxLifetime:      o.flowMaxLife,
		SnapshotInterval: o.flowSnapshot,
		MaxFlows:         o.flowMax,
	}
}

// filterLabel is the human-readable filter string advertised in the SYNPOIP
// ServerAccept and shown in the daemon's capture-sources row.
func (o *sensorOpts) filterLabel() string {
	if o.iface == "" {
		return "" // a whole capture file: no filter
	}
	parts := []string{o.iface}
	if o.direction != "" && o.direction != "inout" {
		parts = append(parts, o.direction)
	}
	if o.filter != "" {
		parts = append(parts, o.filter)
	}
	if o.promisc {
		parts = append(parts, "promisc")
	}
	return strings.Join(parts, " ")
}

// openSource turns the chosen capture source into a SYNPOIP stream, its
// authoritative link type, and a drop-counter callback for keepalives.
func openSource(o *sensorOpts) (pcapoverip.StreamFunc, uint32, func() uint64, error) {
	if o.from != "" {
		stream, link, err := pcapoverip.PcapFileStream(o.from, o.speed)
		if err != nil {
			return nil, 0, nil, err
		}
		log.Printf("pcap-over-ip: source is the capture file %s (link %d) at speed %v", o.from, link, o.speed)
		return stream, link, nil, nil
	}

	live, err := capture.NewLiveStreamer(capture.LiveConfig{
		Interface:   o.iface,
		Promiscuous: o.promisc,
		Snaplen:     o.snaplen,
		Filter:      o.filter,
		Direction:   o.direction,
		Device:      o.device,
		BufferLen:   o.bpfBuffer,
		Logf:        log.Printf,
	})
	if err != nil {
		return nil, 0, nil, err
	}
	log.Printf("pcap-over-ip: source is the live interface %s (link %d, filter %q)",
		o.iface, live.LinkType(), o.filterLabel())
	return live.Stream, live.LinkType(), live.Drops, nil
}

// runListen is the original posture: the sensor listens and synapsed dials it.
func runListen(ctx context.Context, o *sensorOpts, cfg pcapoverip.ServerConfig,
	stream pcapoverip.StreamFunc, ready func(net.Addr)) int {
	tlsCfg, err := serverTLSConfig(o.listen, o.certFile, o.keyFile, o.clientCA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip:", err)
		return 1
	}

	ln, err := tls.Listen("tcp", o.listen, tlsCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcap-over-ip: listen:", err)
		return 1
	}
	log.Printf("pcap-over-ip: serving on %s (link %d)", ln.Addr(), cfg.LinkType)
	if ready != nil {
		ready(ln.Addr())
	}

	serr := pcapoverip.Serve(ctx, ln, cfg, stream)
	if serr != nil && !errors.Is(serr, context.Canceled) {
		log.Printf("pcap-over-ip: %v", serr)
		return 1
	}
	log.Printf("pcap-over-ip: stopped")
	return 0
}

func serverTLSConfig(listen, certFile, keyFile, clientCA string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	} else {
		host := "127.0.0.1"
		if h, err := hostOf(listen); err == nil && h != "" {
			host = h
		}
		pair, certPEM, _, err := pcapoverip.SelfSignedCert(host, "127.0.0.1", "::1", "localhost")
		if err != nil {
			return nil, fmt.Errorf("generating self-signed certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
		sum := sha256.Sum256(certPEM)
		log.Printf("pcap-over-ip: using a generated self-signed certificate for %q", host)
		log.Printf("pcap-over-ip: cert SHA-256 %s", hex.EncodeToString(sum[:]))
		log.Printf("pcap-over-ip: point synapsed at it with insecure_tls + authorized, or pin this PEM as ca_file")
	}

	if clientCA != "" {
		pem, err := os.ReadFile(clientCA) //nolint:gosec // the operator names the CA bundle
		if err != nil {
			return nil, fmt.Errorf("client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client-ca %q holds no PEM certificate", clientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("pcap-over-ip: mutual TLS required — clients must present a certificate signed by %s", clientCA)
	}
	return cfg, nil
}

// hostOf returns the host part of a "host:port" string, with any IPv6 brackets
// stripped. It is used for the self-signed certificate's subject and for the
// default TLS ServerName, neither of which wants the port.
func hostOf(hostport string) (string, error) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return "", errors.New("no port")
	}
	return strings.Trim(hostport[:i], "[]"), nil
}

// parseSpeed maps the CLI speed token to the float PcapFileStream expects.
func parseSpeed(s string) (float64, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "1", "1x":
		return 1, nil
	case "max", "0":
		return 0, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToLower(s), "x"), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid replay speed %q", s)
	}
	return f, nil
}
