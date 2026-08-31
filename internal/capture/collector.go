package capture

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// CollectorSourceKind is the SourceMeta.Kind every accepted sensor is registered
// under, so GET /api/v1/captures can tell a dialled pcap-over-ip target from a
// reverse-connected sensor.
const CollectorSourceKind = "pcap-over-ip-listen"

// DefaultMaxSensors bounds concurrent accepted sensors when the config leaves
// max_sensors at 0. An unauthenticated remote opening connections is a
// resource-exhaustion vector (PROJECT.md §21), so the accept path is always
// capped.
const DefaultMaxSensors = 32

// SourceRegistrar is the slice of capture.Manager the Collector needs: register
// a source per accepted peer, drop it on disconnect, and read its live counters
// back for GET /api/v1/sensors. *Manager satisfies it.
type SourceRegistrar interface {
	Add(name string, src Source, meta SourceMeta) error
	Remove(name string) bool
	Get(name string) (SourceStatus, bool)
}

// SensorInfo is the immutable facts about one accepted sensor, handed to the
// Collector's connect/disconnect hooks so the daemon can publish
// events.SensorConnected / events.SensorDisconnected without the capture package
// importing the event bus.
type SensorInfo struct {
	SensorID     string
	Location     string
	AgentVersion string
	OSArch       string
	RemoteAddr   string
	LinkType     uint32
	Filter       string
	SessionID    string
	ConnectedAt  time.Time
	// SourceName is the name the peer was registered under in the Manager (the
	// sensor id, or the remote address, de-duplicated).
	SourceName string
}

// SensorStatus is one row of GET /api/v1/sensors: the Collector's view of a
// connected peer — its hello identity plus the live counters projected from the
// matching capture.Manager row (PROJECT.md §5.3, §19.14, §19.15).
type SensorStatus struct {
	SensorID     string    `json:"sensor_id"`
	Location     string    `json:"location"`
	RemoteAddr   string    `json:"remote_addr"`
	LinkType     uint32    `json:"link_type"`
	Filter       string    `json:"filter"`
	ConnectedAt  time.Time `json:"connected_at"`
	Packets      uint64    `json:"packets"`
	Bytes        uint64    `json:"bytes"`
	Drops        uint64    `json:"drops"`
	PPS          float64   `json:"pps"`
	BPS          float64   `json:"bps"`
	LastPacket   time.Time `json:"last_packet"`
	State        string    `json:"state"`
	AgentVersion string    `json:"agent_version,omitempty"`
	OSArch       string    `json:"os_arch,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	SourceName   string    `json:"source_name"`
}

// CollectorConfig configures the daemon-side SYNPOIP collector. TLS material and
// the bearer token are resolved by the caller (internal/capturewire) from file
// paths / SYNAPSE_* env, never inline (PROJECT.md §23).
type CollectorConfig struct {
	// Listen is the TLS listen address (host:port).
	Listen string
	// TLSConfig is the server-side configuration: the daemon's certificate is
	// installed, and ClientAuth is RequireAndVerifyClientCert when a client CA
	// was configured for mutual TLS.
	TLSConfig *tls.Config
	// Token is presented in the ClientHello the collector sends; the sensor
	// verifies it with crypto/subtle. "" connects token-less (only sane with an
	// acknowledged authorized:true and, ideally, mTLS).
	Token string
	// RequireClientCert records that TLSConfig demands a client certificate, for
	// the startup log line only.
	RequireClientCert bool
	// MaxSensors caps concurrent accepted sensors. 0 uses DefaultMaxSensors.
	MaxSensors int
	// LinkPref is the libpcap DLT advertised in the ClientHello; 0 accepts
	// whatever the sensor streams (the ServerAccept is authoritative).
	LinkPref packet.LinkType
	// Handshake / read-idle / keepalive timeouts. 0 uses the pcapoverip defaults.
	HandshakeTimeout  time.Duration
	ReadIdleTimeout   time.Duration
	KeepaliveInterval time.Duration
	// Logf receives one-line lifecycle and rejection messages. Never given the
	// bearer token. Defaults to a no-op.
	Logf func(string, ...any)
}

// Collector accepts reverse-connecting sensors on one TLS listener and registers
// each as its own capture.Manager source. It speaks the SYNPOIP client role on
// every accepted connection (it sends the ClientHello, the sensor answers with a
// ServerAccept and streams packet frames) — the identical wire format the
// dialled pcap-over-ip source uses, per PROTOCOL.md §6. No byte of the protocol
// changes; only who opened the socket.
type Collector struct {
	listen    string
	tlsCfg    *tls.Config
	token     string
	mtls      bool
	max       int
	linkPref  uint32
	handshake time.Duration
	readIdle  time.Duration
	keepalive time.Duration
	logf      func(string, ...any)

	// OnConnect / OnDisconnect are invoked (not on the packet path) as sensors
	// come and go. Set them before Run; they are read without synchronisation.
	OnConnect    func(SensorInfo)
	OnDisconnect func(SensorInfo)

	inflight atomic.Int64
	boundStr atomic.Pointer[string] // the listener address once Run has bound it
	// rejection counters, surfaced in logs and (future) /api/v1/status.
	rejectedCap   atomic.Uint64
	rejectedTLS   atomic.Uint64
	rejectedAuth  atomic.Uint64
	rejectedProto atomic.Uint64
	accepted      atomic.Uint64

	mu    sync.Mutex
	reg   SourceRegistrar  // captured on Run, for the /api/v1/sensors projection
	peers map[string]*peer // keyed by SourceName
}

type peer struct {
	info SensorInfo
	src  *sessionSource
}

// NewCollector validates cfg and returns an idle Collector. It does not listen —
// Run does — so a bad listen address or unreadable TLS material surfaces there
// and the daemon keeps serving the API in a degraded mode (PROJECT.md §21).
func NewCollector(cfg CollectorConfig) (*Collector, error) {
	if !strings.Contains(cfg.Listen, ":") {
		return nil, fmt.Errorf("collector: listen %q must be host:port", cfg.Listen)
	}
	if cfg.TLSConfig == nil || len(cfg.TLSConfig.Certificates) == 0 {
		return nil, errors.New("collector: a server certificate is required (cert_file / key_file)")
	}
	max := cfg.MaxSensors
	if max <= 0 {
		max = DefaultMaxSensors
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Collector{
		listen:    cfg.Listen,
		tlsCfg:    cfg.TLSConfig,
		token:     cfg.Token,
		mtls:      cfg.RequireClientCert,
		max:       max,
		linkPref:  uint32(cfg.LinkPref),
		handshake: orDur(cfg.HandshakeTimeout, pcapoverip.DefaultHandshakeTimeout),
		readIdle:  orDur(cfg.ReadIdleTimeout, pcapoverip.DefaultReadIdleTimeout),
		keepalive: orDur(cfg.KeepaliveInterval, pcapoverip.DefaultKeepaliveInterval),
		logf:      logf,
		peers:     make(map[string]*peer),
	}, nil
}

// Run opens the listener and serves accepted sensors until ctx is cancelled,
// then closes the listener and waits for every in-flight connection to end. A
// listen failure is returned so the caller can degrade; a per-connection failure
// is isolated and logged.
func (c *Collector) Run(ctx context.Context, reg SourceRegistrar) error {
	c.mu.Lock()
	c.reg = reg
	c.mu.Unlock()

	ln, err := tls.Listen("tcp", c.listen, c.tlsCfg)
	if err != nil {
		return fmt.Errorf("collector: listen %s: %w", c.listen, err)
	}
	bound := ln.Addr().String()
	c.boundStr.Store(&bound)
	c.logf("collector: SYNPOIP listener on %s (max_sensors=%d, mtls=%t, token=%t)",
		bound, c.max, c.mtls, c.token != "")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("collector: accept: %w", aerr)
		}
		// The cap is on *registered* sensors; connections still handshaking do
		// not count, so a stream of probes / failed handshakes cannot starve
		// legitimate sensors. A separate, looser bound on connections in flight
		// blunts a half-open-connection flood (PROJECT.md §21).
		if c.registeredCount() >= c.max || c.inflight.Load() >= int64(c.max)+maxHandshakeSlack {
			c.rejectedCap.Add(1)
			c.logf("collector: %s refused — at capacity (%d sensors, %d in flight, max %d)",
				conn.RemoteAddr(), c.registeredCount(), c.inflight.Load(), c.max)
			_ = conn.Close()
			continue
		}
		c.inflight.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.inflight.Add(-1)
			c.serve(ctx, conn, reg)
		}()
	}
}

// maxHandshakeSlack is how many connections past max_sensors may be handshaking
// at once before new ones are refused outright.
const maxHandshakeSlack = 16

func (c *Collector) registeredCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.peers)
}

func (c *Collector) serve(ctx context.Context, conn net.Conn, reg SourceRegistrar) {
	remote := conn.RemoteAddr().String()
	start := time.Now()

	tconn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = tconn.SetDeadline(time.Now().Add(c.handshake))
	if err := tconn.HandshakeContext(ctx); err != nil {
		c.rejectedTLS.Add(1)
		c.logf("collector: %s TLS handshake failed: %v", remote, err)
		_ = conn.Close()
		return
	}

	// SYNPOIP client role: the collector speaks first, exactly as the dialled
	// pcap-over-ip source does (PROTOCOL.md §6).
	hello := pcapoverip.ClientHello{Version: pcapoverip.Version1, LinkType: c.linkPref, Token: c.token}
	sess, err := pcapoverip.ClientHandshake(conn, hello, time.Now().Add(c.handshake))
	if err != nil {
		var re *pcapoverip.RejectError
		if errors.As(err, &re) {
			c.rejectedAuth.Add(1)
			c.logf("collector: %s rejected the handshake (%s)", remote, re.Code)
		} else {
			c.rejectedProto.Add(1)
			c.logf("collector: %s handshake failed: %v", remote, err)
		}
		_ = conn.Close()
		return
	}

	link := packet.LinkType(sess.LinkType())
	if link != packet.LinkEthernet && link != packet.LinkRaw {
		c.rejectedProto.Add(1)
		c.logf("collector: %s offered unsupported link type %d — dropping", remote, sess.LinkType())
		_ = sess.Close()
		return
	}

	ident := pcapoverip.ParseSensorIdentity(sess.SessionID())
	latency := time.Since(start).Milliseconds()
	src := newSessionSource(sess, link, latency, c.readIdle, c.keepalive, c.logf)

	name := ident.SensorID
	if name == "" {
		name = remote
	}
	meta := SourceMeta{Kind: CollectorSourceKind, Filter: filterLabel(sess.Filter()), Origin: "collector"}
	regName := name
	if aerr := reg.Add(regName, src, meta); aerr != nil {
		regName = name + "#" + shortSession(sess.SessionID())
		if aerr2 := reg.Add(regName, src, meta); aerr2 != nil {
			c.logf("collector: cannot register sensor %q from %s: %v", name, remote, aerr2)
			_ = src.Close()
			return
		}
	}

	info := SensorInfo{
		SensorID: ident.SensorID, Location: ident.Location,
		AgentVersion: ident.AgentVersion, OSArch: ident.OSArch,
		RemoteAddr: remote, LinkType: uint32(link), Filter: sess.Filter(),
		SessionID: sess.SessionID(), ConnectedAt: time.Now(), SourceName: regName,
	}
	c.mu.Lock()
	c.peers[regName] = &peer{info: info, src: src}
	c.mu.Unlock()
	c.accepted.Add(1)
	if c.OnConnect != nil {
		c.OnConnect(info)
	}
	c.logf("collector: sensor %q connected from %s (session %s, link %d, filter %q, %dms)",
		displayName(ident, remote), remote, sess.SessionID(), link, sess.Filter(), latency)

	// The Manager drives src.Packets; we wait for the stream to end (goodbye /
	// EOF / idle) or for daemon shutdown, then deregister the peer.
	select {
	case <-src.Done():
	case <-ctx.Done():
		_ = src.Close()
		<-src.Done()
	}

	reg.Remove(regName)
	c.mu.Lock()
	delete(c.peers, regName)
	c.mu.Unlock()
	if c.OnDisconnect != nil {
		c.OnDisconnect(info)
	}
	c.logf("collector: sensor %q disconnected (%s)", displayName(ident, remote), remote)
}

// Addr reports the listener address once Run has bound it, or "" before then.
// With a ":0" configured port this is how a caller learns the real port.
func (c *Collector) Addr() string {
	if p := c.boundStr.Load(); p != nil {
		return *p
	}
	return ""
}

// Sensors returns the current per-peer view for GET /api/v1/sensors, newest
// first. Live counters come from the matching capture.Manager row.
func (c *Collector) Sensors() []SensorStatus {
	c.mu.Lock()
	reg := c.reg
	peers := make([]*peer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	c.mu.Unlock()

	out := make([]SensorStatus, 0, len(peers))
	for _, p := range peers {
		out = append(out, c.status(p, reg))
	}
	sortByConnectedDesc(out)
	return out
}

// Sensor returns one peer by sensor id (or, for an anonymous sensor, by the
// source name it was registered under).
func (c *Collector) Sensor(id string) (SensorStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.peers {
		if p.info.SensorID == id || p.info.SourceName == id {
			return c.status(p, c.reg), true
		}
	}
	return SensorStatus{}, false
}

func (c *Collector) status(p *peer, reg SourceRegistrar) SensorStatus {
	st := p.src.Stats()
	ss := SensorStatus{
		SensorID: p.info.SensorID, Location: p.info.Location,
		RemoteAddr: p.info.RemoteAddr, LinkType: p.info.LinkType,
		Filter: p.info.Filter, ConnectedAt: p.info.ConnectedAt,
		Packets: st.Packets, Bytes: st.Bytes, Drops: st.Drops,
		LastPacket: st.LastTS, State: StateRunning,
		AgentVersion: p.info.AgentVersion, OSArch: p.info.OSArch,
		SessionID: p.info.SessionID, SourceName: p.info.SourceName,
	}
	if reg != nil {
		if row, ok := reg.Get(p.info.SourceName); ok {
			ss.PPS, ss.BPS, ss.State = row.PPS, row.BPS, row.State
			if row.Packets >= ss.Packets {
				ss.Packets, ss.Bytes, ss.Drops = row.Packets, row.Bytes, row.Drops
				ss.LastPacket = row.LastPacket
			}
		}
	}
	return ss
}

func filterLabel(f string) string {
	if f == "" {
		return "(all)"
	}
	return f
}

func shortSession(sid string) string {
	if len(sid) <= 8 {
		return sid
	}
	return sid[len(sid)-8:]
}

func displayName(id pcapoverip.SensorIdentity, remote string) string {
	if id.SensorID == "" {
		return remote
	}
	if id.Location != "" {
		return id.SensorID + "@" + id.Location
	}
	return id.SensorID
}

func sortByConnectedDesc(s []SensorStatus) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].ConnectedAt.After(s[j-1].ConnectedAt); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
