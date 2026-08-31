package capture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// POIPConfig configures a PCAP-over-IP client Source: where the sensor is, how
// to authenticate, and how to verify its TLS identity. Secrets (Token, key
// files) come from the environment or file paths, never inline in a committed
// config (PROJECT.md §23).
type POIPConfig struct {
	// Addr is the sensor's host:port.
	Addr string
	// Token is the bearer secret presented inside the TLS tunnel.
	Token string
	// ServerName is the TLS SNI / certificate name to verify. Empty defaults to
	// the host part of Addr.
	ServerName string
	// CAFile is a PEM bundle used to verify the sensor certificate. Empty uses
	// the host's system roots.
	CAFile string
	// ClientCertFile / ClientKeyFile enable mutual TLS. Both or neither.
	ClientCertFile string
	ClientKeyFile  string
	// InsecureSkipVerify disables sensor certificate verification. It logs a
	// loud warning and requires Authorized.
	InsecureSkipVerify bool
	// Authorized is the operator asserting they are authorized to monitor this
	// sensor (PROJECT.md §21) and acknowledging any insecure_tls / token-less
	// choice (PROJECT.md §28.18). Required for a non-loopback Addr.
	Authorized bool
	// LinkType is the preferred libpcap DLT; 0 accepts whatever the sensor
	// streams. The server's ServerAccept is always authoritative.
	LinkType packet.LinkType
	// SensorID / Filter are advisory metadata advertised in the handshake.
	SensorID string
	Filter   string
	// Timeouts. Zero values fall back to the pcapoverip defaults.
	DialTimeout       time.Duration
	HandshakeTimeout  time.Duration
	ReadIdleTimeout   time.Duration
	KeepaliveInterval time.Duration
	// Logf receives one-line lifecycle and warning messages. Defaults to a
	// no-op; the caller normally passes log.Printf.
	Logf func(string, ...any)
}

// PCAPOverIP is a capture.Source that consumes a SYNPOIP stream from a remote
// sensor over TLS. It does not reconnect: a dial failure, auth reject, TLS
// error, protocol error or read-idle timeout is a single terminal error and the
// Manager row flips to "error". Reconnect/backoff is a tracked follow-up.
type PCAPOverIP struct {
	addr       string
	serverName string
	token      string
	linkPref   uint32
	sensorID   string
	filterAdv  string
	tlsCfg     *tls.Config

	dialTO      time.Duration
	handshakeTO time.Duration
	readIdle    time.Duration
	keepalive   time.Duration
	logf        func(string, ...any)

	stats struct {
		packets, decoded, decodeErr, bytes, drops uint64
		lastUnixNano                              int64
	}
	connLatencyMS atomic.Int64
	dynFilter     atomic.Pointer[string]

	mu     sync.Mutex
	sess   *pcapoverip.Session
	cancel context.CancelFunc
	closed bool
}

// NewPCAPOverIP validates cfg and builds the TLS client configuration. It does
// not dial — the connection is opened by Packets so a sensor that is down at
// startup leaves the daemon serving the API in a degraded mode (PROJECT.md
// §21).
func NewPCAPOverIP(cfg POIPConfig) (*PCAPOverIP, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if !strings.Contains(cfg.Addr, ":") {
		return nil, fmt.Errorf("pcapoverip: addr %q must be host:port", cfg.Addr)
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("pcapoverip: addr %q: %w", cfg.Addr, err)
	}
	if !hostIsLoopback(host) && !cfg.Authorized {
		return nil, fmt.Errorf("pcapoverip: remote sensor %q needs authorized=true — you are asserting you are authorized to monitor it (PROJECT.md §21, §28.18)", cfg.Addr)
	}
	if cfg.InsecureSkipVerify && !cfg.Authorized {
		return nil, errors.New("pcapoverip: insecure_tls disables certificate verification and needs authorized=true (PROJECT.md §28.18)")
	}
	if cfg.Token == "" && !cfg.Authorized {
		return nil, errors.New("pcapoverip: no bearer token — set a token, or authorized=true to connect token-less (PROJECT.md §21)")
	}
	if (cfg.ClientCertFile == "") != (cfg.ClientKeyFile == "") {
		return nil, errors.New("pcapoverip: client_cert_file and client_key_file must be set together")
	}
	if cfg.InsecureSkipVerify {
		cfg.Logf("WARNING: pcapoverip: TLS certificate verification is DISABLED for sensor %s — the connection is encrypted but the sensor identity is not checked (PROJECT.md §21)", cfg.Addr)
	}

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = host
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // gated on Authorized above; logged loudly
	}
	if cfg.CAFile != "" {
		pem, rerr := os.ReadFile(cfg.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("pcapoverip: ca_file: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("pcapoverip: ca_file %q holds no PEM certificate", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCertFile != "" {
		pair, cerr := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if cerr != nil {
			return nil, fmt.Errorf("pcapoverip: client certificate: %w", cerr)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return &PCAPOverIP{
		addr:        cfg.Addr,
		serverName:  serverName,
		token:       cfg.Token,
		linkPref:    uint32(cfg.LinkType),
		sensorID:    cfg.SensorID,
		filterAdv:   cfg.Filter,
		tlsCfg:      tlsCfg,
		dialTO:      orDur(cfg.DialTimeout, pcapoverip.DefaultHandshakeTimeout),
		handshakeTO: orDur(cfg.HandshakeTimeout, pcapoverip.DefaultHandshakeTimeout),
		readIdle:    orDur(cfg.ReadIdleTimeout, pcapoverip.DefaultReadIdleTimeout),
		keepalive:   orDur(cfg.KeepaliveInterval, pcapoverip.DefaultKeepaliveInterval),
		logf:        cfg.Logf,
	}, nil
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// Packets dials the sensor, runs the handshake, and streams decoded packets.
// The error channel carries at most one terminal error; a per-frame decode
// failure is counted, not fatal.
func (p *PCAPOverIP) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, 256)
	errc := make(chan error, 1)

	ctx, cancel := context.WithCancel(ctx)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		cancel()
		close(out)
		errc <- errors.New("pcapoverip: source is closed")
		close(errc)
		return out, errc
	}
	p.cancel = cancel
	p.mu.Unlock()

	go p.run(ctx, cancel, out, errc)
	return out, errc
}

func (p *PCAPOverIP) run(ctx context.Context, cancel context.CancelFunc, out chan<- packet.Packet, errc chan<- error) {
	defer close(out)
	defer close(errc)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{Timeout: p.dialTO}
	conn, err := tls.DialWithDialer(dialer, "tcp", p.addr, p.tlsCfg)
	if err != nil {
		errc <- fmt.Errorf("pcapoverip: dial %s: %w", p.addr, err)
		return
	}

	hello := pcapoverip.ClientHello{
		Version:  pcapoverip.Version1,
		LinkType: p.linkPref,
		Token:    p.token,
		SensorID: p.sensorID,
		Filter:   p.filterAdv,
	}
	sess, err := pcapoverip.ClientHandshake(conn, hello, time.Now().Add(p.handshakeTO))
	if err != nil {
		_ = conn.Close()
		errc <- fmt.Errorf("pcapoverip: handshake with %s: %w", p.addr, err)
		return
	}
	p.connLatencyMS.Store(time.Since(start).Milliseconds())

	link := packet.LinkType(sess.LinkType())
	if link != packet.LinkEthernet && link != packet.LinkRaw {
		_ = sess.Close()
		errc <- fmt.Errorf("pcapoverip: sensor %s offered unsupported link type %d", p.addr, sess.LinkType())
		return
	}
	adv := sess.Filter()
	p.dynFilter.Store(&adv)
	p.logf("pcapoverip: connected to sensor %s (session %s, protocol v%d, link %d, filter %q)",
		p.addr, sess.SessionID(), sess.NegotiatedVersion(), sess.LinkType(), adv)

	p.mu.Lock()
	p.sess = sess
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)

	// Keepalive writer.
	go func() {
		defer wg.Done()
		t := time.NewTicker(p.keepalive)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if werr := sess.WriteKeepalive(); werr != nil {
					return
				}
			}
		}
	}()

	// On cancel (Close or parent ctx): send goodbye, then close the conn to
	// unblock the reader below.
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = sess.WriteGoodbye("client closing")
		_ = sess.Close()
	}()

	termErr := p.readLoop(ctx, sess, link, out)

	cancel()
	wg.Wait()
	_ = sess.Close()
	if termErr != nil {
		errc <- termErr
	}
}

func (p *PCAPOverIP) readLoop(ctx context.Context, sess *pcapoverip.Session, link packet.LinkType, out chan<- packet.Packet) error {
	for {
		ft, payload, err := sess.ReadFrame(p.readIdle)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				return nil // Close / parent cancel: clean stop
			case isTimeout(err):
				return fmt.Errorf("pcapoverip: no frame from %s within %s (read-idle timeout)", p.addr, p.readIdle)
			case errors.Is(err, net.ErrClosed):
				return nil
			default:
				return fmt.Errorf("pcapoverip: stream from %s: %w", p.addr, err)
			}
		}

		switch ft {
		case pcapoverip.FramePacket:
			ts, raw, perr := pcapoverip.ParsePacketFrame(payload)
			if perr != nil {
				atomic.AddUint64(&p.stats.decodeErr, 1)
				continue
			}
			when := time.Unix(0, ts).UTC()
			atomic.AddUint64(&p.stats.packets, 1)
			atomic.AddUint64(&p.stats.bytes, uint64(len(raw)))
			atomic.StoreInt64(&p.stats.lastUnixNano, when.UnixNano())

			pk, derr := packet.Decode(link, when, raw)
			if derr != nil {
				atomic.AddUint64(&p.stats.decodeErr, 1)
				continue
			}
			atomic.AddUint64(&p.stats.decoded, 1)
			select {
			case out <- pk:
			case <-ctx.Done():
				return nil
			}

		case pcapoverip.FrameKeepalive:
			if _, drops, ok := pcapoverip.ParseKeepalive(payload); ok {
				atomic.StoreUint64(&p.stats.drops, drops)
			}

		case pcapoverip.FrameGoodbye:
			p.logf("pcapoverip: sensor %s closed the stream: %q", p.addr, string(payload))
			return nil
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Stats returns a counter snapshot.
func (p *PCAPOverIP) Stats() Stats {
	last := atomic.LoadInt64(&p.stats.lastUnixNano)
	var lt time.Time
	if last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return Stats{
		Packets:   atomic.LoadUint64(&p.stats.packets),
		Decoded:   atomic.LoadUint64(&p.stats.decoded),
		DecodeErr: atomic.LoadUint64(&p.stats.decodeErr),
		Bytes:     atomic.LoadUint64(&p.stats.bytes),
		LastTS:    lt,
		Drops:     atomic.LoadUint64(&p.stats.drops),
	}
}

// ConnLatencyMS reports the TLS dial + handshake time in milliseconds, or 0
// before the first successful connect. The Manager surfaces it as
// connection_latency_ms.
func (p *PCAPOverIP) ConnLatencyMS() int64 { return p.connLatencyMS.Load() }

// DynamicFilter reports the sensor-advertised capture filter once the handshake
// has completed; ok is false until then.
func (p *PCAPOverIP) DynamicFilter() (string, bool) {
	if s := p.dynFilter.Load(); s != nil {
		return *s, true
	}
	return "", false
}

// Close stops the stream and releases the connection. Safe to call more than
// once and before Packets.
func (p *PCAPOverIP) Close() error {
	p.mu.Lock()
	p.closed = true
	cancel := p.cancel
	sess := p.sess
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sess != nil {
		_ = sess.Close()
	}
	return nil
}

// hostIsLoopback reports whether host (no port) is a loopback address or name.
func hostIsLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
