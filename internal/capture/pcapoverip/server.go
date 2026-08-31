package pcapoverip

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Record is one raw captured frame handed to the transport by a sensor's packet
// source. Raw is the link-layer frame exactly as captured.
type Record struct {
	TS  time.Time
	Raw []byte
}

// StreamFunc opens a fresh record stream for one connected client. The server
// calls it once per accepted connection and consumes the channels until the
// record channel closes, the error channel yields a terminal error, or ctx is
// cancelled (client gone / server shutting down).
type StreamFunc func(ctx context.Context) (<-chan Record, <-chan error)

// ServerConfig configures the reference server.
type ServerConfig struct {
	// Token is the bearer secret every client must present. Empty means the
	// server accepts any client — only sane on loopback for a demo.
	Token string
	// LinkType is the authoritative libpcap DLT the stream carries (1 EN10MB,
	// 101 RAW). It is echoed in every ServerAccept.
	LinkType uint32
	// Filter is advertised to clients and shown in their capture-sources view.
	Filter string
	// KeepaliveInterval is how often the server emits a keepalive frame when no
	// packet has gone out. 0 uses DefaultKeepaliveInterval.
	KeepaliveInterval time.Duration
	// Drops, when set, supplies the sender-side kernel drop counter carried in
	// keepalive frames (PROTOCOL.md §3.2). A live NIC sensor wires this to its
	// BIOCGSTATS / PACKET_STATISTICS total so the daemon's capture-sources view
	// shows real drops (PROJECT.md §19.14, §22). nil reports 0.
	Drops func() uint64
	// SessionPrefix is prepended to the generated session id, so a reverse
	// connection can identify itself to the collector that accepted it (the
	// daemon sends the ClientHello in that direction, so the sensor's identity
	// travels in the accept). Truncated to fit MaxSessionIDLen.
	SessionPrefix string
	// HandshakeTimeout bounds how long a client has to complete the handshake.
	// 0 uses DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// WriteTimeout bounds a single frame write. 0 uses DefaultWriteTimeout.
	WriteTimeout time.Duration
	// Logf, if set, logs one line per connection lifecycle event. It must never
	// be given the bearer token.
	Logf func(string, ...any)
}

// Transport defaults.
const (
	DefaultKeepaliveInterval = 15 * time.Second
	DefaultHandshakeTimeout  = 10 * time.Second
	DefaultReadIdleTimeout   = 60 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
)

func (c ServerConfig) withDefaults() ServerConfig {
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.Drops == nil {
		c.Drops = func() uint64 { return 0 }
	}
	return c
}

// Serve accepts connections on ln (already wrapped in TLS by the caller) and
// serves each one the SYNPOIP protocol, sourcing records from stream. It returns
// when ctx is cancelled, after closing ln and signalling every in-flight
// connection to send a goodbye and hang up.
func Serve(ctx context.Context, ln net.Listener, cfg ServerConfig, stream StreamFunc) error {
	cfg = cfg.withDefaults()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(ctx, conn, cfg, stream)
		}()
	}
}

// ServeConn speaks the sensor (server) side of SYNPOIP on a connection that is
// already established, and closes it when the stream ends. Serve calls it once
// per accepted connection.
//
// It is exported for the **reverse-connect** posture: a sensor behind NAT dials
// the daemon's collector, and on that already-open TLS connection the SYNPOIP
// roles are unchanged — the daemon still sends the ClientHello and the sensor
// still answers with a ServerAccept and streams packet frames. Only the TCP/TLS
// dial direction is inverted, so no byte of the wire format changes and no
// version bump is needed. See PROTOCOL.md §6 and ADR 0014.
//
// conn must already be wrapped in TLS by the caller.
func ServeConn(ctx context.Context, conn net.Conn, cfg ServerConfig, stream StreamFunc) {
	serveConn(ctx, conn, cfg.withDefaults(), stream)
}

func serveConn(ctx context.Context, conn net.Conn, cfg ServerConfig, stream StreamFunc) {
	defer func() { _ = conn.Close() }()
	remote := conn.RemoteAddr().String()

	_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	hello, err := ReadClientHello(conn)
	if err != nil {
		cfg.Logf("pcapoverip: %s: handshake read failed: %v", remote, err)
		writeReject(conn, cfg, ServerReject{Code: RejectBadRequest, Reason: "malformed handshake"})
		return
	}

	if code, reason, ok := negotiate(hello, cfg); !ok {
		cfg.Logf("pcapoverip: %s: rejected (%s)", remote, code)
		writeReject(conn, cfg, ServerReject{Code: code, Reason: reason})
		return
	}

	sid := newSessionID(cfg.SessionPrefix)
	acc := ServerAccept{Version: Version1, LinkType: cfg.LinkType, Filter: cfg.Filter, SessionID: sid}
	raw, err := acc.MarshalBinary()
	if err != nil {
		cfg.Logf("pcapoverip: %s: encoding accept: %v", remote, err)
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	if _, err := conn.Write(raw); err != nil {
		cfg.Logf("pcapoverip: %s: writing accept: %v", remote, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	cfg.Logf("pcapoverip: %s: session %s started (sensor=%q link=%d)", remote, sid, hello.SensorID, cfg.LinkType)

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A reader goroutine turns a client goodbye or EOF into a cancel so the
	// server stops streaming to a peer that has gone away.
	go func() {
		fr := NewFrameReader(conn)
		for {
			t, _, rerr := fr.ReadFrame()
			if rerr != nil {
				cancel()
				return
			}
			if t == FrameGoodbye {
				cancel()
				return
			}
		}
	}()

	records, errc := stream(connCtx)
	ka := time.NewTicker(cfg.KeepaliveInterval)
	defer ka.Stop()

	var sent uint64
	write := func(ft FrameType, payload []byte) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
		if werr := WriteFrame(conn, ft, payload); werr != nil {
			cfg.Logf("pcapoverip: %s: session %s write: %v", remote, sid, werr)
			cancel()
			return false
		}
		return true
	}

	for {
		select {
		case <-connCtx.Done():
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
			_ = WriteFrame(conn, FrameGoodbye, []byte("server closing"))
			cfg.Logf("pcapoverip: %s: session %s closed (%d packets)", remote, sid, sent)
			return

		case <-ka.C:
			if !write(FrameKeepalive, KeepalivePayload(sent, cfg.Drops())) {
				return
			}

		case rerr := <-errc:
			if rerr != nil && !errors.Is(rerr, context.Canceled) {
				_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
				_ = WriteFrame(conn, FrameGoodbye, []byte("source error: "+rerr.Error()))
				cfg.Logf("pcapoverip: %s: session %s source error: %v", remote, sid, rerr)
				return
			}

		case rec, ok := <-records:
			if !ok {
				_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
				_ = WriteFrame(conn, FrameGoodbye, []byte("end of capture"))
				cfg.Logf("pcapoverip: %s: session %s end of capture (%d packets)", remote, sid, sent)
				return
			}
			if len(rec.Raw) > MaxFramePayload-8 {
				continue // a single frame larger than the ceiling is dropped, not fatal
			}
			if !write(FramePacket, PacketFramePayload(rec.TS.UnixNano(), rec.Raw)) {
				return
			}
			sent++
		}
	}
}

// negotiate applies the version rule and checks the bearer token and requested
// link type. ok=false carries the reject code and reason.
func negotiate(h ClientHello, cfg ServerConfig) (code RejectCode, reason string, ok bool) {
	if h.Version == 0 || h.Version > Version1 {
		return RejectVersion, "server speaks protocol version 1 only", false
	}
	if cfg.Token != "" {
		if subtle.ConstantTimeCompare([]byte(h.Token), []byte(cfg.Token)) != 1 {
			return RejectUnauthorized, "bad bearer token", false
		}
	}
	if h.LinkType != 0 && h.LinkType != cfg.LinkType {
		return RejectLinkType, "sensor stream is a different link-layer type", false
	}
	return RejectNone, "", true
}

func writeReject(conn net.Conn, cfg ServerConfig, rj ServerReject) {
	raw, err := rj.MarshalBinary()
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	_, _ = conn.Write(raw)
}

// newSessionID mints a random per-connection id, optionally prefixed with a
// caller-supplied label so a reverse connection can name the sensor it came
// from. The result is always within MaxSessionIDLen.
func newSessionID(prefix string) string {
	var b [8]byte
	id := "session"
	if _, err := io.ReadFull(rand.Reader, b[:]); err == nil {
		id = hex.EncodeToString(b[:])
	}
	if prefix != "" {
		id = prefix + "-" + id
	}
	if len(id) > MaxSessionIDLen {
		id = id[:MaxSessionIDLen]
	}
	return id
}
