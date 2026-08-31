package pcapoverip

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/flow"
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
	// Mode is what this sensor ships (PROJECT.md §5.3). ModeRaw is the v1
	// behaviour and the default: the raw StreamFunc is written straight out as
	// FramePacket frames, byte for byte as before.
	//
	// ModeFlow and ModeFeature need SYNPOIP v2. The raw stream is wrapped in
	// Aggregate, which runs the flow engine (and, for ModeFeature, feature
	// extraction) here on the sensor. A client that did not advertise a v2
	// ceiling is refused with RejectMode rather than silently downgraded to raw —
	// a feature-mode sensor quietly shipping packet content would break the very
	// property the operator selected the mode for.
	Mode Mode
	// Flow is the flow-table lifecycle configuration used by ModeFlow and
	// ModeFeature. It should match the daemon's, so the same capture yields the
	// same flows whichever mode carries it.
	Flow flow.Options
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
	// WriteTimeout bounds one batch of frame writes. 0 uses
	// DefaultWriteTimeout.
	WriteTimeout time.Duration
	// WriteBufferSize is the outbound batching buffer per connection. 0 uses
	// DefaultWriteBufferSize. Frames are coalesced into it while the source is
	// backlogged and flushed the moment it is not, so the buffer only ever
	// trades syscalls for throughput, never latency (see ADR 0029).
	WriteBufferSize int
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
	if c.WriteBufferSize <= 0 {
		c.WriteBufferSize = DefaultWriteBufferSize
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

	version, code, reason, ok := negotiate(hello, cfg)
	if !ok {
		cfg.Logf("pcapoverip: %s: rejected (%s)", remote, code)
		writeReject(conn, cfg, ServerReject{Code: code, Reason: reason})
		return
	}

	sid := newSessionID(cfg.SessionPrefix)
	acc := ServerAccept{Version: version, LinkType: cfg.LinkType, Filter: cfg.Filter, SessionID: sid}
	if version >= Version2 {
		acc.Mode = cfg.Mode
		acc.PayloadSchema = cfg.Mode.PayloadSchema()
	}
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
	cfg.Logf("pcapoverip: %s: session %s started (sensor=%q link=%d protocol=v%d mode=%s schema=%q)",
		remote, sid, hello.SensorID, cfg.LinkType, version, cfg.Mode, acc.PayloadSchema)

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

	ka := time.NewTicker(cfg.KeepaliveInterval)
	defer ka.Stop()

	// Outbound frames are batched into one buffer and flushed as soon as the
	// source has nothing else ready (ADR 0029). The wire bytes are identical;
	// only the TLS record and syscall boundaries move. The deferred flush is the
	// backstop for any path that returns without one — it runs before the
	// deferred conn.Close above it.
	w := newFrameWriter(conn, cfg.WriteBufferSize, cfg.WriteTimeout)
	defer func() { _ = w.flush() }()

	var sent uint64
	fail := func(werr error) bool {
		cfg.Logf("pcapoverip: %s: session %s write: %v", remote, sid, werr)
		cancel()
		return false
	}
	// write queues a data frame; it may sit in the buffer until flush.
	write := func(ft FrameType, payload []byte) bool {
		if werr := w.writeFrame(ft, payload); werr != nil {
			return fail(werr)
		}
		return true
	}
	// control queues a control frame and flushes it, together with everything
	// already queued behind it.
	control := func(ft FrameType, payload []byte) bool {
		if werr := w.writeControl(ft, payload); werr != nil {
			return fail(werr)
		}
		return true
	}
	flush := func() bool {
		if werr := w.flush(); werr != nil {
			return fail(werr)
		}
		return true
	}
	bye := func(reason string) {
		_ = w.writeControl(FrameGoodbye, []byte(reason))
	}

	// Record modes take the aggregation path: the flow engine (and, for
	// ModeFeature, feature extraction) runs here and only encoded records go out.
	if cfg.Mode != ModeRaw {
		frames, aerrc := Aggregate(AggregateConfig{
			Mode: cfg.Mode, LinkType: cfg.LinkType, Flow: cfg.Flow, Logf: cfg.Logf,
		}, stream)(connCtx)

		for {
			select {
			case <-connCtx.Done():
				bye("server closing")
				cfg.Logf("pcapoverip: %s: session %s closed (%d %s record(s))", remote, sid, sent, cfg.Mode)
				return

			case <-ka.C:
				if !control(FrameKeepalive, KeepalivePayload(sent, cfg.Drops())) {
					return
				}

			case rerr := <-aerrc:
				if rerr != nil && !errors.Is(rerr, context.Canceled) {
					bye("source error: " + rerr.Error())
					cfg.Logf("pcapoverip: %s: session %s source error: %v", remote, sid, rerr)
					return
				}

			case f, fok := <-frames:
				if !fok {
					bye("end of capture")
					cfg.Logf("pcapoverip: %s: session %s end of capture (%d %s record(s))", remote, sid, sent, cfg.Mode)
					return
				}
				if !write(f.Type, f.Payload) {
					return
				}
				sent++

				// Coalesce whatever the aggregator already has queued, then
				// flush. A record burst (a flow table flushing many closed flows
				// at once) becomes one batch; a single record on a quiet link is
				// still on the wire before this iteration ends.
			drainRecords:
				for !w.full() {
					select {
					case f, fok = <-frames:
						if !fok {
							bye("end of capture")
							cfg.Logf("pcapoverip: %s: session %s end of capture (%d %s record(s))", remote, sid, sent, cfg.Mode)
							return
						}
						if !write(f.Type, f.Payload) {
							return
						}
						sent++
					default:
						break drainRecords
					}
				}
				if !flush() {
					return
				}
			}
		}
	}

	records, errc := stream(connCtx)

	// writePacket queues one raw record, skipping an over-cap frame as before.
	// false means the write failed and the session is over.
	writePacket := func(rec Record) bool {
		if len(rec.Raw) > MaxFramePayload-8 {
			return true // a single frame larger than the ceiling is dropped, not fatal
		}
		if werr := w.writePacketFrame(rec.TS.UnixNano(), rec.Raw); werr != nil {
			return fail(werr)
		}
		sent++
		return true
	}

	for {
		select {
		case <-connCtx.Done():
			bye("server closing")
			cfg.Logf("pcapoverip: %s: session %s closed (%d packets)", remote, sid, sent)
			return

		case <-ka.C:
			if !control(FrameKeepalive, KeepalivePayload(sent, cfg.Drops())) {
				return
			}

		case rerr := <-errc:
			if rerr != nil && !errors.Is(rerr, context.Canceled) {
				bye("source error: " + rerr.Error())
				cfg.Logf("pcapoverip: %s: session %s source error: %v", remote, sid, rerr)
				return
			}

		case rec, ok := <-records:
			if !ok {
				bye("end of capture")
				cfg.Logf("pcapoverip: %s: session %s end of capture (%d packets)", remote, sid, sent)
				return
			}
			if !writePacket(rec) {
				return
			}

			// Batch while the source is backlogged; flush the moment it is not.
			// The non-blocking receive is the whole policy: it succeeds only if a
			// record is *already* waiting (buffered or a blocked sender), so a
			// quiet link never sits on a packet, and a saturated one turns a
			// burst into one flush instead of one syscall pair per frame
			// (PROJECT.md §17, §22; ADR 0029).
		drainPackets:
			for !w.full() {
				select {
				case rec, ok = <-records:
					if !ok {
						bye("end of capture")
						cfg.Logf("pcapoverip: %s: session %s end of capture (%d packets)", remote, sid, sent)
						return
					}
					if !writePacket(rec) {
						return
					}
				default:
					break drainPackets
				}
			}
			if !flush() {
				return
			}
		}
	}
}

// negotiate applies the version rule, checks the bearer token and the requested
// link type, and confirms the client can receive this sensor's mode. ok=false
// carries the reject code and reason; ok=true carries the version in force.
func negotiate(h ClientHello, cfg ServerConfig) (version uint16, code RejectCode, reason string, ok bool) {
	if h.Version == 0 || h.Version > VersionMax {
		return 0, RejectVersion, fmt.Sprintf("server speaks protocol versions 1..%d", VersionMax), false
	}
	// The client's baseline is the fixed Version field; its ceiling is the
	// "max_version" capability in the hello metadata, which a v1 client never
	// sends. Pick the highest version both ends can speak (PROTOCOL.md §2.3).
	version = h.Ceiling()
	if version > VersionMax {
		version = VersionMax
	}

	if cfg.Token != "" {
		if subtle.ConstantTimeCompare([]byte(h.Token), []byte(cfg.Token)) != 1 {
			return 0, RejectUnauthorized, "bad bearer token", false
		}
	}
	if h.LinkType != 0 && h.LinkType != cfg.LinkType {
		return 0, RejectLinkType, "sensor stream is a different link-layer type", false
	}
	if version < cfg.Mode.MinVersion() {
		return 0, RejectMode, fmt.Sprintf(
			"sensor is in %s mode, which needs SYNPOIP v%d; the client offered at most v%d",
			cfg.Mode, cfg.Mode.MinVersion(), version), false
	}
	return version, RejectNone, "", true
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
