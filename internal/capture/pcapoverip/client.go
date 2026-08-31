package pcapoverip

import (
	"net"
	"sync"
	"time"
)

// Session is an established client side of a SYNPOIP stream. It owns the
// connection: reads happen from one goroutine via ReadFrame, writes (keepalive,
// goodbye) are serialised with an internal mutex so a keepalive ticker and a
// Close can race safely.
type Session struct {
	conn    net.Conn
	fr      *FrameReader
	accept  ServerAccept
	writeTO time.Duration
	mu      sync.Mutex
	closed  bool
}

// ClientHandshake performs the SYNPOIP handshake over conn (already a
// *tls.Conn). It writes hello, reads the server response, and returns a live
// Session on accept. A declined handshake returns a *RejectError. deadline
// bounds the whole exchange; it is cleared before the Session is returned so
// the caller controls per-read deadlines afterwards.
func ClientHandshake(conn net.Conn, hello ClientHello, deadline time.Time) (*Session, error) {
	_ = conn.SetDeadline(deadline)

	raw, err := hello.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	acc, err := ReadServerResponse(conn)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return &Session{
		conn:    conn,
		fr:      NewFrameReader(conn),
		accept:  *acc,
		writeTO: 10 * time.Second,
	}, nil
}

// LinkType is the authoritative libpcap DLT the server negotiated.
func (s *Session) LinkType() uint32 { return s.accept.LinkType }

// Accept is the ServerAccept this session was established on. Callers pass it to
// ValidateAccept before consuming a single frame.
func (s *Session) Accept() ServerAccept { return s.accept }

// Mode is what the sensor declared it is shipping. A v1 accept carries no mode
// field and always means ModeRaw.
func (s *Session) Mode() Mode { return s.accept.Mode }

// PayloadSchema is the frozen schema id the sensor's record frames conform to,
// or "" in raw mode.
func (s *Session) PayloadSchema() string { return s.accept.PayloadSchema }

// NegotiatedVersion is the protocol version in force for this session.
func (s *Session) NegotiatedVersion() uint16 { return s.accept.Version }

// Filter is the capture filter string the server advertised ("" = everything).
func (s *Session) Filter() string { return s.accept.Filter }

// SessionID is the server-assigned identifier for this stream.
func (s *Session) SessionID() string { return s.accept.SessionID }

// ReadFrame reads the next frame, arming a read deadline of idle from now so a
// silent server surfaces as a timeout rather than a hang. idle <= 0 disables
// the deadline.
func (s *Session) ReadFrame(idle time.Duration) (FrameType, []byte, error) {
	if idle > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(idle))
	}
	return s.fr.ReadFrame()
}

// WriteKeepalive sends an empty keepalive frame. It is safe to call concurrently
// with Close.
func (s *Session) WriteKeepalive() error {
	return s.write(FrameKeepalive, nil)
}

// WriteGoodbye sends a goodbye frame with an optional reason.
func (s *Session) WriteGoodbye(reason string) error {
	return s.write(FrameGoodbye, []byte(reason))
}

func (s *Session) write(t FrameType, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeTO))
	return WriteFrame(s.conn, t, payload)
}

// Close closes the connection. It is idempotent and unblocks a ReadFrame in
// flight.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.conn.Close()
}
