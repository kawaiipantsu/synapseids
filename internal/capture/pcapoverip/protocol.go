// Package pcapoverip implements SYNPOIP, a small framed, authenticated and
// versioned transport for streaming raw capture records from a remote sensor to
// synapsed over a single TLS connection (PROJECT.md §6 "PCAP-over-IP", §21,
// §28.16). It carries the client handshake, the record framing, a reference
// server that replays a capture file over the wire, and an in-memory
// self-signed certificate helper for tests and local demos.
//
// The daemon is the client: it dials the sensor, authenticates with a bearer
// token inside the TLS tunnel, and reads packet frames. The wire format is
// specified byte-for-byte in PROTOCOL.md next to this file; the constants and
// codecs here are the single implementation of it.
//
// Nothing in this package trusts packet bytes: every frame is length-capped and
// bounds-checked, and decoding the frames into packets is left to
// packet.Decode, which already treats its input as hostile (PROJECT.md §28.11).
package pcapoverip

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Wire-level limits. They bound how much memory a single crafted peer message
// can make the other side allocate (PROJECT.md §21 "cap resource consumption").
const (
	// Magic is the 8-byte preamble that opens both the ClientHello and the
	// ServerResponse. The trailing NUL keeps it a fixed width and non-printable
	// enough to fail fast against a wrong protocol on the socket.
	Magic = "SYNPOIP\x00"

	// Version1 is the first (and, so far, only) protocol version.
	Version1 uint16 = 1

	// MaxTokenLen caps the bearer token in a ClientHello.
	MaxTokenLen = 512
	// MaxMetaLen caps the JSON metadata blob in a ClientHello.
	MaxMetaLen = 1 << 16
	// MaxReasonLen caps a reject or goodbye reason string.
	MaxReasonLen = 1024
	// MaxSessionIDLen caps the server-assigned session id in a ServerAccept.
	MaxSessionIDLen = 128
	// MaxFilterLen caps the server-advertised filter string in a ServerAccept.
	MaxFilterLen = 1024

	// MaxFramePayload caps a single post-handshake frame's payload: the
	// 262144-byte snaplen ceiling the pcap readers already enforce, plus slack
	// for the 8-byte timestamp prefix and small headroom. A frame that declares
	// more is a protocol error and the connection is dropped without allocating
	// the claimed size.
	MaxFramePayload = 262144 + 64
)

// magicLen is the fixed width of Magic.
const magicLen = len(Magic)

// FrameType identifies a post-handshake record frame.
type FrameType uint8

// Frame types carried after a successful handshake.
const (
	// FramePacket payload is a uint64 big-endian Unix-nanoseconds capture
	// timestamp followed by the raw link-layer frame bytes.
	FramePacket FrameType = 0x01
	// FrameKeepalive payload is empty, or exactly 16 bytes: a uint64 count of
	// packets the sender has produced followed by a uint64 kernel-drop counter.
	FrameKeepalive FrameType = 0x02
	// FrameGoodbye payload is an optional UTF-8 reason. Either peer may send it
	// to close the stream cleanly.
	FrameGoodbye FrameType = 0x03
)

func (t FrameType) String() string {
	switch t {
	case FramePacket:
		return "packet"
	case FrameKeepalive:
		return "keepalive"
	case FrameGoodbye:
		return "goodbye"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

// RejectCode is why a server declined a ClientHello. It travels in the single
// status byte of a ServerResponse; 0 means accepted.
type RejectCode uint8

// Reject codes. RejectNone (0) is the accept marker.
const (
	RejectNone         RejectCode = 0x00
	RejectVersion      RejectCode = 0x01 // unsupported protocol version
	RejectUnauthorized RejectCode = 0x02 // missing or wrong bearer token
	RejectBadRequest   RejectCode = 0x03 // malformed or oversized handshake
	RejectUnavailable  RejectCode = 0x04 // server shutting down / no capacity
	RejectLinkType     RejectCode = 0x05 // client demanded a link type the server cannot provide
)

func (c RejectCode) String() string {
	switch c {
	case RejectNone:
		return "ok"
	case RejectVersion:
		return "unsupported-version"
	case RejectUnauthorized:
		return "unauthorized"
	case RejectBadRequest:
		return "bad-request"
	case RejectUnavailable:
		return "unavailable"
	case RejectLinkType:
		return "link-type-unsupported"
	default:
		return fmt.Sprintf("reject(0x%02x)", uint8(c))
	}
}

// ErrProtocol is the class of every framing / handshake decode failure. Callers
// surface it as a single terminal error; they never retry a broken stream in
// this pass.
var ErrProtocol = errors.New("pcapoverip: protocol error")

func protoErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, a...))
}

// ClientHello is the first message on the wire, sent by the dialing daemon.
type ClientHello struct {
	// Version is the protocol version the client proposes. A server may accept
	// this or any lower version it still supports; a higher-than-known version
	// is rejected (see PROTOCOL.md).
	Version uint16
	// LinkType is the libpcap DLT the client prefers (1 EN10MB, 101 RAW). 0
	// means "accept whatever the server streams" — the ServerAccept is always
	// authoritative.
	LinkType uint32
	// Token is the bearer secret, carried only inside the TLS tunnel and never
	// logged.
	Token string
	// SensorID, Filter and Location are advisory metadata echoed into the
	// capture-sources view; they never affect what the server streams.
	SensorID string
	Filter   string
	Location string
}

type helloMeta struct {
	SensorID string `json:"sensor_id,omitempty"`
	Filter   string `json:"filter,omitempty"`
	Location string `json:"location,omitempty"`
}

// MarshalBinary encodes the ClientHello in wire form.
func (h ClientHello) MarshalBinary() ([]byte, error) {
	if len(h.Token) > MaxTokenLen {
		return nil, protoErr("token too long (%d > %d)", len(h.Token), MaxTokenLen)
	}
	meta, err := json.Marshal(helloMeta{SensorID: h.SensorID, Filter: h.Filter, Location: h.Location})
	if err != nil {
		return nil, protoErr("encoding metadata: %v", err)
	}
	if len(meta) > MaxMetaLen {
		return nil, protoErr("metadata too long (%d > %d)", len(meta), MaxMetaLen)
	}
	buf := make([]byte, 0, magicLen+2+4+2+len(h.Token)+4+len(meta))
	buf = append(buf, Magic...)
	buf = binary.BigEndian.AppendUint16(buf, h.Version)
	buf = binary.BigEndian.AppendUint32(buf, h.LinkType)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.Token)))
	buf = append(buf, h.Token...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(meta)))
	buf = append(buf, meta...)
	return buf, nil
}

// ReadClientHello decodes a ClientHello from r, enforcing every length cap.
func ReadClientHello(r io.Reader) (ClientHello, error) {
	var head [magicLen + 2 + 4 + 2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return ClientHello{}, ioErr("hello header", err)
	}
	if string(head[:magicLen]) != Magic {
		return ClientHello{}, protoErr("bad magic")
	}
	off := magicLen
	h := ClientHello{
		Version:  binary.BigEndian.Uint16(head[off:]),
		LinkType: binary.BigEndian.Uint32(head[off+2:]),
	}
	tokenLen := binary.BigEndian.Uint16(head[off+6:])
	if int(tokenLen) > MaxTokenLen {
		return ClientHello{}, protoErr("token length %d exceeds %d", tokenLen, MaxTokenLen)
	}
	token := make([]byte, tokenLen)
	if _, err := io.ReadFull(r, token); err != nil {
		return ClientHello{}, ioErr("hello token", err)
	}
	h.Token = string(token)

	var ml [4]byte
	if _, err := io.ReadFull(r, ml[:]); err != nil {
		return ClientHello{}, ioErr("hello metadata length", err)
	}
	metaLen := binary.BigEndian.Uint32(ml[:])
	if metaLen > MaxMetaLen {
		return ClientHello{}, protoErr("metadata length %d exceeds %d", metaLen, MaxMetaLen)
	}
	if metaLen > 0 {
		meta := make([]byte, metaLen)
		if _, err := io.ReadFull(r, meta); err != nil {
			return ClientHello{}, ioErr("hello metadata", err)
		}
		var m helloMeta
		if err := json.Unmarshal(meta, &m); err != nil {
			return ClientHello{}, protoErr("decoding metadata: %v", err)
		}
		h.SensorID, h.Filter, h.Location = m.SensorID, m.Filter, m.Location
	}
	return h, nil
}

// ServerAccept is the success reply to a ClientHello.
type ServerAccept struct {
	// Version is the negotiated protocol version (<= the client's proposal).
	Version uint16
	// LinkType is the authoritative libpcap DLT for every FramePacket that
	// follows.
	LinkType uint32
	// Filter is the human-readable capture filter the sensor is applying, or ""
	// for "everything". It is surfaced in the capture-sources view.
	Filter string
	// SessionID identifies this stream in server logs.
	SessionID string
}

// ServerReject is the failure reply to a ClientHello. The server closes the
// connection immediately after sending it.
type ServerReject struct {
	Code   RejectCode
	Reason string
}

// MarshalBinary encodes a ServerAccept in wire form.
func (a ServerAccept) MarshalBinary() ([]byte, error) {
	if len(a.Filter) > MaxFilterLen {
		return nil, protoErr("filter too long (%d > %d)", len(a.Filter), MaxFilterLen)
	}
	if len(a.SessionID) > MaxSessionIDLen {
		return nil, protoErr("session id too long (%d > %d)", len(a.SessionID), MaxSessionIDLen)
	}
	buf := make([]byte, 0, magicLen+1+2+4+2+len(a.Filter)+2+len(a.SessionID))
	buf = append(buf, Magic...)
	buf = append(buf, byte(RejectNone))
	buf = binary.BigEndian.AppendUint16(buf, a.Version)
	buf = binary.BigEndian.AppendUint32(buf, a.LinkType)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.Filter)))
	buf = append(buf, a.Filter...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.SessionID)))
	buf = append(buf, a.SessionID...)
	return buf, nil
}

// MarshalBinary encodes a ServerReject in wire form.
func (rj ServerReject) MarshalBinary() ([]byte, error) {
	reason := rj.Reason
	if len(reason) > MaxReasonLen {
		reason = reason[:MaxReasonLen]
	}
	buf := make([]byte, 0, magicLen+1+2+len(reason))
	buf = append(buf, Magic...)
	buf = append(buf, byte(rj.Code))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(reason)))
	buf = append(buf, reason...)
	return buf, nil
}

// RejectError is the terminal error a client surfaces when the server declines
// the handshake.
type RejectError struct {
	Code   RejectCode
	Reason string
}

func (e *RejectError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("pcapoverip: server rejected connection (%s)", e.Code)
	}
	return fmt.Sprintf("pcapoverip: server rejected connection (%s): %s", e.Code, e.Reason)
}

// ReadServerResponse decodes the server's reply to a ClientHello. Exactly one of
// the return values is non-nil on success: an accepted handshake yields
// (*ServerAccept, nil), a declined one yields (nil, *RejectError).
func ReadServerResponse(r io.Reader) (*ServerAccept, error) {
	var head [magicLen + 1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, ioErr("server response header", err)
	}
	if string(head[:magicLen]) != Magic {
		return nil, protoErr("bad magic in server response")
	}
	code := RejectCode(head[magicLen])
	if code != RejectNone {
		var rl [2]byte
		if _, err := io.ReadFull(r, rl[:]); err != nil {
			return nil, ioErr("reject reason length", err)
		}
		n := binary.BigEndian.Uint16(rl[:])
		if n > MaxReasonLen {
			return nil, protoErr("reject reason length %d exceeds %d", n, MaxReasonLen)
		}
		reason := make([]byte, n)
		if _, err := io.ReadFull(r, reason); err != nil {
			return nil, ioErr("reject reason", err)
		}
		return nil, &RejectError{Code: code, Reason: string(reason)}
	}

	var fixed [2 + 4 + 2]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, ioErr("accept header", err)
	}
	a := &ServerAccept{
		Version:  binary.BigEndian.Uint16(fixed[0:]),
		LinkType: binary.BigEndian.Uint32(fixed[2:]),
	}
	filterLen := binary.BigEndian.Uint16(fixed[6:])
	if filterLen > MaxFilterLen {
		return nil, protoErr("accept filter length %d exceeds %d", filterLen, MaxFilterLen)
	}
	filter := make([]byte, filterLen)
	if _, err := io.ReadFull(r, filter); err != nil {
		return nil, ioErr("accept filter", err)
	}
	a.Filter = string(filter)

	var sl [2]byte
	if _, err := io.ReadFull(r, sl[:]); err != nil {
		return nil, ioErr("accept session length", err)
	}
	sidLen := binary.BigEndian.Uint16(sl[:])
	if sidLen > MaxSessionIDLen {
		return nil, protoErr("accept session id length %d exceeds %d", sidLen, MaxSessionIDLen)
	}
	sid := make([]byte, sidLen)
	if _, err := io.ReadFull(r, sid); err != nil {
		return nil, ioErr("accept session id", err)
	}
	a.SessionID = string(sid)
	return a, nil
}

// WriteFrame writes one post-handshake frame: a type byte, a uint32 big-endian
// payload length, then the payload. It rejects an over-cap payload rather than
// putting a frame on the wire the peer must refuse.
func WriteFrame(w io.Writer, t FrameType, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return protoErr("frame payload %d exceeds %d", len(payload), MaxFramePayload)
	}
	var head [5]byte
	head[0] = byte(t)
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// FrameReader reads length-delimited frames off a connection into one reusable
// buffer. It is single-goroutine: call ReadFrame from one place.
type FrameReader struct {
	r   io.Reader
	buf []byte
}

// NewFrameReader wraps r. The initial buffer grows on demand up to
// MaxFramePayload.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r, buf: make([]byte, 0, 2048)}
}

// ReadFrame reads the next frame. The returned slice aliases the FrameReader's
// internal buffer and is only valid until the next ReadFrame call. A payload
// that claims more than MaxFramePayload is an ErrProtocol and nothing that
// large is allocated.
func (fr *FrameReader) ReadFrame() (FrameType, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(fr.r, head[:]); err != nil {
		return 0, nil, ioErr("frame header", err)
	}
	t := FrameType(head[0])
	n := binary.BigEndian.Uint32(head[1:])
	if n > MaxFramePayload {
		return 0, nil, protoErr("frame payload %d exceeds %d", n, MaxFramePayload)
	}
	if n == 0 {
		return t, nil, nil
	}
	if cap(fr.buf) < int(n) {
		fr.buf = make([]byte, n)
	}
	fr.buf = fr.buf[:n]
	if _, err := io.ReadFull(fr.r, fr.buf); err != nil {
		return 0, nil, ioErr("frame payload", err)
	}
	return t, fr.buf, nil
}

// PacketFramePayload builds a FramePacket payload from a timestamp and raw
// frame bytes.
func PacketFramePayload(tsUnixNano int64, raw []byte) []byte {
	out := make([]byte, 8+len(raw))
	binary.BigEndian.PutUint64(out[:8], uint64(tsUnixNano))
	copy(out[8:], raw)
	return out
}

// ParsePacketFrame splits a FramePacket payload into its timestamp and raw
// frame bytes. The returned slice aliases payload.
func ParsePacketFrame(payload []byte) (tsUnixNano int64, raw []byte, err error) {
	if len(payload) < 8 {
		return 0, nil, protoErr("packet frame payload %d bytes, need >= 8", len(payload))
	}
	return int64(binary.BigEndian.Uint64(payload[:8])), payload[8:], nil
}

// KeepalivePayload builds the optional 16-byte keepalive body carrying the
// sender's packet and drop counters.
func KeepalivePayload(packets, drops uint64) []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[:8], packets)
	binary.BigEndian.PutUint64(out[8:], drops)
	return out
}

// ParseKeepalive reads a keepalive body. An empty body is valid and reports
// zeroes with ok=false.
func ParseKeepalive(payload []byte) (packets, drops uint64, ok bool) {
	if len(payload) < 16 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(payload[:8]), binary.BigEndian.Uint64(payload[8:16]), true
}

func ioErr(what string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return fmt.Errorf("pcapoverip: reading %s: %w", what, err)
}
