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

	// Version1 is the first protocol version: raw packet frames only.
	Version1 uint16 = 1

	// Version2 adds the sensor record modes (issue #45): the ServerAccept
	// declares a Mode and the schema id of its payloads, and the stream may carry
	// FrameFlowRecord / FrameFeatureRecord instead of FramePacket.
	//
	// The *fixed* version field of a ClientHello stays at Version1 forever,
	// because a v1 server rejects any higher value outright (RejectVersion) and
	// there is no way to retry inside one accepted connection. A client that can
	// speak v2 therefore keeps proposing 1 in the fixed field and advertises its
	// ceiling as "max_version" in the hello metadata, which a v1 server ignores.
	// See PROTOCOL.md §2.3.
	Version2 uint16 = 2

	// VersionMax is the highest version this implementation speaks.
	VersionMax = Version2

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
	// MaxSchemaLen caps the payload schema id in a v2 ServerAccept.
	MaxSchemaLen = 128

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
	// FrameFlowRecord carries one remotely-aggregated flow.Record. v2 and
	// ModeFlow only; see records.go for the layout.
	FrameFlowRecord FrameType = 0x04
	// FrameFeatureRecord carries one flow-features-v1 vector plus the minimal
	// flow identity needed to render and store a row — and no packet content at
	// all. v2 and ModeFeature only; see records.go for the layout.
	FrameFeatureRecord FrameType = 0x05
)

func (t FrameType) String() string {
	switch t {
	case FramePacket:
		return "packet"
	case FrameKeepalive:
		return "keepalive"
	case FrameGoodbye:
		return "goodbye"
	case FrameFlowRecord:
		return "flow-record"
	case FrameFeatureRecord:
		return "feature-record"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

// Mode is what a sensor puts on the wire (PROJECT.md §5.3). It is chosen by the
// sensor, declared in the v2 ServerAccept, and decides which frame types the
// stream carries.
type Mode uint8

// Sensor modes.
const (
	// ModeRaw streams FramePacket records: every captured frame crosses the
	// wire. The v1 behaviour, and the default.
	ModeRaw Mode = 0x00
	// ModeFlow runs the flow engine on the sensor and streams FrameFlowRecord.
	// The daemon does not re-run its flow table over them.
	ModeFlow Mode = 0x01
	// ModeFeature runs the flow engine *and* feature extraction on the sensor and
	// streams FrameFeatureRecord: only the 48 derived numbers plus the flow
	// identity needed to render a row. No packet content crosses the wire.
	ModeFeature Mode = 0x02
)

func (m Mode) String() string {
	switch m {
	case ModeRaw:
		return "raw"
	case ModeFlow:
		return "flow"
	case ModeFeature:
		return "feature"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(m))
	}
}

// ParseMode maps a mode name to a Mode. "" and "raw" are ModeRaw.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "raw":
		return ModeRaw, nil
	case "flow":
		return ModeFlow, nil
	case "feature":
		return ModeFeature, nil
	default:
		return ModeRaw, fmt.Errorf("pcapoverip: unknown sensor mode %q (want raw, flow or feature)", s)
	}
}

// MinVersion is the lowest protocol version that can carry this mode.
func (m Mode) MinVersion() uint16 {
	if m == ModeRaw {
		return Version1
	}
	return Version2
}

// PayloadSchema is the frozen schema id a mode's record frames conform to, or ""
// for ModeRaw (whose payload is a link-layer frame, described by link_type).
func (m Mode) PayloadSchema() string {
	switch m {
	case ModeFlow:
		return FlowRecordSchema
	case ModeFeature:
		return FeatureRecordSchema
	default:
		return ""
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
	RejectMode         RejectCode = 0x06 // sensor is in flow/feature mode and the client cannot receive it
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
	case RejectMode:
		return "mode-unsupported"
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
	// MaxVersion is the highest version the client can be upgraded to. It travels
	// in the hello metadata as "max_version", *not* in the fixed Version field,
	// so a v1 server ignores it and accepts at version 1 instead of rejecting the
	// whole handshake (PROTOCOL.md §2.3). 0 or a value below Version means
	// "Version only".
	MaxVersion uint16
	// SensorID, Filter and Location are advisory metadata echoed into the
	// capture-sources view; they never affect what the server streams.
	SensorID string
	Filter   string
	Location string
}

// Ceiling is the highest version this hello can be upgraded to.
func (h ClientHello) Ceiling() uint16 {
	if h.MaxVersion > h.Version {
		return h.MaxVersion
	}
	return h.Version
}

type helloMeta struct {
	SensorID string `json:"sensor_id,omitempty"`
	Filter   string `json:"filter,omitempty"`
	Location string `json:"location,omitempty"`
	// MaxVersion is the SYNPOIP v2 capability advertisement. A v1 server decodes
	// the metadata into this same struct minus the field and silently drops it,
	// which is exactly the backward compatibility this extension point buys.
	MaxVersion uint16 `json:"max_version,omitempty"`
}

// MarshalBinary encodes the ClientHello in wire form.
func (h ClientHello) MarshalBinary() ([]byte, error) {
	if len(h.Token) > MaxTokenLen {
		return nil, protoErr("token too long (%d > %d)", len(h.Token), MaxTokenLen)
	}
	max := h.MaxVersion
	if max <= h.Version {
		max = 0 // omit rather than restate the fixed field
	}
	meta, err := json.Marshal(helloMeta{
		SensorID: h.SensorID, Filter: h.Filter, Location: h.Location, MaxVersion: max,
	})
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
		if m.MaxVersion > h.Version {
			h.MaxVersion = m.MaxVersion
		}
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

	// Mode is what the sensor is shipping. It is encoded only when Version >=
	// Version2; a v1 accept is byte-identical to what it always was and always
	// means ModeRaw.
	Mode Mode
	// PayloadSchema is the frozen schema id every record frame conforms to:
	// "flow-record-v1" for ModeFlow, "flow-features-v1" for ModeFeature, "" for
	// ModeRaw. The receiver compares it with the schema it implements and refuses
	// the session on a mismatch rather than misreading the records (PROJECT.md
	// §28.5-6). Encoded only when Version >= Version2.
	PayloadSchema string
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
	if len(a.PayloadSchema) > MaxSchemaLen {
		return nil, protoErr("payload schema too long (%d > %d)", len(a.PayloadSchema), MaxSchemaLen)
	}
	if a.Version < Version2 && a.Mode != ModeRaw {
		return nil, protoErr("mode %s needs protocol version %d, not %d", a.Mode, Version2, a.Version)
	}
	buf := make([]byte, 0, magicLen+1+2+4+2+len(a.Filter)+2+len(a.SessionID)+1+2+len(a.PayloadSchema))
	buf = append(buf, Magic...)
	buf = append(buf, byte(RejectNone))
	buf = binary.BigEndian.AppendUint16(buf, a.Version)
	buf = binary.BigEndian.AppendUint32(buf, a.LinkType)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.Filter)))
	buf = append(buf, a.Filter...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.SessionID)))
	buf = append(buf, a.SessionID...)
	// v2 tail. A v1 client would read these bytes as a frame header, so they are
	// written only when the client asked to be upgraded and the server answered
	// with Version2 — see PROTOCOL.md §2.3.
	if a.Version >= Version2 {
		buf = append(buf, byte(a.Mode))
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.PayloadSchema)))
		buf = append(buf, a.PayloadSchema...)
	}
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

	if a.Version < Version2 {
		return a, nil
	}
	var mh [1 + 2]byte
	if _, err := io.ReadFull(r, mh[:]); err != nil {
		return nil, ioErr("accept mode", err)
	}
	a.Mode = Mode(mh[0])
	schemaLen := binary.BigEndian.Uint16(mh[1:])
	if schemaLen > MaxSchemaLen {
		return nil, protoErr("accept payload schema length %d exceeds %d", schemaLen, MaxSchemaLen)
	}
	schema := make([]byte, schemaLen)
	if _, err := io.ReadFull(r, schema); err != nil {
		return nil, ioErr("accept payload schema", err)
	}
	a.PayloadSchema = string(schema)
	return a, nil
}

// ValidateAccept checks the negotiated version, mode and payload schema against
// what this build implements. A schema id this daemon does not implement is a
// hard refusal, not a best-effort read: a future flow-features-v2 sensor must be
// rejected rather than silently misread (PROJECT.md §28.5-6, the same discipline
// schema.ValidateBundle applies to a model bundle).
func ValidateAccept(a ServerAccept) error {
	if a.Version == 0 || a.Version > VersionMax {
		return protoErr("server negotiated protocol version %d, this build speaks 1..%d", a.Version, VersionMax)
	}
	switch a.Mode {
	case ModeRaw, ModeFlow, ModeFeature:
	default:
		return protoErr("server declared unknown mode 0x%02x", uint8(a.Mode))
	}
	if a.Version < a.Mode.MinVersion() {
		return protoErr("mode %s needs protocol version %d, server negotiated %d", a.Mode, a.Mode.MinVersion(), a.Version)
	}
	// A v1 accept carries no schema field at all; only hold a v2 peer to it.
	if a.Version >= Version2 {
		if want := a.Mode.PayloadSchema(); a.PayloadSchema != want {
			return protoErr("server declared payload schema %q for mode %s, this build implements %q — refusing the session rather than misreading its records",
				a.PayloadSchema, a.Mode, want)
		}
	}
	return nil
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
