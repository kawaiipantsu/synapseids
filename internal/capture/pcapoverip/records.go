package pcapoverip

// SYNPOIP v2 record frames (issue #45, PROJECT.md §5.3).
//
// A `flow`-mode sensor runs internal/flow locally and ships FrameFlowRecord
// (0x04); a `feature`-mode sensor also runs internal/features and ships
// FrameFeatureRecord (0x05), which contains **no packet content whatsoever** —
// only the 48 derived numbers and the flow identity needed to render a row.
//
// Both payloads are explicitly versioned twice over:
//
//   - the *session* is bound to a schema id in the v2 ServerAccept
//     ("flow-record-v1" / "flow-features-v1"), validated once at handshake time
//     by ValidateAccept, so a future flow-features-v2 sensor talking to a v1
//     daemon is refused rather than misread;
//   - every *frame* opens with a one-byte layout version, so a record from a
//     peer that somehow slipped past the handshake check is counted and skipped
//     instead of being decoded against the wrong offsets.
//
// The schema string is deliberately not repeated in every frame: it is a
// per-session property, and ~20 bytes per record of restated constant is exactly
// the bandwidth these modes exist to save.
//
// Every length is bounds-checked before anything is allocated or indexed, and a
// malformed record is an error the caller counts and skips — never a panic
// (PROJECT.md §21, §28.11).

import (
	"encoding/binary"
	"math"
	"net/netip"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Schema ids the record frames are bound to. They are the frozen ids owned by
// internal/flow and internal/features; this package never invents its own.
const (
	// FlowRecordSchema is the field layout of a FrameFlowRecord payload.
	FlowRecordSchema = flow.RecordSchemaV1
	// FeatureRecordSchema is the schema of the vector in a FrameFeatureRecord.
	FeatureRecordSchema = features.SchemaID
)

// Per-frame layout versions. Bump only alongside a new schema id.
const (
	flowRecordLayoutV1    uint8 = 1
	featureRecordLayoutV1 uint8 = 1
)

// Close-reason wire codes. flow.CloseReason is a string on the inside; on the
// wire it is one byte. Never renumber these.
const (
	reasonWireSnapshot uint8 = 1
	reasonWireFINRST   uint8 = 2
	reasonWireIdle     uint8 = 3
	reasonWireMaxLife  uint8 = 4
	reasonWireCapEnd   uint8 = 5
	reasonWireEvicted  uint8 = 6
)

func reasonToWire(r flow.CloseReason) uint8 {
	switch r {
	case flow.ReasonSnapshot:
		return reasonWireSnapshot
	case flow.ReasonFINRST:
		return reasonWireFINRST
	case flow.ReasonIdle:
		return reasonWireIdle
	case flow.ReasonMaxLife:
		return reasonWireMaxLife
	case flow.ReasonCapEnd:
		return reasonWireCapEnd
	case flow.ReasonEvicted:
		return reasonWireEvicted
	default:
		return 0
	}
}

func reasonFromWire(b uint8) (flow.CloseReason, bool) {
	switch b {
	case reasonWireSnapshot:
		return flow.ReasonSnapshot, true
	case reasonWireFINRST:
		return flow.ReasonFINRST, true
	case reasonWireIdle:
		return flow.ReasonIdle, true
	case reasonWireMaxLife:
		return flow.ReasonMaxLife, true
	case reasonWireCapEnd:
		return flow.ReasonCapEnd, true
	case reasonWireEvicted:
		return flow.ReasonEvicted, true
	default:
		return "", false
	}
}

// FeatureRecord is what a feature-mode sensor ships: one flow-features-v1 vector
// plus the minimum flow identity a daemon needs to store the row, join it to a
// classification and render it in the rolling log.
//
// The minimum is justified by what the receiving side actually consumes. The
// endpoints are the only thing not already in the vector — packet and byte
// counts, the duration and both ports are feature values 0..4, 21 and 22, so
// re-sending them would be pure waste — while §8 deliberately keeps IP addresses
// *out* of the feature vector, so they have to travel beside it. Absolute
// timestamps travel because the vector holds only a duration and the UI needs
// wall-clock. Proto travels as a byte because features 23..25 collapse ICMP and
// ICMPv6 into one indicator.
type FeatureRecord struct {
	// SensorFlowID is the *sensor's* flow id. The daemon remaps it through its
	// own allocator and keeps this as provenance metadata (CLAUDE.md: flow ids
	// must be globally unique across the daemon's lifetime).
	SensorFlowID  uint64
	Proto         packet.Proto
	Reason        flow.CloseReason
	SnapshotIndex int
	InitiatorIP   netip.Addr
	InitiatorPort uint16
	ResponderIP   netip.Addr
	ResponderPort uint16
	FirstSeen     time.Time
	LastSeen      time.Time
	Values        [features.Size]float64
}

// SensorRecord is one decoded record frame handed to the daemon's data plane.
// Exactly one of Flow and Feature is non-nil. Sensor and Location are filled in
// by the receiving side (the collector or the dialled source), not by the codec.
type SensorRecord struct {
	Sensor   string
	Location string
	Mode     Mode
	// WireBytes is the encoded payload size this record arrived as, so the
	// capture-sources view can report record-mode throughput honestly instead of
	// pretending packets crossed the wire.
	WireBytes int
	Flow      *flow.Record
	Feature   *FeatureRecord
}

// ---------------------------------------------------------------- encoding ---

type buf struct{ b []byte }

func (w *buf) u8(v uint8)     { w.b = append(w.b, v) }
func (w *buf) u16(v uint16)   { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32)   { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *buf) u64(v uint64)   { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *buf) i64(v int64)    { w.u64(uint64(v)) }
func (w *buf) f64(v float64)  { w.u64(math.Float64bits(v)) }
func (w *buf) ts(t time.Time) { w.i64(t.UnixNano()) }
func (w *buf) addr(a netip.Addr) {
	if !a.IsValid() {
		w.u8(0)
		return
	}
	s := a.Unmap().AsSlice()
	w.u8(uint8(len(s)))
	w.b = append(w.b, s...)
}

// EncodeFlowRecord builds a FrameFlowRecord payload. The field order below is
// the released flow-record-v1 layout; PROTOCOL.md §3.4 restates it.
func EncodeFlowRecord(r flow.Record) []byte {
	a := r.Accumulators()
	w := &buf{b: make([]byte, 0, 320)}

	w.u8(flowRecordLayoutV1)
	w.u8(uint8(r.Proto))
	w.u8(reasonToWire(r.Reason))
	w.u8(0) // reserved, must be 0
	w.u32(uint32(r.SnapshotIndex))
	w.u64(r.ID)
	w.ts(r.FirstSeen)
	w.ts(r.LastSeen)

	w.addr(r.InitiatorIP)
	w.u16(r.InitiatorPort)
	w.addr(r.ResponderIP)
	w.u16(r.ResponderPort)

	w.u64(r.FwdPackets)
	w.u64(r.BwdPackets)
	w.u64(r.FwdBytes)
	w.u64(r.BwdBytes)
	w.u64(r.FwdPayload)
	w.u64(r.BwdPayload)

	w.u32(uint32(int32(r.PktSizeMin)))
	w.u32(uint32(int32(r.PktSizeMax)))
	w.u64(r.SmallPkts)
	w.u64(r.LargePkts)

	w.u64(r.SynCount)
	w.u64(r.AckCount)
	w.u64(r.FinCount)
	w.u64(r.RstCount)
	w.u64(r.PshCount)
	w.u64(r.UrgCount)

	w.u32(r.InitialWindow)
	w.u64(a.WindowCount)
	w.u64(a.IATCount)
	w.u64(a.FwdIATCount)
	w.u64(a.BwdIATCount)

	w.f64(a.PktSizeSum)
	w.f64(a.PktSizeSumSq)
	w.f64(a.FwdSizeSum)
	w.f64(a.BwdSizeSum)
	w.f64(a.WindowSum)
	w.f64(a.IATSum)
	w.f64(a.IATSumSq)
	w.f64(a.IATMin)
	w.f64(a.IATMax)
	w.f64(a.FwdIATSum)
	w.f64(a.BwdIATSum)

	return w.b
}

// EncodeFeatureRecord builds a FrameFeatureRecord payload.
func EncodeFeatureRecord(fr FeatureRecord) []byte {
	w := &buf{b: make([]byte, 0, 448)}

	w.u8(featureRecordLayoutV1)
	w.u8(uint8(fr.Proto))
	w.u8(reasonToWire(fr.Reason))
	w.u8(0) // reserved, must be 0
	w.u32(uint32(fr.SnapshotIndex))
	w.u64(fr.SensorFlowID)
	w.ts(fr.FirstSeen)
	w.ts(fr.LastSeen)

	w.addr(fr.InitiatorIP)
	w.u16(fr.InitiatorPort)
	w.addr(fr.ResponderIP)
	w.u16(fr.ResponderPort)

	w.u16(features.Size)
	for _, v := range fr.Values {
		w.f64(v)
	}
	return w.b
}

// ---------------------------------------------------------------- decoding ---

// cur is a bounds-checked cursor over a received payload. Every read either
// consumes exactly what it asked for or sets err and returns a zero value, so a
// truncated or crafted record can never index out of range.
type cur struct {
	b   []byte
	i   int
	err error
}

func (c *cur) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || c.i+n > len(c.b) {
		c.err = protoErr("record truncated: need %d more byte(s) at offset %d of %d", n, c.i, len(c.b))
		return nil
	}
	s := c.b[c.i : c.i+n]
	c.i += n
	return s
}

func (c *cur) u8() uint8 {
	s := c.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}

func (c *cur) u16() uint16 {
	s := c.take(2)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint16(s)
}

func (c *cur) u32() uint32 {
	s := c.take(4)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint32(s)
}

func (c *cur) u64() uint64 {
	s := c.take(8)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint64(s)
}

func (c *cur) i64() int64   { return int64(c.u64()) }
func (c *cur) f64() float64 { return math.Float64frombits(c.u64()) }

func (c *cur) ts() time.Time {
	v := c.i64()
	if c.err != nil {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}

func (c *cur) addr() netip.Addr {
	n := c.u8()
	switch n {
	case 0:
		return netip.Addr{}
	case 4, 16:
	default:
		if c.err == nil {
			c.err = protoErr("record address length %d is not 0, 4 or 16", n)
		}
		return netip.Addr{}
	}
	s := c.take(int(n))
	if s == nil {
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(s)
	if !ok {
		c.err = protoErr("record address is not a valid %d-byte address", n)
		return netip.Addr{}
	}
	return a
}

// done reports a trailing-garbage error. A record longer than its layout is as
// suspicious as one that is too short: refuse it rather than guess.
func (c *cur) done() error {
	if c.err != nil {
		return c.err
	}
	if c.i != len(c.b) {
		return protoErr("record has %d trailing byte(s) after a complete body", len(c.b)-c.i)
	}
	return nil
}

// DecodeFlowRecord parses a FrameFlowRecord payload into a flow.Record whose
// private accumulators are restored, so features.Extract on the daemon yields
// exactly what it would have on the sensor. Record.ID is the *sensor's* id; the
// caller remaps it.
func DecodeFlowRecord(payload []byte) (flow.Record, error) {
	c := &cur{b: payload}
	if v := c.u8(); v != flowRecordLayoutV1 {
		if c.err != nil {
			return flow.Record{}, c.err
		}
		return flow.Record{}, protoErr("flow record layout version %d, want %d (%s)", v, flowRecordLayoutV1, FlowRecordSchema)
	}

	var r flow.Record
	r.Proto = packet.Proto(c.u8())
	reason, ok := reasonFromWire(c.u8())
	if !ok && c.err == nil {
		return flow.Record{}, protoErr("flow record carries an unknown close reason")
	}
	r.Reason = reason
	if rsv := c.u8(); rsv != 0 && c.err == nil {
		return flow.Record{}, protoErr("flow record reserved byte is 0x%02x, want 0", rsv)
	}
	r.SnapshotIndex = int(int32(c.u32()))
	r.ID = c.u64()
	r.FirstSeen = c.ts()
	r.LastSeen = c.ts()

	r.InitiatorIP = c.addr()
	r.InitiatorPort = c.u16()
	r.ResponderIP = c.addr()
	r.ResponderPort = c.u16()

	r.FwdPackets = c.u64()
	r.BwdPackets = c.u64()
	r.FwdBytes = c.u64()
	r.BwdBytes = c.u64()
	r.FwdPayload = c.u64()
	r.BwdPayload = c.u64()

	r.PktSizeMin = int(int32(c.u32()))
	r.PktSizeMax = int(int32(c.u32()))
	r.SmallPkts = c.u64()
	r.LargePkts = c.u64()

	r.SynCount = c.u64()
	r.AckCount = c.u64()
	r.FinCount = c.u64()
	r.RstCount = c.u64()
	r.PshCount = c.u64()
	r.UrgCount = c.u64()

	r.InitialWindow = c.u32()

	var a flow.Accumulators
	a.WindowCount = c.u64()
	a.IATCount = c.u64()
	a.FwdIATCount = c.u64()
	a.BwdIATCount = c.u64()

	a.PktSizeSum = c.f64()
	a.PktSizeSumSq = c.f64()
	a.FwdSizeSum = c.f64()
	a.BwdSizeSum = c.f64()
	a.WindowSum = c.f64()
	a.IATSum = c.f64()
	a.IATSumSq = c.f64()
	a.IATMin = c.f64()
	a.IATMax = c.f64()
	a.FwdIATSum = c.f64()
	a.BwdIATSum = c.f64()

	if err := c.done(); err != nil {
		return flow.Record{}, err
	}
	return r.WithAccumulators(a).WithDerivedKey(), nil
}

// DecodeFeatureRecord parses a FrameFeatureRecord payload.
func DecodeFeatureRecord(payload []byte) (FeatureRecord, error) {
	c := &cur{b: payload}
	if v := c.u8(); v != featureRecordLayoutV1 {
		if c.err != nil {
			return FeatureRecord{}, c.err
		}
		return FeatureRecord{}, protoErr("feature record layout version %d, want %d (%s)", v, featureRecordLayoutV1, FeatureRecordSchema)
	}

	var fr FeatureRecord
	fr.Proto = packet.Proto(c.u8())
	reason, ok := reasonFromWire(c.u8())
	if !ok && c.err == nil {
		return FeatureRecord{}, protoErr("feature record carries an unknown close reason")
	}
	fr.Reason = reason
	if rsv := c.u8(); rsv != 0 && c.err == nil {
		return FeatureRecord{}, protoErr("feature record reserved byte is 0x%02x, want 0", rsv)
	}
	fr.SnapshotIndex = int(int32(c.u32()))
	fr.SensorFlowID = c.u64()
	fr.FirstSeen = c.ts()
	fr.LastSeen = c.ts()

	fr.InitiatorIP = c.addr()
	fr.InitiatorPort = c.u16()
	fr.ResponderIP = c.addr()
	fr.ResponderPort = c.u16()

	n := c.u16()
	if c.err != nil {
		return FeatureRecord{}, c.err
	}
	// The dimension is checked before the 8n-byte read, so a crafted count can
	// neither over-allocate nor be read past the payload.
	if int(n) != features.Size {
		return FeatureRecord{}, protoErr("feature record declares %d values, %s has %d", n, FeatureRecordSchema, features.Size)
	}
	for i := range fr.Values {
		fr.Values[i] = c.f64()
	}

	if err := c.done(); err != nil {
		return FeatureRecord{}, err
	}
	return fr, nil
}

// Vector rebuilds a features.Vector from the record, stamped with the flow id
// the daemon assigned. The 48 values are exactly what the sensor computed; only
// the id — which is not a feature — is rewritten.
func (fr FeatureRecord) Vector(flowID uint64) features.Vector {
	return features.Vector{FlowID: flowID, Schema: features.SchemaID, Values: fr.Values}
}
