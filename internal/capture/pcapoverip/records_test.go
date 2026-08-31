package pcapoverip

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// sampleFlowRecord builds a record with every field distinct and non-zero, so a
// round-trip that silently drops or transposes one is caught.
func sampleFlowRecord() flow.Record {
	r := flow.Record{
		ID:            0xDEADBEEFCAFE01,
		Reason:        flow.ReasonFINRST,
		SnapshotIndex: 7,
		InitiatorIP:   netip.MustParseAddr("10.1.2.3"),
		InitiatorPort: 44123,
		ResponderIP:   netip.MustParseAddr("93.184.216.34"),
		ResponderPort: 443,
		Proto:         packet.ProtoTCP,
		FirstSeen:     time.Unix(1735689600, 123456789).UTC(),
		LastSeen:      time.Unix(1735689742, 987654321).UTC(),
		FwdPackets:    11, BwdPackets: 13,
		FwdBytes: 1717, BwdBytes: 2929,
		FwdPayload: 909, BwdPayload: 1313,
		PktSizeMin: 54, PktSizeMax: 1514,
		SmallPkts: 3, LargePkts: 5,
		SynCount: 2, AckCount: 19, FinCount: 2,
		RstCount: 1, PshCount: 6, UrgCount: 1,
		InitialWindow: 64240,
	}
	return r.WithAccumulators(flow.Accumulators{
		PktSizeSum: 4646.5, PktSizeSumSq: 1234567.75,
		FwdSizeSum: 1717.25, BwdSizeSum: 2929.125,
		WindowSum: 512000.5, WindowCount: 23,
		IATSum: 141.5, IATSumSq: 5001.25,
		IATMin: 0.000125, IATMax: 12.5, IATCount: 23,
		FwdIATSum: 70.25, BwdIATSum: 71.25,
		FwdIATCount: 10, BwdIATCount: 12,
	}).WithDerivedKey()
}

func TestFlowRecordRoundTrip(t *testing.T) {
	want := sampleFlowRecord()
	payload := EncodeFlowRecord(want)
	if len(payload) > MaxFramePayload {
		t.Fatalf("flow record payload %d exceeds the frame cap %d", len(payload), MaxFramePayload)
	}
	got, err := DecodeFlowRecord(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Errorf("round-trip changed the record:\n got %+v\nwant %+v", got, want)
	}
	// The point of carrying the private accumulators is that the daemon derives
	// exactly what the sensor would have.
	if features.Extract(got) != features.Extract(want) {
		t.Error("features.Extract differs across the wire — an accumulator was lost")
	}
	t.Logf("flow-record-v1 is %d bytes for an IPv4 flow", len(payload))
}

func TestFlowRecordRoundTripIPv6AndZeroPorts(t *testing.T) {
	r := flow.Record{
		ID:          42,
		Reason:      flow.ReasonCapEnd,
		InitiatorIP: netip.MustParseAddr("2001:db8::1"),
		ResponderIP: netip.MustParseAddr("2001:db8::dead:beef"),
		Proto:       packet.ProtoICMPv6,
		FirstSeen:   time.Unix(1, 0).UTC(),
		LastSeen:    time.Unix(2, 0).UTC(),
		FwdPackets:  1,
	}
	got, err := DecodeFlowRecord(EncodeFlowRecord(r.WithDerivedKey()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != r.WithDerivedKey() {
		t.Errorf("IPv6 round-trip mismatch:\n got %+v\nwant %+v", got, r.WithDerivedKey())
	}
}

func TestFlowRecordRoundTripInvalidAddress(t *testing.T) {
	// A record whose endpoints were never set must survive as "unset", not become
	// a bogus 0.0.0.0.
	r := flow.Record{ID: 1, Reason: flow.ReasonIdle, FirstSeen: time.Unix(0, 0).UTC(), LastSeen: time.Unix(0, 0).UTC()}
	got, err := DecodeFlowRecord(EncodeFlowRecord(r))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.InitiatorIP.IsValid() || got.ResponderIP.IsValid() {
		t.Errorf("an unset address came back valid: %v / %v", got.InitiatorIP, got.ResponderIP)
	}
}

func sampleFeatureRecord() FeatureRecord {
	fr := FeatureRecord{
		SensorFlowID:  9911,
		Proto:         packet.ProtoUDP,
		Reason:        flow.ReasonSnapshot,
		SnapshotIndex: 3,
		InitiatorIP:   netip.MustParseAddr("192.168.7.9"),
		InitiatorPort: 51000,
		ResponderIP:   netip.MustParseAddr("1.1.1.1"),
		ResponderPort: 53,
		FirstSeen:     time.Unix(1700000000, 1).UTC(),
		LastSeen:      time.Unix(1700000030, 2).UTC(),
	}
	for i := range fr.Values {
		fr.Values[i] = float64(i) * 1.5
	}
	return fr
}

func TestFeatureRecordRoundTrip(t *testing.T) {
	want := sampleFeatureRecord()
	payload := EncodeFeatureRecord(want)
	if len(payload) > MaxFramePayload {
		t.Fatalf("feature record payload %d exceeds the frame cap %d", len(payload), MaxFramePayload)
	}
	got, err := DecodeFeatureRecord(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Errorf("round-trip changed the record:\n got %+v\nwant %+v", got, want)
	}
	v := got.Vector(777)
	if v.FlowID != 777 || v.Schema != features.SchemaID || v.Values != want.Values {
		t.Errorf("Vector(777) = %+v, want the sensor's values stamped with the daemon's id", v)
	}
	t.Logf("flow-features-v1 record is %d bytes for an IPv4 flow", len(payload))
}

// TestRecordDecodeTruncated walks every prefix of both encodings: none may panic
// and none may be accepted (PROJECT.md §28.11).
func TestRecordDecodeTruncated(t *testing.T) {
	flowPayload := EncodeFlowRecord(sampleFlowRecord())
	featPayload := EncodeFeatureRecord(sampleFeatureRecord())

	for i := 0; i < len(flowPayload); i++ {
		if _, err := DecodeFlowRecord(flowPayload[:i]); err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte flow record was accepted", i, len(flowPayload))
		}
	}
	for i := 0; i < len(featPayload); i++ {
		if _, err := DecodeFeatureRecord(featPayload[:i]); err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte feature record was accepted", i, len(featPayload))
		}
	}
}

func TestRecordDecodeOversized(t *testing.T) {
	// Trailing bytes past a complete body are refused, not silently ignored.
	flowPayload := append(EncodeFlowRecord(sampleFlowRecord()), 0xFF, 0xFF)
	if _, err := DecodeFlowRecord(flowPayload); err == nil {
		t.Error("a flow record with trailing garbage was accepted")
	}
	featPayload := append(EncodeFeatureRecord(sampleFeatureRecord()), 0x00)
	if _, err := DecodeFeatureRecord(featPayload); err == nil {
		t.Error("a feature record with trailing garbage was accepted")
	}

	// A crafted feature dimension must be rejected *before* the 8n-byte read.
	p := EncodeFeatureRecord(sampleFeatureRecord())
	binary.BigEndian.PutUint16(p[len(p)-features.Size*8-2:], 0xFFFF)
	_, err := DecodeFeatureRecord(p)
	if err == nil {
		t.Fatal("a feature record claiming 65535 values was accepted")
	}
	if !strings.Contains(err.Error(), "declares 65535 values") {
		t.Errorf("unclear dimension error: %v", err)
	}
}

func TestRecordDecodeBadLayoutVersion(t *testing.T) {
	p := EncodeFlowRecord(sampleFlowRecord())
	p[0] = 99
	_, err := DecodeFlowRecord(p)
	if err == nil || !strings.Contains(err.Error(), FlowRecordSchema) {
		t.Errorf("want a layout error naming %s, got %v", FlowRecordSchema, err)
	}
	if !errors.Is(err, ErrProtocol) {
		t.Errorf("layout error is not an ErrProtocol: %v", err)
	}

	q := EncodeFeatureRecord(sampleFeatureRecord())
	q[0] = 2
	if _, err := DecodeFeatureRecord(q); err == nil || !strings.Contains(err.Error(), FeatureRecordSchema) {
		t.Errorf("want a layout error naming %s, got %v", FeatureRecordSchema, err)
	}
}

func TestRecordDecodeRejectsMalformedFields(t *testing.T) {
	p := EncodeFlowRecord(sampleFlowRecord())

	bad := append([]byte(nil), p...)
	bad[2] = 0 // unknown close reason
	if _, err := DecodeFlowRecord(bad); err == nil {
		t.Error("an unknown close reason was accepted")
	}

	bad = append([]byte(nil), p...)
	bad[3] = 1 // reserved byte must be zero
	if _, err := DecodeFlowRecord(bad); err == nil {
		t.Error("a non-zero reserved byte was accepted")
	}

	bad = append([]byte(nil), p...)
	bad[32] = 7 // address length is neither 0, 4 nor 16
	if _, err := DecodeFlowRecord(bad); err == nil {
		t.Error("a 7-byte address length was accepted")
	}
}

// TestFeatureRecordNaNSurvives documents that the codec is bit-transparent: it
// is features.Extract's job to sanitise, not the transport's, and a value the
// sensor computed must arrive unchanged.
func TestFeatureRecordNaNSurvives(t *testing.T) {
	fr := sampleFeatureRecord()
	fr.Values[5] = math.Inf(-1)
	got, err := DecodeFeatureRecord(EncodeFeatureRecord(fr))
	if err != nil {
		t.Fatal(err)
	}
	if !math.IsInf(got.Values[5], -1) {
		t.Errorf("values[5] = %v, want -Inf", got.Values[5])
	}
}

// ---------------------------------------------------- schema binding ---------

func TestValidateAcceptSchemaBinding(t *testing.T) {
	tests := []struct {
		name    string
		acc     ServerAccept
		wantErr string
	}{
		{"v1 raw", ServerAccept{Version: Version1, Mode: ModeRaw}, ""},
		{"v2 raw", ServerAccept{Version: Version2, Mode: ModeRaw}, ""},
		{"v2 flow", ServerAccept{Version: Version2, Mode: ModeFlow, PayloadSchema: FlowRecordSchema}, ""},
		{"v2 feature", ServerAccept{Version: Version2, Mode: ModeFeature, PayloadSchema: FeatureRecordSchema}, ""},
		{
			// The case the whole binding exists for: a future sensor computing a
			// different feature schema must be refused, not misread.
			"future feature schema",
			ServerAccept{Version: Version2, Mode: ModeFeature, PayloadSchema: "flow-features-v2"},
			"flow-features-v2",
		},
		{
			"future flow-record schema",
			ServerAccept{Version: Version2, Mode: ModeFlow, PayloadSchema: "flow-record-v2"},
			"flow-record-v2",
		},
		{"flow schema on a feature mode", ServerAccept{Version: Version2, Mode: ModeFeature, PayloadSchema: FlowRecordSchema}, "refusing the session"},
		{"empty schema in a record mode", ServerAccept{Version: Version2, Mode: ModeFlow}, "refusing the session"},
		{"unknown mode", ServerAccept{Version: Version2, Mode: Mode(0x7F)}, "unknown mode"},
		{"record mode at v1", ServerAccept{Version: Version1, Mode: ModeFlow}, "needs protocol version 2"},
		{"version above max", ServerAccept{Version: VersionMax + 1}, "this build speaks"},
		{"version zero", ServerAccept{Version: 0}, "this build speaks"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAccept(tc.acc)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want accepted, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestModeHelpers(t *testing.T) {
	for _, tc := range []struct {
		in     string
		mode   Mode
		schema string
		min    uint16
	}{
		{"", ModeRaw, "", Version1},
		{"raw", ModeRaw, "", Version1},
		{"flow", ModeFlow, FlowRecordSchema, Version2},
		{"feature", ModeFeature, FeatureRecordSchema, Version2},
	} {
		m, err := ParseMode(tc.in)
		if err != nil || m != tc.mode {
			t.Fatalf("ParseMode(%q) = %v, %v", tc.in, m, err)
		}
		if m.PayloadSchema() != tc.schema {
			t.Errorf("%s.PayloadSchema() = %q, want %q", m, m.PayloadSchema(), tc.schema)
		}
		if m.MinVersion() != tc.min {
			t.Errorf("%s.MinVersion() = %d, want %d", m, m.MinVersion(), tc.min)
		}
	}
	if _, err := ParseMode("packets"); err == nil {
		t.Error("ParseMode accepted an unknown mode")
	}
}

// TestSchemaIDsAreTheOwningPackages guards the binding against drift: the
// transport must never invent its own schema names.
func TestSchemaIDsAreTheOwningPackages(t *testing.T) {
	if FlowRecordSchema != flow.RecordSchemaV1 {
		t.Errorf("FlowRecordSchema %q != flow.RecordSchemaV1 %q", FlowRecordSchema, flow.RecordSchemaV1)
	}
	if FeatureRecordSchema != features.SchemaID {
		t.Errorf("FeatureRecordSchema %q != features.SchemaID %q", FeatureRecordSchema, features.SchemaID)
	}
}

// TestHelloMetaIsIgnorableByV1 is the "old sensor, new daemon" compatibility
// claim at the byte level: a v2-capable ClientHello still declares version 1 in
// the fixed field, and its metadata decodes cleanly into the v1 shape with the
// unknown capability key dropped.
func TestHelloMetaIsIgnorableByV1(t *testing.T) {
	h := ClientHello{
		Version: Version1, MaxVersion: Version2,
		LinkType: 1, Token: "tok", SensorID: "edge-1", Location: "wan", Filter: "port 80",
	}
	raw, err := h.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if v := binary.BigEndian.Uint16(raw[magicLen:]); v != Version1 {
		t.Fatalf("fixed hello version is %d — a v1 sensor would reject the handshake", v)
	}

	// Locate and decode the metadata exactly as a v1 sensor's helloMeta would.
	off := magicLen + 2 + 4
	tokenLen := int(binary.BigEndian.Uint16(raw[off:]))
	off += 2 + tokenLen
	metaLen := int(binary.BigEndian.Uint32(raw[off:]))
	meta := raw[off+4 : off+4+metaLen]

	var v1meta struct {
		SensorID string `json:"sensor_id,omitempty"`
		Filter   string `json:"filter,omitempty"`
		Location string `json:"location,omitempty"`
	}
	if err := json.Unmarshal(meta, &v1meta); err != nil {
		t.Fatalf("a v1 sensor could not decode the metadata: %v", err)
	}
	if v1meta.SensorID != "edge-1" || v1meta.Filter != "port 80" || v1meta.Location != "wan" {
		t.Errorf("v1 metadata fields were disturbed: %+v", v1meta)
	}

	// And a v2 peer reads the ceiling back.
	got, err := ReadClientHello(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Ceiling() != Version2 {
		t.Errorf("Ceiling() = %d, want %d", got.Ceiling(), Version2)
	}
}

// TestHelloOmitsCeilingWhenV1Only proves a v1-only client's hello is byte-for-byte
// what it always was: no max_version key appears.
func TestHelloOmitsCeilingWhenV1Only(t *testing.T) {
	h := ClientHello{Version: Version1, LinkType: 1, Token: "tok", SensorID: "s"}
	raw, err := h.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "max_version") {
		t.Error("a v1-only hello advertised max_version")
	}
	// MaxVersion == Version is also "v1 only".
	h.MaxVersion = Version1
	raw2, err := h.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw2) != string(raw) {
		t.Error("MaxVersion == Version changed the wire bytes")
	}
}

// TestAcceptV1TailIsAbsent is the "new sensor, old daemon" claim: when the
// negotiated version is 1 the accept carries no mode/schema tail, so a v1 client
// reading frames right after the session id sees a frame header, not our bytes.
func TestAcceptV1TailIsAbsent(t *testing.T) {
	v1 := ServerAccept{Version: Version1, LinkType: 1, Filter: "f", SessionID: "sid"}
	rawV1, err := v1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wantLen := magicLen + 1 + 2 + 4 + 2 + len("f") + 2 + len("sid")
	if len(rawV1) != wantLen {
		t.Fatalf("v1 accept is %d bytes, want exactly the v1 layout's %d", len(rawV1), wantLen)
	}

	v2 := v1
	v2.Version = Version2
	v2.Mode = ModeFeature
	v2.PayloadSchema = FeatureRecordSchema
	rawV2, err := v2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(rawV2) != wantLen+1+2+len(FeatureRecordSchema) {
		t.Fatalf("v2 accept is %d bytes, want the v1 layout plus the mode tail", len(rawV2))
	}
	// Everything but the two-byte version field is unchanged, and the tail is
	// strictly appended.
	if string(rawV2[:magicLen+1]) != string(rawV1[:magicLen+1]) ||
		string(rawV2[magicLen+3:wantLen]) != string(rawV1[magicLen+3:]) {
		t.Error("the v2 accept altered the v1 layout instead of appending to it")
	}

	// A record mode cannot be encoded at v1 at all.
	bad := v1
	bad.Mode = ModeFlow
	if _, err := bad.MarshalBinary(); err == nil {
		t.Error("a v1 accept encoded a flow mode")
	}
}

func TestAcceptRoundTripV2(t *testing.T) {
	for _, m := range []Mode{ModeRaw, ModeFlow, ModeFeature} {
		acc := ServerAccept{
			Version: Version2, LinkType: 101, Filter: "any", SessionID: "s|l|v|o-abc",
			Mode: m, PayloadSchema: m.PayloadSchema(),
		}
		raw, err := acc.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadServerResponse(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if *got != acc {
			t.Errorf("accept round-trip for mode %s:\n got %+v\nwant %+v", m, *got, acc)
		}
		if err := ValidateAccept(*got); err != nil {
			t.Errorf("mode %s accept failed validation: %v", m, err)
		}
	}
}

func TestAcceptRejectsOversizedSchema(t *testing.T) {
	acc := ServerAccept{Version: Version2, Mode: ModeRaw, PayloadSchema: strings.Repeat("x", MaxSchemaLen+1)}
	if _, err := acc.MarshalBinary(); err == nil {
		t.Error("an over-cap payload schema was encoded")
	}

	// And on the read side: a declared length over the cap must not allocate.
	raw, err := ServerAccept{Version: Version2, Mode: ModeRaw}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(raw[len(raw)-2:], MaxSchemaLen+1)
	if _, err := ReadServerResponse(strings.NewReader(string(raw))); err == nil {
		t.Error("an over-cap declared schema length was accepted")
	}
}

func TestFrameTypeStrings(t *testing.T) {
	for ft, want := range map[FrameType]string{
		FramePacket: "packet", FrameKeepalive: "keepalive", FrameGoodbye: "goodbye",
		FrameFlowRecord: "flow-record", FrameFeatureRecord: "feature-record",
	} {
		if ft.String() != want {
			t.Errorf("FrameType(0x%02x).String() = %q, want %q", uint8(ft), ft.String(), want)
		}
	}
	if got := FrameType(0x7E).String(); !strings.Contains(got, "unknown") {
		t.Errorf("unknown frame type rendered as %q", got)
	}
	if got := RejectMode.String(); got != "mode-unsupported" {
		t.Errorf("RejectMode.String() = %q", got)
	}
}
