package pcapoverip

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// testFlowOptions is the lifecycle both ends of every test use.
func testFlowOptions() flow.Options {
	return flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute, MaxFlows: 10000}
}

// TestNegotiationMatrix walks every old/new combination over a real TLS
// handshake. "Old" is emulated exactly as an old peer behaves on the wire: an old
// daemon sends a hello with no max_version capability, and an old sensor is one
// whose configured mode is raw and which therefore never needs v2.
//
// The claims:
//   - old daemon ↔ old sensor        → v1, raw. Byte-for-byte unchanged.
//   - old daemon ↔ new sensor (raw)  → v1, raw. No upgrade is forced.
//   - old daemon ↔ new sensor (flow) → typed RejectMode. Never a silent downgrade.
//   - new daemon ↔ old sensor        → v1, raw. The capability key is ignored.
//   - new daemon ↔ new sensor        → v2, the sensor's mode, schema-bound.
func TestNegotiationMatrix(t *testing.T) {
	// oldHello is what a SYNPOIP v1 daemon puts on the wire: fixed version 1 and
	// no max_version in the metadata.
	oldHello := func(tok string) ClientHello {
		return ClientHello{Version: Version1, Token: tok}
	}
	// newHello advertises the v2 ceiling in the metadata, as capture.recordRoute
	// does when the daemon has somewhere to put records.
	newHello := func(tok string) ClientHello {
		return ClientHello{Version: Version1, MaxVersion: VersionMax, Token: tok}
	}

	tests := []struct {
		name        string
		sensorMode  Mode
		hello       ClientHello
		wantVersion uint16
		wantMode    Mode
		wantSchema  string
		wantReject  RejectCode
	}{
		{
			name: "old daemon / old sensor", sensorMode: ModeRaw, hello: oldHello("tok"),
			wantVersion: Version1, wantMode: ModeRaw,
		},
		{
			name: "old daemon / new sensor raw", sensorMode: ModeRaw, hello: oldHello("tok"),
			wantVersion: Version1, wantMode: ModeRaw,
		},
		{
			name: "old daemon / new sensor flow", sensorMode: ModeFlow, hello: oldHello("tok"),
			wantReject: RejectMode,
		},
		{
			name: "old daemon / new sensor feature", sensorMode: ModeFeature, hello: oldHello("tok"),
			wantReject: RejectMode,
		},
		{
			name: "new daemon / old sensor", sensorMode: ModeRaw, hello: newHello("tok"),
			// An *old* sensor would answer v1 here. This build answers v2/raw,
			// which is the same stream of 0x01 frames; TestAcceptV1TailIsAbsent
			// and TestHelloMetaIsIgnorableByV1 cover the real old-code case at
			// the byte level.
			wantVersion: Version2, wantMode: ModeRaw,
		},
		{
			name: "new daemon / new sensor flow", sensorMode: ModeFlow, hello: newHello("tok"),
			wantVersion: Version2, wantMode: ModeFlow, wantSchema: FlowRecordSchema,
		},
		{
			name: "new daemon / new sensor feature", sensorMode: ModeFeature, hello: newHello("tok"),
			wantVersion: Version2, wantMode: ModeFeature, wantSchema: FeatureRecordSchema,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ca := testTLSServer(t, ServerConfig{
				Token: "tok", LinkType: 1, Mode: tc.sensorMode, Flow: testFlowOptions(),
			}, blockingStream)

			sess, err := dialSession(t, addr, ca, tc.hello)
			if tc.wantReject != RejectNone {
				var re *RejectError
				if !errors.As(err, &re) {
					if sess != nil {
						_ = sess.Close()
					}
					t.Fatalf("want reject %s, got session/err %v", tc.wantReject, err)
				}
				if re.Code != tc.wantReject {
					t.Fatalf("want reject %s, got %s (%s)", tc.wantReject, re.Code, re.Reason)
				}
				// The reason has to tell the operator what to fix.
				if !strings.Contains(re.Reason, tc.sensorMode.String()) {
					t.Errorf("reject reason %q does not name the sensor mode", re.Reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer func() { _ = sess.Close() }()

			if sess.NegotiatedVersion() != tc.wantVersion {
				t.Errorf("version = %d, want %d", sess.NegotiatedVersion(), tc.wantVersion)
			}
			if sess.Mode() != tc.wantMode {
				t.Errorf("mode = %s, want %s", sess.Mode(), tc.wantMode)
			}
			if sess.PayloadSchema() != tc.wantSchema {
				t.Errorf("schema = %q, want %q", sess.PayloadSchema(), tc.wantSchema)
			}
			if verr := ValidateAccept(sess.Accept()); verr != nil {
				t.Errorf("negotiated accept failed validation: %v", verr)
			}
		})
	}
}

// TestAggregateFlowMode runs the sensor-side aggregation over a committed
// capture and checks the records it emits are decodable, schema-correct and
// equivalent to what a local flow table would have produced.
func TestAggregateFlowMode(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "pcap", "portscan.pcap")

	for _, mode := range []Mode{ModeFlow, ModeFeature} {
		t.Run(mode.String(), func(t *testing.T) {
			stream, link, err := PcapFileStream(path, 0)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			frames, errc := Aggregate(AggregateConfig{
				Mode: mode, LinkType: link, Flow: testFlowOptions(), Logf: t.Logf,
			}, stream)(ctx)

			var got, bytesOnWire int
			wantType := FrameFlowRecord
			if mode == ModeFeature {
				wantType = FrameFeatureRecord
			}
		drain:
			for {
				select {
				case err := <-errc:
					if err != nil {
						t.Fatalf("aggregation error: %v", err)
					}
				case f, ok := <-frames:
					if !ok {
						break drain
					}
					if f.Type != wantType {
						t.Fatalf("frame type 0x%02x, want 0x%02x", uint8(f.Type), uint8(wantType))
					}
					bytesOnWire += len(f.Payload)
					got++

					switch mode {
					case ModeFlow:
						r, derr := DecodeFlowRecord(f.Payload)
						if derr != nil {
							t.Fatalf("record %d: %v", got, derr)
						}
						if r.FwdPackets+r.BwdPackets == 0 {
							t.Errorf("record %d carries no packets", got)
						}
						if !r.InitiatorIP.IsValid() {
							t.Errorf("record %d has no initiator address", got)
						}
					case ModeFeature:
						fr, derr := DecodeFeatureRecord(f.Payload)
						if derr != nil {
							t.Fatalf("record %d: %v", got, derr)
						}
						if fr.Vector(1).Schema != features.SchemaID {
							t.Errorf("record %d: wrong schema", got)
						}
						if c := fr.Vector(1).Counts(); c.FwdPackets+c.BwdPackets == 0 {
							t.Errorf("record %d: the vector reports no packets", got)
						}
					}
				case <-ctx.Done():
					t.Fatal("aggregation did not finish")
				}
			}

			if got == 0 {
				t.Fatal("aggregation produced no records at all")
			}
			t.Logf("%s mode: %d records, %d bytes on the wire (%d B/record)",
				mode, got, bytesOnWire, bytesOnWire/got)
		})
	}
}

// TestAggregateSkipsUndecodableFrames feeds deliberate garbage through the
// aggregation stage: it must be counted and skipped, never fatal, never a panic.
func TestAggregateSkipsUndecodableFrames(t *testing.T) {
	junk := func(ctx context.Context) (<-chan Record, <-chan error) {
		recs := make(chan Record, 4)
		errc := make(chan error, 1)
		recs <- Record{TS: time.Unix(1, 0), Raw: []byte{0x00}}
		recs <- Record{TS: time.Unix(2, 0), Raw: nil}
		recs <- Record{TS: time.Unix(3, 0), Raw: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
		close(recs)
		return recs, errc
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	frames, _ := Aggregate(AggregateConfig{
		Mode: ModeFlow, LinkType: 1, Flow: testFlowOptions(), Logf: t.Logf,
	}, junk)(ctx)

	for f := range frames {
		t.Errorf("garbage produced a record frame: type 0x%02x, %d bytes", uint8(f.Type), len(f.Payload))
	}
}
