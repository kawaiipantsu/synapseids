package pcapoverip

import (
	"encoding/binary"
	"math"
	"net/netip"
	"reflect"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func TestRichRoundTripAndBounds(t *testing.T) {
	r := flow.Record{Reason: flow.ReasonCapEnd, Telemetry: &flow.Telemetry{Samples: 2, Gaps: [32]float64{0, .25}, Sizes: [32]float64{100, -50}, DNSQueries: 1, QueryNames: []string{"example.test"}, Bindings: []packet.NameBinding{{Name: "example.test", Address: netip.MustParseAddr("192.0.2.1"), TTL: 60, Source: "observed DNS answer"}}}}
	b, e := EncodeRichFlowRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeRichFlowRecord(b)
	if e != nil || !reflect.DeepEqual(got.Telemetry, r.Telemetry) {
		t.Fatalf("round trip failed: %v", e)
	}
	for i := 0; i < len(b); i++ {
		if _, e = DecodeRichFlowRecord(b[:i]); e == nil {
			t.Fatalf("accepted truncated length %d", i)
		}
	}
	n := int(binary.BigEndian.Uint16(b[1:]))
	bad := append(append([]byte{}, b...), []byte(" {}")...)
	binary.BigEndian.PutUint32(bad[3+n:], uint32(len(bad)-n-7))
	if _, e = DecodeRichFlowRecord(bad); e == nil {
		t.Fatal("accepted trailing object")
	}
	r.Telemetry.Gaps[0] = math.NaN()
	if _, e = EncodeRichFlowRecord(r); e == nil {
		t.Fatal("accepted NaN")
	}
	if _, e = DecodeFlowRecord(b); e == nil {
		t.Fatal("rich record accepted as legacy")
	}
}
