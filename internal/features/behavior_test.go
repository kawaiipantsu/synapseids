package features

import (
	"math"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/flow"
)

func TestBehaviorTimingGolden(t *testing.T) {
	tm := &flow.Telemetry{Samples: 5, Gaps: [32]float64{0, 1, 2, 1, 2}, Sizes: [32]float64{100, -200, 100, -200, 100}, DNSQueries: 2, DNSNameCount: 2, EntropySum: 6, EntropyMax: 4, QueryNames: []string{"first.example", "second.example"}}
	base := Vector{}
	base.Values[0] = 42
	v := Behavior(flow.Record{Telemetry: tm, FwdBytes: 300, BwdBytes: 400, FwdPayload: 100, BwdPayload: 200}, base)
	want := map[int]float64{0: 42, 75: 0, 76: 1, 77: 2, 78: 1, 79: 2, 107: 100, 108: -200, 109: 100, 110: -200, 111: 100, 112: 5.0 / 32, 113: 1.5, 114: .5, 115: 1.0 / 3, 116: -1, 120: 1.5, 121: 2, 122: 0, 123: 0, 124: 1, 125: .6, 126: 3.0 / 7, 127: 1, 128: 2, 132: 4, 133: 3, 136: 2, 143: 1}
	for i, w := range want {
		if math.Abs(v.Values[i]-w) > 1e-9 {
			t.Errorf("feature %d=%g want %g", i, v.Values[i], w)
		}
	}
	absent := Behavior(flow.Record{}, base)
	if absent.Values[0] != 42 || absent.Values[127] != 0 || absent.Values[143] != 0 {
		t.Fatal("missing telemetry must be masked")
	}
	if Correlation([]float64{1, 1, 1, 1}, 1) != 0 || Correlation([]float64{1, 2}, 1) != 0 {
		t.Fatal("degenerate correlation")
	}
}
func TestHostWindowIdentityAndSensorIsolation(t *testing.T) {
	h := NewHostWindow()
	base := time.Unix(1000, 0)
	var v BehaviorVector
	for i := 0; i < 10; i++ {
		s := HostSample{Sensor: "a", Initiator: "source", Responder: "target", Identity: time.Duration(i).String(), Port: uint16(80 + i), Started: base.Add(time.Duration(i) * 5 * time.Second), At: base.Add(time.Duration(i) * 5 * time.Second), SYNOnly: true, OneWay: true, Bytes: 100, Telemetry: &flow.Telemetry{DNSQueries: 2, QueryNames: []string{"a.example"}}}
		h.Apply(&v, s)
		h.Apply(&v, s)
	}
	for i, w := range map[int]float64{144: 10, 145: 10, 146: 1, 147: 1, 148: 1, 149: 5, 150: 0, 153: 20, 155: 1, 156: 45, 157: 1000, 158: 1, 159: 1} {
		if v.Values[i] != w {
			t.Errorf("feature %d=%g want %g", i, v.Values[i], w)
		}
	}
	h.Apply(&v, HostSample{Sensor: "b", Initiator: "source", Identity: "1", At: base, Started: base})
	if v.Values[144] != 1 {
		t.Fatal("sensors mixed")
	}
	h.Apply(&v, HostSample{Sensor: "a", Initiator: "source", Identity: "new", At: base.Add(3 * time.Minute), Started: base.Add(3 * time.Minute)})
	if v.Values[144] != 1 {
		t.Fatal("expired records survived")
	}
}
