// Package features turns a closed or snapshotted flow record into the frozen
// flow-features-v1 numeric vector that models consume. It computes nothing from
// raw IP addresses — only derived behavioural and context values (PROJECT.md §8).
package features

import (
	"math"
	"net/netip"

	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/packet"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Size is the flow-features-v1 input dimension.
const Size = 48

// SchemaID names the frozen schema this package implements.
const SchemaID = "flow-features-v1"

// Vector is one flow-features-v1 sample. The array order is the frozen schema
// order and must never be reordered (PROJECT.md §28.5).
type Vector struct {
	FlowID uint64        `json:"flow_id"`
	Schema string        `json:"schema"`
	Values [Size]float64 `json:"values"`
}

// Get returns the value of a named feature, or 0 if the name is unknown.
func (v Vector) Get(name string) float64 {
	for i := 0; i < Size; i++ {
		if schema.FeatureName(i) == name {
			return v.Values[i]
		}
	}
	return 0
}

// Named returns the vector as an ordered name→value map view for reporting.
func (v Vector) Named() []struct {
	Name  string
	Value float64
} {
	out := make([]struct {
		Name  string
		Value float64
	}, Size)
	for i := 0; i < Size; i++ {
		out[i].Name = schema.FeatureName(i)
		out[i].Value = v.Values[i]
	}
	return out
}

const secFloor = 1e-6

// Extract computes flow-features-v1 for a flow record.
func Extract(r flow.Record) Vector {
	dur := r.Duration().Seconds()
	if dur < 0 {
		dur = 0
	}
	durNZ := dur
	if durNZ < secFloor {
		durNZ = secFloor
	}
	totalPkts := float64(r.FwdPackets + r.BwdPackets)
	totalBytes := float64(r.FwdBytes + r.BwdBytes)

	var v Vector
	v.FlowID = r.ID
	v.Schema = SchemaID
	s := &v.Values

	s[0] = dur
	s[1] = float64(r.FwdPackets)
	s[2] = float64(r.BwdPackets)
	s[3] = float64(r.FwdBytes)
	s[4] = float64(r.BwdBytes)
	s[5] = r.PktSizeMean()
	s[6] = float64(r.PktSizeMin)
	s[7] = float64(r.PktSizeMax)
	s[8] = r.PktSizeStdDev()
	s[9] = r.FwdSizeMean()
	s[10] = r.BwdSizeMean()
	s[11] = totalPkts / durNZ
	s[12] = totalBytes / durNZ
	s[13] = float64(r.FwdPackets) / durNZ
	s[14] = float64(r.BwdPackets) / durNZ
	s[15] = r.IATMean()
	s[16] = r.IATMinS()
	s[17] = r.IATMaxS()
	s[18] = r.IATStdDev()
	s[19] = r.FwdIATMean()
	s[20] = r.BwdIATMean()
	s[21] = float64(r.InitiatorPort)
	s[22] = float64(r.ResponderPort)
	s[23] = boolf(r.Proto == packet.ProtoTCP)
	s[24] = boolf(r.Proto == packet.ProtoUDP)
	s[25] = boolf(r.Proto == packet.ProtoICMP || r.Proto == packet.ProtoICMPv6)
	s[26] = float64(r.SynCount)
	s[27] = float64(r.AckCount)
	s[28] = float64(r.FinCount)
	s[29] = float64(r.RstCount)
	s[30] = float64(r.PshCount)
	s[31] = float64(r.UrgCount)
	s[32] = ratio(float64(r.SynCount), math.Max(float64(r.AckCount), 1))
	s[33] = ratio(float64(r.FwdPackets), math.Max(totalPkts, 1))
	s[34] = ratio(float64(r.FwdBytes), math.Max(totalBytes, 1))
	s[35] = float64(r.InitialWindow)
	s[36] = r.AvgWindow()
	s[37] = ratio(float64(r.BwdBytes), math.Max(float64(r.FwdBytes), 1))
	s[38] = ratio(float64(r.SmallPkts), math.Max(totalPkts, 1))
	s[39] = ratio(float64(r.LargePkts), math.Max(totalPkts, 1))
	s[40] = payloadMean(r, totalPkts)
	s[41] = boolf(r.FwdPackets > 0 && r.BwdPackets > 0)

	i2i, i2e, e2i, e2e := context4(r.InitiatorIP, r.ResponderIP)
	s[42] = i2i
	s[43] = i2e
	s[44] = e2i
	s[45] = e2e
	s[46] = boolf(r.ResponderPort >= 1 && r.ResponderPort <= 1023)
	s[47] = float64(r.SnapshotIndex)

	for i := range s {
		if math.IsNaN(s[i]) || math.IsInf(s[i], 0) {
			s[i] = 0
		}
	}
	return v
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func ratio(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func payloadMean(r flow.Record, totalPkts float64) float64 {
	if totalPkts == 0 {
		return 0
	}
	return float64(r.FwdPayload+r.BwdPayload) / totalPkts
}

// isInternal reports whether an address is private / link-local / loopback / ULA.
func isInternal(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()
}

func context4(init, resp netip.Addr) (i2i, i2e, e2i, e2e float64) {
	ii, ri := isInternal(init), isInternal(resp)
	switch {
	case ii && ri:
		return 1, 0, 0, 0
	case ii && !ri:
		return 0, 1, 0, 0
	case !ii && ri:
		return 0, 0, 1, 0
	default:
		return 0, 0, 0, 1
	}
}
