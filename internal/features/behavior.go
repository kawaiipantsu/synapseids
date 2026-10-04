package features

import (
	"math"
	"sort"

	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// BehaviorSize is the input width of the independent traffic-behavior-v1 schema.
const BehaviorSize = 160

// BehaviorSchemaID names the frozen temporal and protocol feature contract.
const BehaviorSchemaID = "traffic-behavior-v1"

// BehaviorVector contains no identifying names, addresses or reputation labels.
type BehaviorVector struct {
	Schema string                `json:"schema"`
	Values [BehaviorSize]float64 `json:"values"`
}

// Behavior extracts packet-level context; the last sixteen host-context slots
// are populated separately by HostWindow in the pipeline or offline extractor.
func Behavior(r flow.Record, base Vector) BehaviorVector {
	out := BehaviorVector{Schema: BehaviorSchemaID}
	copy(out.Values[:48], base.Values[:])
	s := out.Values[:]
	t := r.Telemetry
	if t == nil {
		return out
	}
	gaps, sizes := t.Ordered()
	offset := 32 - len(gaps)
	copy(s[48+offset:80], gaps)
	copy(s[80+offset:112], sizes)
	s[112] = float64(len(gaps)) / 32
	validGaps := gaps
	if t.Samples <= 32 && len(validGaps) > 0 {
		validGaps = validGaps[1:]
	}
	mean, std := MeanStd(validGaps)
	s[113], s[114] = mean, std
	if mean > 0 {
		s[115] = std / mean
	}
	for i, lag := range []int{1, 2, 4, 8} {
		s[116+i] = Correlation(validGaps, lag)
	}
	if len(validGaps) > 0 {
		ordered := append([]float64{}, validGaps...)
		sort.Float64s(ordered)
		n := len(ordered)
		s[120] = ordered[n/2]
		if n%2 == 0 {
			s[120] = (ordered[n/2-1] + ordered[n/2]) / 2
		}
		s[121] = ordered[int(math.Ceil(.9*float64(n)))-1]
		var burst, repeated int
		for i, g := range validGaps {
			if g <= .01 {
				burst++
			}
			if i > 0 && mean > 0 && math.Abs(g-validGaps[i-1]) <= .05*mean {
				repeated++
			}
		}
		s[122] = float64(repeated) / math.Max(1, float64(n-1))
		s[123] = float64(burst) / float64(n)
	}
	var switches, forward int
	for i, size := range sizes {
		if size > 0 {
			forward++
		}
		if i > 0 && size*sizes[i-1] < 0 {
			switches++
		}
	}
	s[124] = float64(switches) / math.Max(1, float64(len(sizes)-1))
	s[125] = float64(forward) / math.Max(1, float64(len(sizes)))
	s[126] = float64(r.FwdPayload+r.BwdPayload) / math.Max(1, float64(r.FwdBytes+r.BwdBytes))
	s[127] = 1
	s[128] = float64(t.DNSQueries)
	s[129] = float64(t.DNSResponses)
	s[130] = float64(t.NXDomains)
	s[131] = float64(t.MalformedDNS)
	s[132] = t.EntropyMax
	s[133] = t.EntropySum / math.Max(1, float64(t.DNSNameCount))
	s[134] = float64(t.MaxNameLength)
	s[135] = float64(t.MaxLabelLength)
	s[136] = float64(len(t.QueryNames))
	s[137] = float64(t.HTTPRequests)
	s[138] = float64(t.Downloads)
	s[139] = float64(t.TLSHellos)
	s[140] = float64(t.IRC)
	s[141] = boolf(t.HasSNI)
	s[142] = boolf(t.HasHTTPHost)
	s[143] = 1 - float64(t.TruncatedSamples)/math.Max(1, float64(t.Samples))
	out.Sanitize()
	return out
}

// Sanitize bounds every untrusted feature and replaces non-finite values.
func (v *BehaviorVector) Sanitize() {
	for i, x := range v.Values {
		if math.IsInf(x, 0) || math.IsNaN(x) {
			v.Values[i] = 0
		} else {
			v.Values[i] = math.Max(-1e12, math.Min(1e12, x))
		}
	}
}

// MeanStd computes population moments of a bounded numeric series.
func MeanStd(x []float64) (mean, std float64) {
	if len(x) == 0 {
		return
	}
	for _, v := range x {
		mean += v
	}
	mean /= float64(len(x))
	for _, v := range x {
		std += (v - mean) * (v - mean)
	}
	std = math.Sqrt(std / float64(len(x)))
	return
}

// Correlation is Pearson correlation between two lagged slices, not a claim of
// maliciousness. Constant or insufficient series return zero.
func Correlation(x []float64, lag int) float64 {
	if lag < 1 || len(x)-lag < 3 {
		return 0
	}
	a, b := x[:len(x)-lag], x[lag:]
	ma, sa := MeanStd(a)
	mb, sb := MeanStd(b)
	if sa*sb <= 1e-15 {
		return 0
	}
	sum := 0.0
	for i := range a {
		sum += (a[i] - ma) * (b[i] - mb)
	}
	return math.Max(-1, math.Min(1, sum/(float64(len(a))*sa*sb)))
}
