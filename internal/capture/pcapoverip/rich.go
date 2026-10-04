package pcapoverip

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"unicode"

	"github.com/kawaiipantsu/synapseids/internal/flow"
)

// RichFlowSchema is an independent, versioned layout retaining v1 statistics
// plus the ordered packet sketch and bounded application metadata.
const RichFlowSchema = "flow-record-v2"

// EncodeRichFlowRecord wraps the immutable v1 record and validated telemetry.
func EncodeRichFlowRecord(r flow.Record) ([]byte, error) {
	if e := validateTelemetry(r.Telemetry); e != nil {
		return nil, e
	}
	base := EncodeFlowRecord(r)
	extra, e := json.Marshal(r.Telemetry)
	if e != nil {
		return nil, e
	}
	if len(extra) > 16384 {
		return nil, fmt.Errorf("rich metadata too large")
	}
	b := []byte{2}
	b = binary.BigEndian.AppendUint16(b, uint16(len(base)))
	b = append(b, base...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(extra)))
	return append(b, extra...), nil
}

// DecodeRichFlowRecord rejects malformed lengths, extra fields and non-finite
// or unbounded telemetry before any derived features are calculated.
func DecodeRichFlowRecord(b []byte) (flow.Record, error) {
	if len(b) < 7 || len(b) > 18000 || b[0] != 2 {
		return flow.Record{}, fmt.Errorf("invalid rich-flow layout")
	}
	n := int(binary.BigEndian.Uint16(b[1:]))
	if n > 1024 || n+7 > len(b) {
		return flow.Record{}, fmt.Errorf("invalid rich-flow base length")
	}
	r, e := DecodeFlowRecord(b[3 : 3+n])
	if e != nil {
		return r, e
	}
	size := int(binary.BigEndian.Uint32(b[3+n:]))
	if size > 16384 || size != len(b)-n-7 {
		return flow.Record{}, fmt.Errorf("invalid rich-flow metadata length")
	}
	var t flow.Telemetry
	d := json.NewDecoder(bytes.NewReader(b[7+n:]))
	d.DisallowUnknownFields()
	if e = d.Decode(&t); e != nil {
		return flow.Record{}, e
	}
	if d.Decode(new(any)) != io.EOF {
		return flow.Record{}, fmt.Errorf("trailing rich metadata")
	}
	if e = validateTelemetry(&t); e != nil {
		return flow.Record{}, e
	}
	r.Telemetry = &t
	return r, nil
}
func validateTelemetry(t *flow.Telemetry) error {
	if t == nil || t.Samples == 0 || t.Samples > 1<<48 {
		return fmt.Errorf("invalid rich sample count")
	}
	finite := func(x float64, lo, hi float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= lo && x <= hi }
	for i, g := range t.Gaps {
		if !finite(g, 0, 1e7) || !finite(t.Sizes[i], -65575, 65575) {
			return fmt.Errorf("invalid packet sketch")
		}
	}
	for _, n := range []uint64{t.TruncatedSamples, t.DNSQueries, t.DNSResponses, t.NXDomains, t.MalformedDNS, t.HTTPRequests, t.Downloads, t.TLSHellos, t.IRC} {
		if n > t.Samples {
			return fmt.Errorf("invalid telemetry count")
		}
	}
	if t.DNSNameCount > t.Samples*8 || !finite(t.EntropyMax, 0, 8) || !finite(t.EntropySum, 0, float64(t.DNSNameCount)*8) || t.MaxNameLength < 0 || t.MaxNameLength > 253 || t.MaxLabelLength < 0 || t.MaxLabelLength > 63 {
		return fmt.Errorf("invalid DNS statistics")
	}
	if len(t.QueryNames) > 8 || len(t.Bindings) > 16 || len(t.DownloadExtensions) > 8 {
		return fmt.Errorf("rich metadata collection limit")
	}
	validName := func(s string) bool {
		if len(s) == 0 || len(s) > 253 {
			return false
		}
		for _, c := range s {
			if unicode.IsControl(c) || c > 126 {
				return false
			}
		}
		return true
	}
	for _, n := range t.QueryNames {
		if !validName(n) {
			return fmt.Errorf("invalid DNS name")
		}
	}
	for _, b := range t.Bindings {
		if !validName(b.Name) || !b.Address.IsValid() || b.Address.Zone() != "" {
			return fmt.Errorf("invalid name association")
		}
		switch b.Source {
		case "observed DNS answer", "observed TLS SNI", "observed HTTP Host":
		default:
			return fmt.Errorf("invalid name provenance")
		}
	}
	for _, e := range t.DownloadExtensions {
		if len(e) > 10 || len(e) < 2 || e[0] != '.' {
			return fmt.Errorf("invalid extension hint")
		}
	}
	return nil
}
