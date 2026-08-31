package features_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// flow-features-v1 defines the four rate features' behaviour when a flow has no
// measurable duration, and the code must implement what the schema says rather
// than something merely plausible.
//
// It did not. Dividing by the 1e-6 duration floor made a single-packet flow
// report 1,000,000 packets/second. On a live WAN sensor that fired heuristic rule
// dos.udp_flood (pps >= 500) on every single-packet DNS response — ordinary
// replies from AWS and Cloudflare reported as dos_ddos, severity critical, 100%
// confidence.
//
// The assertions below are driven by the schema's own `missing` text, so the test
// cannot drift away from the contract it is protecting.
func TestZeroDurationRatesFollowTheSchemaContract(t *testing.T) {
	ts := time.Date(2026, 8, 31, 20, 2, 14, 0, time.UTC)

	// A single inbound UDP packet: exactly the DNS-response shape that broke.
	rec := flow.Record{
		ID:         1,
		FwdPackets: 1,
		FwdBytes:   73,
		FirstSeen:  ts,
		LastSeen:   ts, // identical: duration is genuinely zero
		PktSizeMin: 73,
		PktSizeMax: 73,
	}
	if rec.Duration() != 0 {
		t.Fatalf("fixture is not zero-duration: %v", rec.Duration())
	}

	v := features.Extract(rec)
	fs := schema.FlowFeaturesV1()

	for _, tc := range []struct {
		index int
		name  string
		want  float64
	}{
		{11, "packets_per_second", 1},          // total packets
		{12, "bytes_per_second", 73},           // total bytes
		{13, "forward_packets_per_second", 1},  // packets_forward
		{14, "backward_packets_per_second", 0}, // packets_backward
	} {
		f := fs.Features[tc.index]
		if f.Name != tc.name {
			t.Fatalf("schema index %d is %q, want %q — the frozen order changed", tc.index, f.Name, tc.name)
		}
		// The schema documents each of these as "<something> when duration is 0".
		if !strings.Contains(f.Missing, "when duration is 0") {
			t.Fatalf("%s: schema `missing` is %q; this test assumes the zero-duration clause",
				f.Name, f.Missing)
		}
		if got := v.Values[tc.index]; got != tc.want {
			t.Errorf("%s = %v, want %v (schema says %q)", f.Name, got, tc.want, f.Missing)
		}
	}
}
