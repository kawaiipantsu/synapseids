package flow

import (
	"math"
	"slices"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Telemetry is the bounded rich-flow-v2 evidence. Released v1 frames omit it.
// Sample arrays are a ring of the last 32 captured packet gaps and signed sizes.
type Telemetry struct {
	TruncatedSamples   uint64               `json:"truncated_samples,omitempty"`
	Samples            uint64               `json:"samples"`
	Gaps               [32]float64          `json:"gaps"`
	Sizes              [32]float64          `json:"sizes"`
	DNSQueries         uint64               `json:"dns_queries"`
	DNSResponses       uint64               `json:"dns_responses"`
	NXDomains          uint64               `json:"nxdomains"`
	MalformedDNS       uint64               `json:"malformed_dns"`
	EntropySum         float64              `json:"entropy_sum"`
	EntropyMax         float64              `json:"entropy_max"`
	DNSNameCount       uint64               `json:"dns_name_count"`
	MaxNameLength      int                  `json:"max_name_length"`
	MaxLabelLength     int                  `json:"max_label_length"`
	QueryNames         []string             `json:"query_names,omitempty"`
	Bindings           []packet.NameBinding `json:"bindings,omitempty"`
	HTTPRequests       uint64               `json:"http_requests"`
	Downloads          uint64               `json:"downloads"`
	DownloadExtensions []string             `json:"download_extensions,omitempty"`
	TLSHellos          uint64               `json:"tls_hellos"`
	IRC                uint64               `json:"irc"`
	HasSNI             bool                 `json:"has_sni"`
	HasHTTPHost        bool                 `json:"has_http_host"`
}

func (t *Telemetry) clone() *Telemetry {
	if t == nil {
		return nil
	}
	c := *t
	c.QueryNames = append([]string{}, t.QueryNames...)
	c.Bindings = append([]packet.NameBinding{}, t.Bindings...)
	c.DownloadExtensions = append([]string{}, t.DownloadExtensions...)
	return &c
}
func (e *entry) foldTelemetry(p packet.Packet, forward bool) {
	if e.Telemetry == nil {
		e.Telemetry = &Telemetry{}
	}
	t := e.Telemetry
	slot := t.Samples % 32
	gap := 0.0
	if t.Samples > 0 && p.TS.After(e.LastSeen) {
		gap = p.TS.Sub(e.LastSeen).Seconds()
	}
	t.Gaps[slot] = gap
	size := float64(p.TotalLen)
	if !forward {
		size = -size
	}
	t.Sizes[slot] = size
	t.Samples++
	if p.Truncated {
		t.TruncatedSamples++
	}
	m := p.Metadata
	if m == nil {
		return
	}
	if m.DNSQuery {
		t.DNSQueries++
	}
	if m.DNSResponse {
		t.DNSResponses++
	}
	if m.DNSNXDomain {
		t.NXDomains++
	}
	if m.DNSMalformed {
		t.MalformedDNS++
	}
	if m.DNSQuery {
		for _, name := range m.DNSNames {
			t.DNSNameCount++
			h := packet.LabelEntropy(name)
			t.EntropySum += h
			t.EntropyMax = math.Max(t.EntropyMax, h)
			t.MaxNameLength = max(t.MaxNameLength, len(name))
			for _, l := range strings.Split(name, ".") {
				t.MaxLabelLength = max(t.MaxLabelLength, len(l))
			}
			if len(t.QueryNames) < 8 && !slices.Contains(t.QueryNames, name) {
				t.QueryNames = append(t.QueryNames, name)
			}
		}
	}
	for _, binding := range m.Bindings {
		if len(t.Bindings) < 16 && !slices.Contains(t.Bindings, binding) {
			t.Bindings = append(t.Bindings, binding)
		}
	}
	if m.HTTPRequest {
		t.HTTPRequests++
	}
	if m.Download {
		t.Downloads++
		if m.DownloadExtension != "" && len(t.DownloadExtensions) < 8 && !slices.Contains(t.DownloadExtensions, m.DownloadExtension) {
			t.DownloadExtensions = append(t.DownloadExtensions, m.DownloadExtension)
		}
	}
	if m.TLSClientHello {
		t.TLSHellos++
	}
	if m.IRC {
		t.IRC++
	}
	if m.TLSServerName != "" {
		t.HasSNI = true
		if len(t.Bindings) < 16 {
			t.Bindings = append(t.Bindings, packet.NameBinding{Name: m.TLSServerName, Address: p.DstIP, TTL: 3600, Source: "observed TLS SNI"})
		}
	}
	if m.HTTPHost != "" {
		t.HasHTTPHost = true
		if len(t.Bindings) < 16 {
			t.Bindings = append(t.Bindings, packet.NameBinding{Name: m.HTTPHost, Address: p.DstIP, TTL: 3600, Source: "observed HTTP Host"})
		}
	}
}

// Ordered returns valid samples oldest first; leading padding is left to features.
func (t *Telemetry) Ordered() (gaps, sizes []float64) {
	if t == nil {
		return nil, nil
	}
	n := min(t.Samples, 32)
	start := uint64(0)
	if t.Samples > 32 {
		start = t.Samples % 32
	}
	for i := uint64(0); i < n; i++ {
		slot := (start + i) % 32
		gaps = append(gaps, t.Gaps[slot])
		sizes = append(sizes, t.Sizes[slot])
	}
	return
}
