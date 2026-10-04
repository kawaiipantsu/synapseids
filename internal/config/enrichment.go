package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

// Enrichment is restart-only. External context is opt-in; Geo can be self-hosted.
type Enrichment struct {
	Enabled     bool     `json:"enabled"`
	ReverseDNS  bool     `json:"reverse_dns"`
	Geo         bool     `json:"geo"`
	WHOIS       bool     `json:"whois"`
	GeoURL      string   `json:"geo_url"`
	Resolver    string   `json:"resolver"`
	CacheTTL    Duration `json:"cache_ttl"`
	NegativeTTL Duration `json:"negative_ttl"`
	Timeout     Duration `json:"timeout"`
	MaxEntries  int      `json:"max_entries"`
}

// DefaultEnrichment returns bounded provider defaults with enrichment disabled.
func DefaultEnrichment() Enrichment {
	return Enrichment{ReverseDNS: true, Geo: true, WHOIS: true, GeoURL: "https://api.country.is",
		CacheTTL: Duration(6 * time.Hour), NegativeTTL: Duration(15 * time.Minute), Timeout: Duration(4 * time.Second), MaxEntries: 4096}
}

// ValidateEnrichment checks provider URLs, resolver addresses and resource bounds.
func ValidateEnrichment(e Enrichment) error {
	if !e.Enabled {
		return nil
	}
	if e.MaxEntries < 16 || e.MaxEntries > 65536 {
		return fmt.Errorf("enrichment.max_entries must be between 16 and 65536")
	}
	if time.Duration(e.CacheTTL) < time.Minute || time.Duration(e.CacheTTL) > 7*24*time.Hour {
		return fmt.Errorf("enrichment.cache_ttl must be between 1m and 168h")
	}
	if time.Duration(e.NegativeTTL) < time.Minute || e.NegativeTTL > e.CacheTTL {
		return fmt.Errorf("enrichment.negative_ttl must be between 1m and cache_ttl")
	}
	if time.Duration(e.Timeout) < 100*time.Millisecond || time.Duration(e.Timeout) > 30*time.Second {
		return fmt.Errorf("enrichment.timeout must be between 100ms and 30s")
	}
	if e.Geo {
		u, err := url.Parse(e.GeoURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("enrichment.geo_url must be an HTTP(S) base URL without credentials, query or fragment")
		}
	}
	if e.Resolver != "" {
		h, p, err := net.SplitHostPort(e.Resolver)
		ip, ipErr := netip.ParseAddr(h)
		port, portErr := strconv.Atoi(p)
		if err != nil || ipErr != nil || ip.Zone() != "" || portErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("enrichment.resolver must be an IP:port DNS resolver")
		}
	}
	return nil
}
