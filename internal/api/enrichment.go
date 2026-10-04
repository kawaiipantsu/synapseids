package api

import (
	"net/http"
	"net/netip"

	"github.com/kawaiipantsu/synapseids/internal/enrichment"
	"github.com/kawaiipantsu/synapseids/internal/policy"
	"github.com/kawaiipantsu/synapseids/internal/reputation"
)

// Only observed addresses can trigger lookups; this is not an IP lookup proxy.
func (s *Server) handleEnrichment(w http.ResponseWriter, r *http.Request) {
	ips := r.URL.Query()["ip"]
	if len(ips) == 0 || len(ips) > 64 {
		http.Error(w, "supply 1..64 ip parameters", http.StatusBadRequest)
		return
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, raw := range ips {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" {
			http.Error(w, "invalid IP address", http.StatusBadRequest)
			return
		}
		addrs = append(addrs, ip.Unmap())
	}
	type row struct {
		enrichment.Record
		Asset      policy.Match      `json:"asset"`
		Reputation reputation.Record `json:"reputation"`
	}
	rows := make([]row, 0, len(addrs))
	for _, ip := range addrs {
		if asset := s.policy.Lookup(ip); asset.Excluded {
			rows = append(rows, row{Record: enrichment.Record{IP: ip.String(), Status: "excluded", DNS: enrichment.DNS{Status: "excluded", Names: []string{}}, Geo: enrichment.Geo{Status: "excluded"}, WHOIS: enrichment.Registration{Status: "excluded"}}, Asset: asset, Reputation: reputation.Record{Status: "excluded", Findings: []reputation.Finding{}}})
			continue
		}
		if _, found := s.insight.Host(ip.String()); !found {
			rows = append(rows, row{Record: enrichment.Record{IP: ip.String(), Status: "unobserved", DNS: enrichment.DNS{Status: "unobserved", Names: []string{}}, Geo: enrichment.Geo{Status: "unobserved"}, WHOIS: enrichment.Registration{Status: "unobserved"}}, Asset: s.policy.Lookup(ip), Reputation: reputation.Record{Status: "unobserved", Findings: []reputation.Finding{}}})
			continue
		}
		rows = append(rows, row{Record: s.enrichment.Get(ip), Asset: s.policy.Lookup(ip), Reputation: s.reputation.Get(ip)})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"hosts": rows})
}
