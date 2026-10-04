package api

import (
	"net/http"
	"net/netip"

	"github.com/kawaiipantsu/synapseids/internal/enrichment"
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
	rows := make([]enrichment.Record, 0, len(addrs))
	for _, ip := range addrs {
		if _, found := s.insight.Host(ip.String()); !found {
			rows = append(rows, enrichment.Record{IP: ip.String(), Status: "unobserved", DNS: enrichment.DNS{Status: "unobserved", Names: []string{}}, Geo: enrichment.Geo{Status: "unobserved"}, WHOIS: enrichment.Registration{Status: "unobserved"}})
			continue
		}
		rows = append(rows, s.enrichment.Get(ip))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"hosts": rows})
}
