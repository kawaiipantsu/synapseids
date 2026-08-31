package api

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// Host profiles are sensitive network telemetry: they name every address the
// sensor has seen and how it behaves (PROJECT.md §21). These routes are
// read-only, so unlike the model-activation routes they need no explicit-action
// gate, but they inherit the daemon's loopback-only default posture and must sit
// behind an authenticating proxy on any non-loopback listener.
//
// Every address in a response is a packet-derived string. It is emitted as a
// plain JSON string value and never interpolated into markup, a header, a log
// format or a query (§28.11).

// hostScanLimit is how many recent stored records a per-host query walks. Like
// classFilterScan, this is the memory store's substitute for an index; a
// predicate-pushdown backend will replace it.
const hostScanLimit = 5000

// handleHosts serves GET /api/v1/hosts.
//
//	limit  — max profiles (default 100, cap 2000)
//	q      — case-insensitive substring match on the address
//	sort   — last_seen (default) | flows | bytes
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if s.insight == nil {
		writeJSON(w, http.StatusOK, []insight.Profile{})
		return
	}
	q := r.URL.Query()
	ord, ok := insight.ParseSort(q.Get("sort"))
	if !ok {
		http.Error(w, "bad sort: want last_seen, flows or bytes", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.insight.Hosts(q.Get("q"), ord, limitParam(r, 2000)))
}

// handleHost serves GET /api/v1/hosts/{ip}.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	ip, ok := hostPathValue(w, r)
	if !ok {
		return
	}
	if s.insight == nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	p, found := s.insight.Host(ip)
	if !found {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleHostFlows serves GET /api/v1/hosts/{ip}/flows. It accepts the same
// filter parameters as GET /api/v1/classifications plus from/to, so an operator
// does not have to learn a second dialect. The classification predicates (class,
// model, min_confidence, disagreement) are applied by joining each flow to its
// verdict from the recent classification window.
func (s *Server) handleHostFlows(w http.ResponseWriter, r *http.Request) {
	ip, ok := hostPathValue(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f, ok := parseClassFilters(w, q)
	if !ok {
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}
	limit := limitParam(r, 2000)

	var verdict map[uint64]storage.Classification
	if !f.empty() {
		rows := s.store.RecentClassifications(hostScanLimit)
		verdict = make(map[uint64]storage.Classification, len(rows))
		for _, c := range rows {
			// Newest first: keep the first verdict seen for a flow.
			if _, seen := verdict[c.FlowID]; !seen {
				verdict[c.FlowID] = c
			}
		}
	}

	out := make([]storage.FlowRecord, 0, min(limit, 128))
	for _, fr := range s.store.RecentFlows(hostScanLimit) {
		if fr.InitiatorIP != ip && fr.ResponderIP != ip {
			continue
		}
		if !tr.contains(fr.LastSeen) {
			continue
		}
		if verdict != nil {
			c, found := verdict[fr.ID]
			if !found || !f.match(c) {
				continue
			}
		}
		out = append(out, fr)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleHostClassifications serves GET /api/v1/hosts/{ip}/classifications with
// the same filter parameters as GET /api/v1/classifications, plus from/to.
func (s *Server) handleHostClassifications(w http.ResponseWriter, r *http.Request) {
	ip, ok := hostPathValue(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f, ok := parseClassFilters(w, q)
	if !ok {
		return
	}
	tr, ok := parseTimeRange(w, q)
	if !ok {
		return
	}
	limit := limitParam(r, 2000)

	out := make([]storage.Classification, 0, min(limit, 128))
	for _, c := range s.store.RecentClassifications(hostScanLimit) {
		if c.InitiatorIP != ip && c.ResponderIP != ip {
			continue
		}
		if !tr.contains(c.TS) || !f.match(c) {
			continue
		}
		out = append(out, c)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// hostPathValue validates the {ip} path segment. Addresses reaching this API
// came from decoded packets, so the handler re-parses rather than trusting the
// request: anything that is not an IP literal is a 400, never a lookup key.
// The canonical netip form is returned so "10.0.0.1" and "::ffff:10.0.0.1"
// cannot address the same profile under two spellings.
func hostPathValue(w http.ResponseWriter, r *http.Request) (string, bool) {
	return parseHostParam(w, r.PathValue("ip"))
}

// parseHostParam canonicalises one address, writing a 400 if it is not an IP
// literal. It backs both the {ip} path segment and the timeline's host= query.
func parseHostParam(w http.ResponseWriter, raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		http.Error(w, "bad host address: want an IPv4 or IPv6 literal", http.StatusBadRequest)
		return "", false
	}
	return addr.Unmap().String(), true
}

// timeRange is an optional inclusive from/to filter parsed from RFC3339 values.
type timeRange struct {
	from, to time.Time
}

func (t timeRange) contains(ts time.Time) bool {
	if !t.from.IsZero() && ts.Before(t.from) {
		return false
	}
	if !t.to.IsZero() && ts.After(t.to) {
		return false
	}
	return true
}

// parseTimeRange reads from= and to= as RFC3339. On a bad value it writes a 400
// and returns ok=false.
func parseTimeRange(w http.ResponseWriter, q url.Values) (timeRange, bool) {
	var tr timeRange
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"from", &tr.from}, {"to", &tr.to}} {
		v := q.Get(p.name)
		if v == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "bad "+p.name+": want an RFC3339 timestamp", http.StatusBadRequest)
			return tr, false
		}
		*p.dst = ts
	}
	if !tr.from.IsZero() && !tr.to.IsZero() && tr.to.Before(tr.from) {
		http.Error(w, "bad range: to is before from", http.StatusBadRequest)
		return tr, false
	}
	return tr, true
}
