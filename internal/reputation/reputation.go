// Package reputation supplies advisory feed and DNSBL matches. It never blocks
// packets or changes a neural label. Network requests run on bounded workers.
package reputation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/enrichment"
	"github.com/kawaiipantsu/synapseids/internal/policy"
)

const maxFeedBytes = 8 << 20

// Finding preserves the provider, reason, matched range and lookup time.
type Finding struct {
	Tag       string    `json:"tag"`
	Provider  string    `json:"provider"`
	Reason    string    `json:"reason"`
	CIDR      string    `json:"cidr,omitempty"`
	Score     int       `json:"score,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Stale     bool      `json:"stale"`
}

// Record distinguishes pending/unavailable checks from absence of a listing.
type Record struct {
	Status   string    `json:"status"`
	Findings []Finding `json:"findings"`
}

// FeedStatus is safe provider health metadata; it contains no secret fields.
type FeedStatus struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Entries   int       `json:"entries"`
	UpdatedAt time.Time `json:"updated_at"`
	Copyright string    `json:"copyright,omitempty"`
}
type feed struct {
	status    FeedStatus
	entries   map[netip.Prefix]string
	attempted time.Time
}
type online struct {
	record  Record
	expires time.Time
	pending bool
}

// DNSBL config uses explicit response-code semantics. A generic non-NXDOMAIN
// answer is never assumed malicious: providers also return policy/error codes.
type DNSBL struct {
	Name  string            `json:"name"`
	Zone  string            `json:"zone"`
	Codes map[string]string `json:"codes"`
}

// Service caches provider data and owns refresh and lookup goroutines.
type Service struct {
	pol      *policy.Store
	mu       sync.Mutex
	feeds    map[string]*feed
	cache    map[netip.Addr]*online
	key      string
	zones    []DNSBL
	client   *http.Client
	resolver *net.Resolver
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	queue    chan netip.Addr
	day      string
	checks   int
	backoff  time.Time
}

var feedURLs = map[string]string{"spamhaus-v4": "https://www.spamhaus.org/drop/drop_v4.json", "spamhaus-v6": "https://www.spamhaus.org/drop/drop_v6.json", "cins-army": "https://cinsscore.com/list/ci-badguys.txt"}

// New starts feed refresh and a rate-limited lookup worker. Missing credentials
// leave optional providers visibly unconfigured, without querying anonymously.
func New(pol *policy.Store, keyFile, dnsFile string) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{pol: pol, ctx: ctx, cancel: cancel, feeds: map[string]*feed{}, cache: map[netip.Addr]*online{}, queue: make(chan netip.Addr, 128), resolver: net.DefaultResolver,
		client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if b, err := os.ReadFile(keyFile); err == nil && len(b) <= 1024 {
		s.key = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(dnsFile); err == nil && len(b) <= 16384 {
		var zones []DNSBL
		if json.Unmarshal(b, &zones) == nil && validZones(zones) {
			s.zones = zones
		}
	}
	for id := range feedURLs {
		f := &feed{status: FeedStatus{ID: id, Status: "not_loaded"}, entries: map[netip.Prefix]string{}}
		path := filepath.Join(pol.Directory(), "reputation-"+id+".cache")
		if b, err := os.ReadFile(path); err == nil && len(b) <= maxFeedBytes {
			if entries, credit, e := parseFeed(id, b); e == nil {
				if st, e := os.Stat(path); e == nil && time.Since(st.ModTime()) < 48*time.Hour {
					f.entries = entries
					f.status = FeedStatus{ID: id, Status: "cached", Entries: len(entries), UpdatedAt: st.ModTime(), Copyright: credit}
				}
			}
		}
		s.feeds[id] = f
	}
	s.wg.Add(2)
	go s.refreshLoop()
	go s.lookupLoop()
	return s
}

// Close stops and joins provider work.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.cancel()
	s.wg.Wait()
	s.client.CloseIdleConnections()
}
func validZones(z []DNSBL) bool {
	if len(z) > 8 {
		return false
	}
	for _, v := range z {
		if len(v.Name) == 0 || len(v.Name) > 40 || strings.ContainsAny(v.Name, "\r\n") {
			return false
		}
		if len(v.Zone) > 253 || len(v.Zone) == 0 || len(v.Codes) == 0 || len(v.Codes) > 32 {
			return false
		}
		for _, c := range v.Zone {
			validChar := c == '.' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			if !validChar {
				return false
			}
		}
		for code, reason := range v.Codes {
			a, e := netip.ParseAddr(code)
			if e != nil || !netip.MustParsePrefix("127.0.0.0/24").Contains(a) || a == netip.MustParseAddr("127.0.0.1") || len(reason) > 120 {
				return false
			}
		}
	}
	return true
}
func enabled(d policy.Document, id string) bool {
	if id == "cins-army" {
		return d.CINSArmy
	}
	return d.Spamhaus
}
func (s *Service) refreshLoop() {
	defer s.wg.Done()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		s.refresh()
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (s *Service) refresh() {
	d := s.pol.Get()
	for id, u := range feedURLs {
		if !enabled(d, id) {
			continue
		}
		s.mu.Lock()
		f := s.feeds[id]
		due := time.Since(f.attempted) > 6*time.Hour
		if due {
			f.attempted = time.Now()
		}
		s.mu.Unlock()
		if !due {
			continue
		}
		req, e := http.NewRequestWithContext(s.ctx, http.MethodGet, u, nil)
		if e != nil {
			continue
		}
		req.Header.Set("User-Agent", "SynapseIDS/1.0 reputation-cache")
		res, e := s.client.Do(req)
		var b []byte
		if e == nil {
			if res.StatusCode == 200 {
				b, e = io.ReadAll(io.LimitReader(res.Body, maxFeedBytes+1))
			} else {
				e = fmt.Errorf("provider HTTP status %d", res.StatusCode)
			}
			_ = res.Body.Close()
		}
		var entries map[netip.Prefix]string
		var credit string
		if e == nil {
			entries, credit, e = parseFeed(id, b)
		}
		s.mu.Lock()
		if e != nil {
			f.status.Status = "unavailable"
		} else {
			f.entries = entries
			f.status = FeedStatus{ID: id, Status: "ok", Entries: len(entries), UpdatedAt: time.Now().UTC(), Copyright: credit}
		}
		s.mu.Unlock()
		if e == nil {
			path := filepath.Join(s.pol.Directory(), "reputation-"+id+".cache")
			_ = os.MkdirAll(s.pol.Directory(), 0700)
			if tmp, e := os.CreateTemp(s.pol.Directory(), "reputation-*.tmp"); e == nil {
				name := tmp.Name()
				_, e = tmp.Write(b)
				ce := tmp.Close()
				if e == nil && ce == nil {
					_ = os.Rename(name, path)
				}
				_ = os.Remove(name)
			}
		}
	}
}
func parseFeed(id string, b []byte) (map[netip.Prefix]string, string, error) {
	if len(b) == 0 || len(b) > maxFeedBytes {
		return nil, "", fmt.Errorf("feed size out of bounds")
	}
	entries := map[netip.Prefix]string{}
	credit := ""
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 4096), 65536)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, reason := line, "Listed by CINS Army"
		if id != "cins-army" {
			var row struct {
				CIDR      string `json:"cidr"`
				SBL       string `json:"sblid"`
				Copyright string `json:"copyright"`
			}
			if json.Unmarshal([]byte(line), &row) != nil {
				return nil, "", fmt.Errorf("invalid feed JSON")
			}
			if row.Copyright != "" {
				credit = row.Copyright
			}
			if row.CIDR == "" {
				continue
			}
			raw = row.CIDR
			reason = "Spamhaus DROP " + row.SBL
		}
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			a, ae := netip.ParseAddr(raw)
			if ae != nil {
				return nil, "", fmt.Errorf("invalid feed address")
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		if p.Bits() == 0 || !enrichment.Public(p.Addr()) {
			return nil, "", fmt.Errorf("feed contains special-use range")
		}
		entries[p] = reason
		if len(entries) > 100000 {
			return nil, "", fmt.Errorf("too many feed entries")
		}
	}
	if e := scan.Err(); e != nil {
		return nil, "", e
	}
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("empty feed")
	}
	return entries, credit, nil
}

// Status returns health and configuration flags without provider credentials.
func (s *Service) Status() []FeedStatus {
	if s == nil {
		return []FeedStatus{}
	}
	d := s.pol.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []FeedStatus{}
	for _, id := range []string{"spamhaus-v4", "spamhaus-v6", "cins-army"} {
		st := s.feeds[id].status
		if !enabled(d, id) {
			st.Status = "disabled"
		} else if !st.UpdatedAt.IsZero() && time.Since(st.UpdatedAt) > 48*time.Hour {
			st.Status = "expired"
		}
		out = append(out, st)
	}
	for _, p := range []struct {
		id             string
		on, configured bool
	}{{"abuseipdb", d.AbuseIPDB, s.key != ""}, {"dnsbl", d.DNSBL, len(s.zones) > 0}} {
		st := "disabled"
		if p.on {
			st = "configured"
			if !p.configured {
				st = "needs_credentials"
			}
		}
		out = append(out, FeedStatus{ID: p.id, Status: st})
	}
	return out
}

// Get matches downloaded feeds immediately and queues optional online checks.
// Call only for observed public addresses. A miss means unlisted, not trusted.
func (s *Service) Get(ip netip.Addr) Record {
	out := Record{Status: "disabled", Findings: []Finding{}}
	if s == nil {
		return out
	}
	ip = ip.Unmap()
	if !enrichment.Public(ip) {
		out.Status = "not_applicable"
		return out
	}
	if s.pol.Lookup(ip).Excluded {
		out.Status = "excluded"
		return out
	}
	d := s.pol.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, f := range s.feeds {
		if !enabled(d, id) {
			continue
		}
		out.Status = "checked"
		age := now.Sub(f.status.UpdatedAt)
		if age > 48*time.Hour {
			out.Status = "incomplete"
			continue
		}
		for bits := ip.BitLen(); bits > 0; bits-- {
			p := netip.PrefixFrom(ip, bits).Masked()
			if reason, ok := f.entries[p]; ok {
				out.Findings = append(out.Findings, Finding{Tag: "BadRep", Provider: id, Reason: reason, CIDR: p.String(), CheckedAt: f.status.UpdatedAt, ExpiresAt: f.status.UpdatedAt.Add(48 * time.Hour), Stale: age > 6*time.Hour})
				break
			}
		}
	}
	want := d.AbuseIPDB && s.key != "" || d.DNSBL && len(s.zones) > 0
	if d.AbuseIPDB && s.key == "" || d.DNSBL && len(s.zones) == 0 {
		out.Status = "incomplete"
	}
	if !want || s.ctx.Err() != nil {
		return out
	}
	row := s.cache[ip]
	if row != nil && now.Before(row.expires) {
		for _, f := range row.record.Findings {
			if f.Provider == "abuseipdb" && !d.AbuseIPDB || f.Tag == "RBL" && !d.DNSBL {
				continue
			}
			out.Findings = append(out.Findings, f)
		}
		if row.record.Status != "checked" {
			out.Status = row.record.Status
		} else if out.Status == "disabled" {
			out.Status = "checked"
		}
		return out
	}
	if row == nil {
		if len(s.cache) >= 4096 {
			for k, r := range s.cache {
				if !r.pending {
					delete(s.cache, k)
					break
				}
			}
		}
		if len(s.cache) >= 4096 {
			out.Status = "busy"
			return out
		}
		row = &online{}
		s.cache[ip] = row
	}
	out.Status = "pending"
	if !row.pending {
		select {
		case s.queue <- ip:
			row.pending = true
		default:
			out.Status = "busy"
		}
	}
	return out
}
func (s *Service) lookupLoop() {
	defer s.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case ip := <-s.queue:
			select {
			case <-s.ctx.Done():
				return
			case <-tick.C:
			}
			r := s.lookup(ip)
			s.mu.Lock()
			if row := s.cache[ip]; row != nil {
				ttl := 24 * time.Hour
				if r.Status != "checked" {
					ttl = time.Hour
				}
				row.record = r
				row.expires = time.Now().Add(ttl)
				row.pending = false
			}
			s.mu.Unlock()
		}
	}
}
func (s *Service) lookup(ip netip.Addr) Record {
	out := Record{Status: "checked", Findings: []Finding{}}
	d := s.pol.Get()
	now := time.Now().UTC()
	if s.pol.Lookup(ip).Excluded {
		out.Status = "excluded"
		return out
	}
	if d.AbuseIPDB && s.key != "" {
		// 100 unique checks/day bounds a free account's usage. Every result, including
		// failures, is cached; never submit abuse reports based on IDS predictions.
		day := now.Format("2006-01-02")
		if s.day != day {
			s.day = day
			s.checks = 0
		}
		if s.checks >= 100 || now.Before(s.backoff) {
			out.Status = "rate_limited"
		} else {
			s.checks++
			u := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=30&ipAddress=" + url.QueryEscape(ip.String())
			req, e := http.NewRequestWithContext(s.ctx, http.MethodGet, u, nil)
			if e == nil {
				req.Header.Set("Key", s.key)
				req.Header.Set("Accept", "application/json")
				res, err := s.client.Do(req)
				if err != nil {
					out.Status = "unavailable"
				} else {
					b, er := io.ReadAll(io.LimitReader(res.Body, 65537))
					_ = res.Body.Close()
					if res.StatusCode == 429 {
						s.backoff = now.Add(24 * time.Hour)
						out.Status = "rate_limited"
					} else if er != nil || len(b) > 65536 || res.StatusCode != 200 {
						out.Status = "unavailable"
					} else {
						var v struct {
							Data struct {
								IP    string `json:"ipAddress"`
								Score int    `json:"abuseConfidenceScore"`
							}
						}
						if json.Unmarshal(b, &v) != nil || v.Data.IP != ip.String() || v.Data.Score < 0 || v.Data.Score > 100 {
							out.Status = "unavailable"
						} else if v.Data.Score >= 75 {
							out.Findings = append(out.Findings, Finding{Tag: "BadRep", Provider: "abuseipdb", Reason: "Abuse confidence at least 75 (30-day reports)", Score: v.Data.Score, CheckedAt: now, ExpiresAt: now.Add(24 * time.Hour)})
						}
					}
				}
			}
		}
	}
	if d.DNSBL {
		for _, z := range s.zones {
			ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
			ips, e := s.resolver.LookupNetIP(ctx, "ip4", reverse(ip)+"."+z.Zone)
			cancel()
			if e != nil {
				var de *net.DNSError
				if !asNotFound(e, &de) {
					out.Status = "unavailable"
				}
				continue
			}
			matched := false
			for _, a := range ips {
				if reason, ok := z.Codes[a.String()]; ok {
					out.Findings = append(out.Findings, Finding{Tag: "RBL", Provider: z.Name, Reason: reason, CheckedAt: now, ExpiresAt: now.Add(24 * time.Hour)})
					matched = true
					break
				}
			}
			if !matched && len(ips) > 0 {
				out.Status = "unrecognized_response"
			}
		}
	}
	return out
}
func asNotFound(e error, de **net.DNSError) bool {
	v, ok := e.(*net.DNSError)
	if ok {
		*de = v
	}
	return ok && v.IsNotFound
}
func reverse(ip netip.Addr) string {
	if ip.Is4() {
		a := ip.As4()
		return strconv.Itoa(int(a[3])) + "." + strconv.Itoa(int(a[2])) + "." + strconv.Itoa(int(a[1])) + "." + strconv.Itoa(int(a[0]))
	}
	a := ip.As16()
	parts := make([]string, 0, 32)
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", a[i]&15), fmt.Sprintf("%x", a[i]>>4))
	}
	return strings.Join(parts, ".")
}
