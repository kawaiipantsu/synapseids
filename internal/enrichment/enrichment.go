// Package enrichment supplies cached, advisory IP context outside the packet
// pipeline. Lookups are bounded, asynchronous, and never change an IDS verdict.
package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Options controls provider access, lookup timeouts and bounded cache retention.
type Options struct {
	Enabled, ReverseDNS, Geo, WHOIS bool
	GeoURL                          string
	Resolver                        string
	TTL, NegativeTTL, Timeout       time.Duration
	MaxEntries                      int
}

// DNS is the status and sanitized PTR names for one address.
type DNS struct {
	Status string   `json:"status"`
	Names  []string `json:"names"`
}

// Geo contains approximate geography and network context supplied by a provider.
type Geo struct {
	Status       string   `json:"status"`
	Source       string   `json:"source,omitempty"`
	Country      string   `json:"country,omitempty"`
	City         string   `json:"city,omitempty"`
	Continent    string   `json:"continent,omitempty"`
	Subdivision  string   `json:"subdivision,omitempty"`
	Latitude     *float64 `json:"latitude,omitempty"`
	Longitude    *float64 `json:"longitude,omitempty"`
	AccuracyKM   *float64 `json:"accuracy_km,omitempty"`
	Timezone     string   `json:"timezone,omitempty"`
	ASN          int      `json:"asn,omitempty"`
	Organization string   `json:"organization,omitempty"`
}

// Registration contains network-allocation metadata, excluding contact records.
type Registration struct {
	Status  string `json:"status"`
	Source  string `json:"source,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Name    string `json:"name,omitempty"`
	Start   string `json:"start,omitempty"`
	End     string `json:"end,omitempty"`
	Type    string `json:"type,omitempty"`
	Country string `json:"country,omitempty"`
	Updated string `json:"updated,omitempty"`
}

// Record is a cached composite lookup with explicit freshness and provider states.
type Record struct {
	IP        string       `json:"ip"`
	Scope     string       `json:"scope"`
	Status    string       `json:"status"`
	UpdatedAt time.Time    `json:"updated_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Stale     bool         `json:"stale"`
	DNS       DNS          `json:"dns"`
	Geo       Geo          `json:"geo"`
	WHOIS     Registration `json:"whois"`
}

type entry struct {
	record  Record
	pending bool
	used    time.Time
}

// Service manages a bounded cache and asynchronous provider workers.
type Service struct {
	opts       Options
	mu         sync.Mutex
	cache      map[netip.Addr]*entry
	backoff    map[string]time.Time
	queue      chan netip.Addr
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	client     *http.Client
	lookupAddr func(context.Context, string) ([]string, error)
	now        func() time.Time
}

// New creates a service; disabled services do not start workers or make requests.
func New(opts Options) *Service {
	if opts.TTL <= 0 {
		opts.TTL = 6 * time.Hour
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = 15 * time.Minute
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 4 * time.Second
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 4096
	}
	if opts.GeoURL == "" {
		opts.GeoURL = "https://api.country.is"
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolver := net.DefaultResolver
	if opts.Resolver != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, opts.Resolver)
		}}
	}
	s := &Service{opts: opts, cache: make(map[netip.Addr]*entry), backoff: make(map[string]time.Time), queue: make(chan netip.Addr, 128),
		ctx: ctx, cancel: cancel, lookupAddr: resolver.LookupAddr, now: time.Now,
		client: &http.Client{Timeout: opts.Timeout, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			// RDAP bootstrap redirects only to the five regional registries. Geo
			// redirects are refused. Remote JSON can never select a request URL.
			if len(via) > 3 || r.URL.Scheme != "https" || r.URL.User != nil || (r.URL.Port() != "" && r.URL.Port() != "443") {
				return http.ErrUseLastResponse
			}
			if len(via) == 0 || via[0].URL.Hostname() != "rdap.org" {
				return http.ErrUseLastResponse
			}
			switch r.URL.Hostname() {
			case "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net":
				return nil
			default:
				return http.ErrUseLastResponse
			}
		}}}
	if opts.Enabled {
		// A shared ticker limits new jobs to two/second, across four workers.
		ticker := time.NewTicker(500 * time.Millisecond)
		for range 4 {
			s.wg.Add(1)
			go s.worker(ticker.C)
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); <-ctx.Done(); ticker.Stop() }()
	}
	return s
}

// Close cancels pending work, joins workers and closes idle HTTP connections.
func (s *Service) Close() { s.cancel(); s.wg.Wait(); s.client.CloseIdleConnections() }

// Public excludes private, link-local, documentation, benchmarking, translation
// and other special-use space before disclosing an address to external services.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return !ip.Is6() || netip.MustParsePrefix("2000::/3").Contains(ip)
}

func empty(ip netip.Addr, status string) Record {
	scope := "special"
	if Public(ip) {
		scope = "public"
	} else if ip.IsPrivate() {
		scope = "private"
	}
	return Record{IP: ip.String(), Scope: scope, Status: status, DNS: DNS{Status: status, Names: []string{}}, Geo: Geo{Status: status}, WHOIS: Registration{Status: status}}
}

// Get returns immediately. Concurrent requests for one address share one job.
// A full queue returns busy without allocating another goroutine or cache entry.
func (s *Service) Get(ip netip.Addr) Record {
	ip = ip.Unmap()
	if s == nil || !s.opts.Enabled || s.ctx.Err() != nil {
		return empty(ip, "disabled")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e := s.cache[ip]
	if e != nil {
		e.used = now
		if e.pending || now.Before(e.record.ExpiresAt) {
			return e.record
		}
	}
	if e == nil && len(s.cache) >= s.opts.MaxEntries {
		var oldest netip.Addr
		var at time.Time
		for key, v := range s.cache {
			if !v.pending && (at.IsZero() || v.used.Before(at)) {
				oldest = key
				at = v.used
			}
		}
		if !oldest.IsValid() {
			return empty(ip, "busy")
		}
		delete(s.cache, oldest)
	}
	select {
	case <-s.ctx.Done():
		return empty(ip, "disabled")
	case s.queue <- ip:
		if e == nil {
			e = &entry{record: empty(ip, "pending")}
			s.cache[ip] = e
		} else {
			e.record.Stale = true
			e.record.Status = "refreshing"
		}
		e.pending = true
		e.used = now
		return e.record
	default:
		if e != nil {
			r := e.record
			r.Stale = true
			return r
		}
		return empty(ip, "busy")
	}
}

func (s *Service) worker(ticks <-chan time.Time) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case ip := <-s.queue:
			select {
			case <-s.ctx.Done():
				return
			case <-ticks:
			}
			r := s.lookup(ip)
			s.mu.Lock()
			if e := s.cache[ip]; e != nil {
				e.record = r
				e.pending = false
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) lookup(ip netip.Addr) Record {
	r := empty(ip, "ready")
	r.DNS.Status = "disabled"
	r.Geo.Status = "disabled"
	r.WHOIS.Status = "disabled"
	if s.opts.ReverseDNS {
		r.DNS.Status = "not_applicable"
		// Private PTR queries use the configured/system resolver only. Never
		// query PTR for synthetic, multicast, unspecified or link-local data.
		if Public(ip) || ip.IsPrivate() {
			ctx, cancel := context.WithTimeout(s.ctx, s.opts.Timeout)
			names, err := s.lookupAddr(ctx, ip.String())
			cancel()
			r.DNS.Status = "not_found"
			if err != nil {
				var dnsErr *net.DNSError
				if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
					r.DNS.Status = "error"
				}
			} else {
				for _, name := range names {
					if len(r.DNS.Names) >= 8 {
						break
					}
					name = clean(strings.TrimSuffix(name, "."))
					if name != "" {
						r.DNS.Names = append(r.DNS.Names, name)
					}
				}
				if len(r.DNS.Names) > 0 {
					r.DNS.Status = "ok"
				}
			}
		}
	}
	if s.opts.Geo {
		if Public(ip) {
			r.Geo = s.geo(ip)
		} else {
			r.Geo.Status = "not_applicable"
		}
	}
	if s.opts.WHOIS {
		if Public(ip) {
			r.WHOIS = s.registration(ip)
		} else {
			r.WHOIS.Status = "not_applicable"
		}
	}
	r.UpdatedAt = s.now()
	ttl := s.opts.TTL
	for _, status := range []string{r.DNS.Status, r.Geo.Status, r.WHOIS.Status} {
		if status == "error" || status == "not_found" || status == "rate_limited" {
			ttl = s.opts.NegativeTTL
			break
		}
	}
	r.ExpiresAt = r.UpdatedAt.Add(ttl)
	return r
}

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	r := []rune(strings.TrimSpace(s))
	if len(r) > 256 {
		r = r[:256]
	}
	return string(r)
}
func country(s string) string {
	s = strings.ToUpper(s)
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

func (s *Service) getJSON(raw string, dst any) (string, string) {
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "error", ""
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "SynapseIDS-IP-context/1")
	provider := req.URL.Hostname()
	s.mu.Lock()
	wait := s.now().Before(s.backoff[provider])
	s.mu.Unlock()
	if wait {
		return "rate_limited", ""
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "error", ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == 404 {
		return "not_found", ""
	}
	if resp.StatusCode == 429 {
		// Share cooldown across addresses rather than retrying a refusing
		// provider for each newly visible host.
		delay := s.opts.NegativeTTL
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 86400 {
			if retry := time.Duration(seconds) * time.Second; retry > delay {
				delay = retry
			}
		} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil && at.After(s.now()) {
			if retry := at.Sub(s.now()); retry > delay && retry <= 24*time.Hour {
				delay = retry
			}
		}
		s.mu.Lock()
		s.backoff[provider] = s.now().Add(delay)
		s.mu.Unlock()
		return "rate_limited", ""
	}
	if resp.StatusCode != 200 {
		return "error", ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, dst) != nil {
		return "error", ""
	}
	return "ok", resp.Request.URL.Hostname()
}

func (s *Service) geo(ip netip.Addr) Geo {
	var data struct {
		IP          string `json:"ip"`
		Country     string `json:"country"`
		City        string `json:"city"`
		Continent   string `json:"continent"`
		Subdivision string `json:"subdivision"`
		Location    struct {
			Latitude  *float64 `json:"latitude"`
			Longitude *float64 `json:"longitude"`
			Accuracy  *float64 `json:"accuracy_radius"`
			Timezone  string   `json:"time_zone"`
		} `json:"location"`
		ASN struct {
			Number       int    `json:"number"`
			Organization string `json:"organization"`
		} `json:"asn"`
	}
	status, source := s.getJSON(strings.TrimRight(s.opts.GeoURL, "/")+"/"+url.PathEscape(ip.String())+"?fields=city,continent,subdivision,location,asn", &data)
	g := Geo{Status: status, Source: source}
	if status != "ok" {
		return g
	}
	got, err := netip.ParseAddr(data.IP)
	if err != nil || got.Unmap() != ip || country(data.Country) == "" {
		g.Status = "not_found"
		return g
	}
	g.Country = country(data.Country)
	g.City = clean(data.City)
	g.Continent = country(data.Continent)
	g.Subdivision = clean(data.Subdivision)
	g.ASN = data.ASN.Number
	g.Organization = clean(data.ASN.Organization)
	g.Timezone = clean(data.Location.Timezone)
	if data.Location.Latitude != nil && data.Location.Longitude != nil && *data.Location.Latitude >= -90 && *data.Location.Latitude <= 90 && *data.Location.Longitude >= -180 && *data.Location.Longitude <= 180 {
		g.Latitude = data.Location.Latitude
		g.Longitude = data.Location.Longitude
		if data.Location.Accuracy != nil && *data.Location.Accuracy >= 0 {
			g.AccuracyKM = data.Location.Accuracy
		}
	}
	return g
}

func (s *Service) registration(ip netip.Addr) Registration {
	var data struct {
		Handle  string `json:"handle"`
		Name    string `json:"name"`
		Start   string `json:"startAddress"`
		End     string `json:"endAddress"`
		Type    string `json:"type"`
		Country string `json:"country"`
		Events  []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	status, source := s.getJSON("https://rdap.org/ip/"+url.PathEscape(ip.String()), &data)
	r := Registration{Status: status, Source: source}
	if status != "ok" {
		return r
	}
	start, e1 := netip.ParseAddr(data.Start)
	end, e2 := netip.ParseAddr(data.End)
	if e1 != nil || e2 != nil || start.BitLen() != ip.BitLen() || end.BitLen() != ip.BitLen() || start.Compare(ip) > 0 || end.Compare(ip) < 0 {
		r.Status = "error"
		return r
	}
	r.Handle = clean(data.Handle)
	r.Name = clean(data.Name)
	r.Start = start.String()
	r.End = end.String()
	r.Type = clean(data.Type)
	r.Country = country(data.Country)
	for _, ev := range data.Events {
		if ev.Action == "last changed" {
			if _, err := time.Parse(time.RFC3339, ev.Date); err == nil {
				r.Updated = ev.Date
			}
		}
	}
	return r
}
