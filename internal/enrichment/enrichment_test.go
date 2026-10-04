package enrichment

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicBoundaries(t *testing.T) {
	for _, raw := range []string{"10.0.0.1", "127.0.0.1", "192.0.2.1", "198.51.100.3", "203.0.113.8", "100.64.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:192.168.1.1", "2002:0808:0808::1"} {
		if Public(netip.MustParseAddr(raw)) {
			t.Errorf("special address considered public: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !Public(netip.MustParseAddr(raw)) {
			t.Errorf("public address excluded: %s", raw)
		}
	}
}

func TestLookupsKeepPrivateAddressesLocalAndCacheNegativeResults(t *testing.T) {
	s := New(Options{ReverseDNS: true, Geo: true, WHOIS: true})
	defer s.Close()
	s.lookupAddr = func(_ context.Context, ip string) ([]string, error) { return []string{"host.example.test."}, nil }
	s.client.Transport = transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("private address sent externally")
		return nil, nil
	})
	r := s.lookup(netip.MustParseAddr("10.0.0.8"))
	if r.DNS.Status != "ok" || r.DNS.Names[0] != "host.example.test" || r.Geo.Status != "not_applicable" || r.WHOIS.Status != "not_applicable" {
		t.Fatalf("unexpected private result: %+v", r)
	}
	s.lookupAddr = func(context.Context, string) ([]string, error) { t.Fatal("synthetic PTR query"); return nil, nil }
	r = s.lookup(netip.MustParseAddr("203.0.113.1"))
	if r.DNS.Status != "not_applicable" {
		t.Fatal(r.DNS)
	}
}

func TestProviderParsingAndLimits(t *testing.T) {
	s := New(Options{Geo: true, WHOIS: true})
	defer s.Close()
	s.client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		body := `{"ip":"8.8.8.8","country":"US","city":"Example city","location":{"latitude":10,"longitude":20,"accuracy_radius":50},"asn":{"number":15169,"organization":"Example network"}}`
		if r.URL.Hostname() == "rdap.org" {
			body = `{"handle":"NET-EXAMPLE","name":"Example network","startAddress":"8.8.8.0","endAddress":"8.8.8.255","country":"US","entities":[{"email":"excluded@example.test"}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	r := s.lookup(netip.MustParseAddr("8.8.8.8"))
	if r.Geo.Status != "ok" || r.Geo.Country != "US" || r.Geo.ASN != 15169 || r.WHOIS.Handle != "NET-EXAMPLE" {
		t.Fatalf("provider parsing failed: %+v", r)
	}
	s.client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	r = s.lookup(netip.MustParseAddr("8.8.8.8"))
	if r.Geo.Status != "rate_limited" || r.ExpiresAt.Sub(r.UpdatedAt) != s.opts.NegativeTTL {
		t.Fatal("negative caching missing")
	}
	s.client.Transport = transport(func(*http.Request) (*http.Response, error) { t.Fatal("provider cooldown ignored"); return nil, nil })
	if s.geo(netip.MustParseAddr("1.1.1.1")).Status != "rate_limited" {
		t.Fatal("shared cooldown missing")
	}
	s.backoff = make(map[string]time.Time)
	s.client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 1<<20) + "{}")), Request: r}, nil
	})
	if s.geo(netip.MustParseAddr("8.8.8.8")).Status != "error" {
		t.Fatal("unbounded response accepted")
	}
}

func TestRequestsCoalesceAndRefreshWithoutBlocking(t *testing.T) {
	s := New(Options{Enabled: true, ReverseDNS: true, MaxEntries: 16})
	defer s.Close()
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	s.lookupAddr = func(context.Context, string) ([]string, error) {
		calls.Add(1)
		close(started)
		<-release
		return []string{"example.test."}, nil
	}
	ip := netip.MustParseAddr("10.0.0.1")
	for range 20 {
		if s.Get(ip).Status != "pending" {
			t.Fatal("expected pending")
		}
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not run")
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate lookup")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for s.Get(ip).Status != "ready" {
		if time.Now().After(deadline) {
			t.Fatal("lookup did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	for range 20 {
		_ = s.Get(ip)
	}
	if calls.Load() != 1 {
		t.Fatal("cache miss")
	}
	s.mu.Lock()
	e := s.cache[ip]
	e.record.ExpiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	// Close before enqueue to avoid another DNS invocation in this test.
	s.cancel()
	if r := s.Get(ip); r.Status != "disabled" && !r.Stale {
		t.Fatal("expired context was presented as fresh")
	}
}

func TestCacheAndQueueAreBounded(t *testing.T) {
	s := New(Options{MaxEntries: 16})
	defer s.Close()
	s.opts.Enabled = true // no workers: deterministic full cache
	for i := 1; i <= 20; i++ {
		_ = s.Get(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	if len(s.cache) != 16 || len(s.queue) != 16 {
		t.Fatalf("unbounded cache: %d / %d", len(s.cache), len(s.queue))
	}
	if s.Get(netip.MustParseAddr("10.0.0.30")).Status != "busy" {
		t.Fatal("capacity should report busy")
	}
}

func TestRedirectRestrictions(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	via, _ := http.NewRequest("GET", "https://rdap.org/ip/8.8.8.8", nil)
	for _, raw := range []string{"http://rdap.arin.net/registry/ip/8.8.8.8", "https://127.0.0.1/", "https://example.test/", "https://rdap.arin.net:444/"} {
		r, _ := http.NewRequest("GET", raw, nil)
		if s.client.CheckRedirect(r, []*http.Request{via}) == nil {
			t.Fatal("unsafe redirect allowed")
		}
	}
	r, _ := http.NewRequest("GET", "https://rdap.arin.net/registry/ip/8.8.8.8", nil)
	if s.client.CheckRedirect(r, []*http.Request{via}) != nil {
		t.Fatal("registry redirect rejected")
	}
}
