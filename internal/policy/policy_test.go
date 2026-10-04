package policy

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestPolicyScopeAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	d := s.Get()
	d.Rules = []Rule{{CIDR: "192.0.2.10", Mode: "owned", Label: "Example server", SuppressClasses: []string{"scan", "suspicious"}}, {CIDR: "2001:db8:42::/48", Mode: "exclude"}}
	saved, e := s.Replace(d)
	if e != nil {
		t.Fatal(e)
	}
	if saved.Revision != 1 || saved.Rules[0].CIDR != "192.0.2.10/32" {
		t.Fatal(saved)
	}
	if !s.Suppress("192.0.2.10", "scan") || s.Suppress("192.0.2.11", "scan") || s.Suppress("192.0.2.10", "botnet_c2") {
		t.Fatal("suppression scope")
	}
	if !s.Excludes(netip.MustParseAddr("2001:db8:42::1"), netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("IPv6 exclusion")
	}
	if _, e = s.Replace(d); e != ErrConflict {
		t.Fatalf("stale writer: %v", e)
	}
	saved.Rules[0].SuppressClasses[0] = "botnet_c2"
	if !s.Suppress("192.0.2.10", "scan") {
		t.Fatal("copy escaped")
	}
	again, e := Open(path)
	if e != nil || !again.Suppress("192.0.2.10", "scan") {
		t.Fatalf("reload: %v", e)
	}
}
func TestExclusionWinsAndInvalidUpdateIsAtomic(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "p.json"))
	d := s.Get()
	d.Rules = []Rule{{CIDR: "192.0.2.0/24", Mode: "exclude"}, {CIDR: "192.0.2.5/32", Mode: "owned"}}
	if _, e := s.Replace(d); e != nil {
		t.Fatal(e)
	}
	if !s.Lookup(netip.MustParseAddr("::ffff:192.0.2.5")).Excluded {
		t.Fatal("broader exclusion must win")
	}
	for _, r := range []Rule{{CIDR: "wrong", Mode: "owned"}, {CIDR: "192.0.2.0/24", Mode: "owned", SuppressClasses: []string{"TYPO"}}, {CIDR: "192.0.2.0/24", Mode: "exclude", SuppressClasses: []string{"scan"}}} {
		d = s.Get()
		d.Rules = []Rule{r}
		if _, e := s.Replace(d); e == nil {
			t.Fatal("invalid accepted")
		}
		if s.Get().Revision != 1 {
			t.Fatal("invalid update published")
		}
	}
}
