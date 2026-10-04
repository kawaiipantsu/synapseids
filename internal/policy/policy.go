// Package policy applies explicit operator-owned CIDR exclusions and asset labels.
// Reads use immutable snapshots; updates are validated and persisted before publication.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// Rule marks an owned asset or explicitly excludes a range from IDS inspection.
type Rule struct {
	CIDR            string   `json:"cidr"`
	Label           string   `json:"label"`
	Mode            string   `json:"mode"`
	SuppressClasses []string `json:"suppress_classes"`
}

// Document is the versioned, replaceable policy configuration.
type Document struct {
	Revision  uint64 `json:"revision"`
	Rules     []Rule `json:"rules"`
	Spamhaus  bool   `json:"spamhaus"`
	CINSArmy  bool   `json:"cins_army"`
	AbuseIPDB bool   `json:"abuseipdb"`
	DNSBL     bool   `json:"dnsbl"`
}

// Match describes an address's effective local policy.
type Match struct {
	Owned           bool     `json:"owned"`
	Excluded        bool     `json:"excluded"`
	Label           string   `json:"label,omitempty"`
	CIDR            string   `json:"cidr,omitempty"`
	SuppressClasses []string `json:"suppress_classes"`
}
type snapshot struct {
	doc      Document
	byPrefix map[netip.Prefix]Rule
	bits     []int
}

// Store owns a durable policy and lock-free lookup snapshots.
type Store struct {
	mu               sync.Mutex
	path             string
	current          atomic.Pointer[snapshot]
	ExcludedPackets  atomic.Uint64
	ExcludedRecords  atomic.Uint64
	SuppressedAlerts atomic.Uint64
}

// ErrConflict means another editor has already changed the document.
var ErrConflict = errors.New("policy changed; reload before saving")

// Open loads a policy. An unreadable or invalid existing policy fails startup.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	d := Document{Rules: []Rule{}}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if err = json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
	}
	snap, err := compile(d)
	if err != nil {
		return nil, err
	}
	s.current.Store(snap)
	return s, nil
}
func compile(d Document) (*snapshot, error) {
	if len(d.Rules) > 1024 {
		return nil, fmt.Errorf("at most 1024 CIDR rules")
	}
	d.Rules = append([]Rule{}, d.Rules...)
	s := &snapshot{doc: d, byPrefix: map[netip.Prefix]Rule{}}
	widths := map[int]bool{}
	for i, r := range d.Rules {
		p, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
		if err != nil {
			a, e := netip.ParseAddr(strings.TrimSpace(r.CIDR))
			if e != nil || a.Zone() != "" {
				return nil, fmt.Errorf("rule %d: invalid IP or CIDR", i+1)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("use IPv4 notation for mapped IPv4 CIDRs")
		}
		p = p.Masked()
		r.CIDR = p.String()
		r.Label = strings.TrimSpace(r.Label)
		if len(r.Label) > 80 || strings.ContainsAny(r.Label, "\r\n\x00") {
			return nil, fmt.Errorf("rule %d: label must be at most 80 characters on one line", i+1)
		}
		if r.Mode != "owned" && r.Mode != "exclude" {
			return nil, fmt.Errorf("rule %d: mode must be owned or exclude", i+1)
		}
		if r.Mode == "exclude" && len(r.SuppressClasses) > 0 {
			return nil, fmt.Errorf("rule %d: exclusion already bypasses every class", i+1)
		}
		r.SuppressClasses = append([]string{}, r.SuppressClasses...)
		if len(r.SuppressClasses) > schema.AttackV2().OutputSize+schema.TrafficClassesV1().OutputSize {
			return nil, fmt.Errorf("too many suppressed classes")
		}
		seen := map[string]bool{}
		for j, c := range r.SuppressClasses {
			c = strings.ToLower(strings.TrimSpace(c))
			valid := false
			for _, cl := range append(append([]schema.Class{}, schema.TrafficClassesV1().Classes...), schema.AttackV2().Classes...) {
				if c == cl.Name && c != "normal" {
					valid = true
				}
			}
			if !valid || seen[c] {
				return nil, fmt.Errorf("invalid or duplicate suppression class")
			}
			seen[c] = true
			r.SuppressClasses[j] = c
		}
		if _, ok := s.byPrefix[p]; ok {
			return nil, fmt.Errorf("duplicate CIDR: %s", p)
		}
		s.doc.Rules[i] = r
		s.byPrefix[p] = r
		widths[p.Bits()] = true
	}
	for b := range widths {
		s.bits = append(s.bits, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.bits)))
	return s, nil
}

// Get returns an independent copy of the configuration.
func (s *Store) Get() Document {
	if s == nil {
		return Document{Rules: []Rule{}}
	}
	d := s.current.Load().doc
	d.Rules = append([]Rule{}, d.Rules...)
	for i := range d.Rules {
		d.Rules[i].SuppressClasses = append([]string{}, d.Rules[i].SuppressClasses...)
	}
	return d
}

// Replace persists a validated update if the revision still matches.
func (s *Store) Replace(d Document) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Revision != s.current.Load().doc.Revision {
		return Document{}, ErrConflict
	}
	d.Revision++
	snap, err := compile(d)
	if err != nil {
		return Document{}, err
	}
	b, err := json.MarshalIndent(snap.doc, "", "  ")
	if err != nil {
		return Document{}, err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return Document{}, err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), "policy-*.tmp")
	if err != nil {
		return Document{}, err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return Document{}, err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return Document{}, err
	}
	if err = f.Close(); err != nil {
		return Document{}, err
	}
	if err = os.Rename(name, s.path); err != nil {
		return Document{}, err
	}
	s.current.Store(snap)
	return s.Get(), nil
}

// Lookup returns the most specific owned rule. Any matching exclusion wins.
func (s *Store) Lookup(ip netip.Addr) Match {
	m := s.lookup(ip)
	m.SuppressClasses = append([]string{}, m.SuppressClasses...)
	return m
}
func (s *Store) lookup(ip netip.Addr) Match {
	if s == nil || !ip.IsValid() {
		return Match{}
	}
	ip = ip.Unmap()
	snap := s.current.Load()
	var match Match
	for _, bits := range snap.bits {
		if bits > ip.BitLen() {
			continue
		}
		if r, ok := snap.byPrefix[netip.PrefixFrom(ip, bits).Masked()]; ok {
			if r.Mode == "exclude" {
				return Match{Excluded: true, Label: r.Label, CIDR: r.CIDR}
			}
			if !match.Owned {
				match = Match{Owned: true, Label: r.Label, CIDR: r.CIDR, SuppressClasses: r.SuppressClasses}
			}
		}
	}
	return match
}

// Excludes reports whether either endpoint belongs to an excluded CIDR.
func (s *Store) Excludes(a, b netip.Addr) bool { return s.lookup(a).Excluded || s.lookup(b).Excluded }

// Suppress applies only to selected classes initiated by an owned asset, never its victims.
func (s *Store) Suppress(initiator, class string) bool {
	if s == nil {
		return false
	}
	ip, err := netip.ParseAddr(initiator)
	return err == nil && slices.Contains(s.lookup(ip).SuppressClasses, strings.ToLower(class))
}

// Directory is the location for private provider cache files.
func (s *Store) Directory() string { return filepath.Dir(s.path) }
