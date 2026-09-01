package alert

import (
	"fmt"
	"net/netip"
	"strings"
)

// SuppressSpec is one raw suppression rule as it comes from the config `alerts`
// block (internal/config.SuppressRule). It is a plain value with no parsing done
// yet, so cmd/synapsed can translate the config type into it without importing
// internal/alert into internal/config or vice versa — the same split that keeps
// alertPolicy a plain field copy.
type SuppressSpec struct {
	Src     string
	Dst     string
	DstPort int
	Class   string
	Note    string
}

// SuppressRule is a compiled expected-behaviour rule (issue #133). Every field
// is a wildcard when unset: a zero Prefix matches any address, DstPort 0 matches
// any port, an empty Class matches any alertable class.
type SuppressRule struct {
	Src     netip.Prefix
	Dst     netip.Prefix
	DstPort uint16
	Class   string
	Note    string
}

// CompileSuppress turns raw specs into matchers. It applies the same rules
// internal/config.validateSuppressRule enforces at load, so a daemon whose
// config validated never sees an error here; the check is repeated because an
// embedder (a test, future tooling) can build a Policy without going through
// config, and a silently dropped rule is exactly what issue #133 forbids.
func CompileSuppress(specs []SuppressSpec) ([]SuppressRule, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make([]SuppressRule, 0, len(specs))
	for i, s := range specs {
		r, err := compileOne(s)
		if err != nil {
			return nil, fmt.Errorf("suppress[%d]: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func compileOne(s SuppressSpec) (SuppressRule, error) {
	if strings.TrimSpace(s.Note) == "" {
		return SuppressRule{}, fmt.Errorf("needs a note explaining why this traffic is expected")
	}
	if s.Src == "" && s.Dst == "" && s.DstPort == 0 && s.Class == "" {
		return SuppressRule{}, fmt.Errorf("has no matchers, so it would suppress every detection")
	}
	if s.DstPort < 0 || s.DstPort > 65535 {
		return SuppressRule{}, fmt.Errorf("dst_port %d is out of range [0,65535]", s.DstPort)
	}
	r := SuppressRule{DstPort: uint16(s.DstPort), Class: s.Class, Note: strings.TrimSpace(s.Note)}
	if s.Src != "" {
		p, err := parseHostOrPrefix(s.Src)
		if err != nil {
			return SuppressRule{}, fmt.Errorf("src %q: %w", s.Src, err)
		}
		r.Src = p
	}
	if s.Dst != "" {
		p, err := parseHostOrPrefix(s.Dst)
		if err != nil {
			return SuppressRule{}, fmt.Errorf("dst %q: %w", s.Dst, err)
		}
		r.Dst = p
	}
	if s.Class != "" {
		if _, ok := SeverityOf(s.Class); !ok {
			return SuppressRule{}, fmt.Errorf("class %q is not an alertable traffic-classes-v1 class", s.Class)
		}
	}
	return r, nil
}

// parseHostOrPrefix accepts a CIDR or a bare address (treated as a single host).
// It mirrors internal/config.parseHostOrPrefix;
// TestSuppressRuleParsingMatchesConfig pins the two together.
func parseHostOrPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an IP address or CIDR")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// matches reports whether this rule covers the given occurrence. An unparseable
// address fails any rule that constrains that side; a rule that does not
// constrain it is unaffected.
func (r SuppressRule) matches(srcIP, dstIP string, dstPort uint16, class string) bool {
	if r.Src.IsValid() {
		a, err := netip.ParseAddr(srcIP)
		if err != nil || !r.Src.Contains(a) {
			return false
		}
	}
	if r.Dst.IsValid() {
		a, err := netip.ParseAddr(dstIP)
		if err != nil || !r.Dst.Contains(a) {
			return false
		}
	}
	if r.DstPort != 0 && r.DstPort != dstPort {
		return false
	}
	if r.Class != "" && r.Class != class {
		return false
	}
	return true
}
