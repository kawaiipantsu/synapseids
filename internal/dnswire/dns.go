// Package dnswire implements bounded DNS metadata decoding and explicit PTR
// queries. It never consults NSS or /etc/hosts when resolving reverse DNS.
package dnswire

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Question is an Internet-class DNS question.
type Question struct {
	Name string
	Type uint16
}

// Answer is a supported A, AAAA, PTR or CNAME resource record.
type Answer struct {
	Name    string
	Type    uint16
	TTL     uint32
	Address netip.Addr
	Target  string
}

// Message contains bounded metadata, excluding payloads and unsupported records.
type Message struct {
	ID        uint16
	Response  bool
	Truncated bool
	RCode     uint8
	Questions []Question
	Answers   []Answer
}

func nameAt(b []byte, at int) (string, int, error) {
	next := -1
	labels := []string{}
	size := 0
	for steps := 0; steps < 128; steps++ {
		if at < 0 || at >= len(b) {
			break
		}
		n := int(b[at])
		at++
		if n == 0 {
			if next < 0 {
				next = at
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		if n&192 == 192 {
			if at >= len(b) {
				break
			}
			if next < 0 {
				next = at + 1
			}
			at = (n&63)<<8 | int(b[at])
			continue
		}
		if n > 63 || at+n > len(b) {
			break
		}
		size += n + 1
		if size > 254 {
			break
		}
		label := b[at : at+n]
		for _, c := range label {
			if c < 33 || c > 126 || c == '.' || c == '\\' {
				return "", 0, fmt.Errorf("invalid DNS label")
			}
		}
		labels = append(labels, string(label))
		at += n
	}
	return "", 0, fmt.Errorf("invalid or cyclic DNS name")
}

// Parse decodes at most 16 questions and 128 total records; malformed input fails.
func Parse(b []byte) (Message, error) {
	var m Message
	if len(b) < 12 || len(b) > 65535 {
		return m, fmt.Errorf("invalid DNS size")
	}
	m.ID = binary.BigEndian.Uint16(b)
	flags := binary.BigEndian.Uint16(b[2:])
	m.Response = flags&0x8000 != 0
	m.Truncated = flags&0x200 != 0
	m.RCode = uint8(flags & 15)
	qn := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))
	if qn > 16 || an+ns+ar > 128 {
		return m, fmt.Errorf("DNS record limit")
	}
	at := 12
	for range qn {
		name, n, e := nameAt(b, at)
		if e != nil || n+4 > len(b) {
			return m, fmt.Errorf("invalid DNS question")
		}
		if binary.BigEndian.Uint16(b[n+2:]) == 1 {
			m.Questions = append(m.Questions, Question{name, binary.BigEndian.Uint16(b[n:])})
		}
		at = n + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, n, e := nameAt(b, at)
		if e != nil || n+10 > len(b) {
			return m, fmt.Errorf("invalid DNS record")
		}
		typ := binary.BigEndian.Uint16(b[n:])
		class := binary.BigEndian.Uint16(b[n+2:])
		ttl := binary.BigEndian.Uint32(b[n+4:])
		size := int(binary.BigEndian.Uint16(b[n+8:]))
		start := n + 10
		at = start + size
		if at > len(b) {
			return m, fmt.Errorf("truncated DNS record")
		}
		if i >= an || class != 1 {
			continue
		}
		a := Answer{Name: name, Type: typ, TTL: ttl}
		switch typ {
		case 1:
			if size != 4 {
				return m, fmt.Errorf("invalid A record")
			}
			a.Address = netip.AddrFrom4([4]byte(b[start:at]))
		case 28:
			if size != 16 {
				return m, fmt.Errorf("invalid AAAA record")
			}
			a.Address = netip.AddrFrom16([16]byte(b[start:at]))
		case 5, 12:
			a.Target, n, e = nameAt(b, start)
			if e != nil || n > at {
				return m, fmt.Errorf("invalid name record")
			}
		default:
			continue
		}
		m.Answers = append(m.Answers, a)
	}
	return m, nil
}

// ReverseName encodes the standard in-addr.arpa / ip6.arpa owner name.
func ReverseName(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	parts := make([]string, 0, 34)
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", b[i]&15), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}
func servers(configured string) []string {
	if configured != "" {
		return []string{configured}
	}
	b, e := os.ReadFile("/etc/resolv.conf")
	if e != nil {
		return nil
	}
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, e := netip.ParseAddr(f[1]); e == nil {
				out = append(out, net.JoinHostPort(ip.String(), "53"))
				if len(out) == 3 {
					break
				}
			}
		}
	}
	return out
}

// Reverse queries the configured resolver directly. Static host mappings cannot
// masquerade as PTR records. Replies must match transaction and question.
func Reverse(ctx context.Context, address, resolver string) ([]string, error) {
	ip, e := netip.ParseAddr(address)
	if e != nil {
		return nil, e
	}
	owner := ReverseName(ip)
	query := make([]byte, 12)
	if _, e = rand.Read(query[:2]); e != nil {
		return nil, e
	}
	binary.BigEndian.PutUint16(query[2:], 0x100)
	binary.BigEndian.PutUint16(query[4:], 1)
	for _, label := range strings.Split(owner, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 12, 0, 1)
	for _, server := range servers(resolver) {
		b, err := exchange(ctx, server, "udp", query)
		if err != nil {
			continue
		}
		m, err := Parse(b)
		if len(b) >= 12 && binary.BigEndian.Uint16(b) == binary.BigEndian.Uint16(query) && m.Response && m.Truncated {
			b, err = exchange(ctx, server, "tcp", query)
			if err == nil {
				m, err = Parse(b)
			}
		}
		if err != nil || m.ID != binary.BigEndian.Uint16(query) || !m.Response || len(m.Questions) != 1 || m.Questions[0].Name != owner || m.Questions[0].Type != 12 {
			continue
		}
		if m.RCode == 3 {
			return nil, &net.DNSError{Err: "no PTR record", IsNotFound: true}
		}
		if m.RCode != 0 {
			continue
		}
		owners := map[string]bool{owner: true}
		for range 8 {
			changed := false
			for _, a := range m.Answers {
				if a.Type == 5 && owners[a.Name] && !owners[a.Target] {
					owners[a.Target] = true
					changed = true
				}
			}
			if !changed {
				break
			}
		}
		out := []string{}
		for _, a := range m.Answers {
			if a.Type == 12 && owners[a.Name] && a.Target != "" {
				out = append(out, a.Target)
			}
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no PTR record", IsNotFound: true}
		}
		return out, nil
	}
	return nil, fmt.Errorf("DNS PTR query unavailable")
}
func exchange(ctx context.Context, server, network string, query []byte) ([]byte, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, network, server)
	if e != nil {
		return nil, e
	}
	defer func() { _ = c.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = c.SetDeadline(deadline); e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if network == "tcp" {
		wire := make([]byte, 2, len(query)+2)
		binary.BigEndian.PutUint16(wire, uint16(len(query)))
		wire = append(wire, query...)
		if _, e = c.Write(wire); e != nil {
			return nil, e
		}
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			return nil, e
		}
		b := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		_, e = io.ReadFull(c, b)
		return b, e
	}
	if _, e = c.Write(query); e != nil {
		return nil, e
	}
	b := make([]byte, 65535)
	n, e := c.Read(b)
	return b[:n], e
}
