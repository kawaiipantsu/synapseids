package packet

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/dnswire"
)

// NameBinding is an observed name-to-address association, never a PTR lookup.
type NameBinding struct {
	Name    string     `json:"name"`
	Address netip.Addr `json:"address"`
	TTL     uint32     `json:"ttl"`
	Source  string     `json:"source"`
}

// Metadata is bounded application evidence decoded from a single captured packet.
// It stores no raw payload, query strings, cookies, authentication or message text.
type Metadata struct {
	DNSQuery          bool          `json:"dns_query"`
	DNSResponse       bool          `json:"dns_response"`
	DNSNXDomain       bool          `json:"dns_nxdomain"`
	DNSMalformed      bool          `json:"dns_malformed"`
	DNSNames          []string      `json:"dns_names,omitempty"`
	Bindings          []NameBinding `json:"bindings,omitempty"`
	HTTPRequest       bool          `json:"http_request"`
	Download          bool          `json:"download"`
	DownloadExtension string        `json:"download_extension,omitempty"`
	HTTPHost          string        `json:"http_host,omitempty"`
	TLSClientHello    bool          `json:"tls_client_hello"`
	TLSServerName     string        `json:"tls_server_name,omitempty"`
	IRC               bool          `json:"irc"`
}

func metadata(p Packet, b []byte) *Metadata {
	if p.Truncated {
		return nil
	}
	if len(b) == 0 {
		return nil
	}
	if len(b) > 16384 {
		b = b[:16384]
	}
	var m Metadata
	if p.SrcPort == 53 || p.DstPort == 53 {
		dns := b
		if p.Proto == ProtoTCP {
			if len(b) < 2 {
				return nil
			}
			n := int(binary.BigEndian.Uint16(b))
			if n > len(b)-2 {
				return nil
			}
			dns = b[2 : 2+n]
		}
		d, e := dnswire.Parse(dns)
		if e != nil {
			m.DNSMalformed = true
		} else {
			m.DNSQuery = !d.Response
			m.DNSResponse = d.Response
			m.DNSNXDomain = d.Response && d.RCode == 3
			for _, q := range d.Questions {
				if len(m.DNSNames) < 8 {
					m.DNSNames = append(m.DNSNames, q.Name)
				}
			}
			if d.Response && d.RCode == 0 {
				for _, a := range d.Answers {
					if a.Address.IsValid() && len(m.Bindings) < 16 {
						m.Bindings = append(m.Bindings, NameBinding{Name: a.Name, Address: a.Address, TTL: a.TTL, Source: "observed DNS answer"})
					}
				}
			}
		}
		return &m
	}
	if p.Proto != ProtoTCP {
		return nil
	}
	if len(b) > 5 && b[0] == 22 && b[1] == 3 {
		m.TLSClientHello, m.TLSServerName = tlsName(b)
		if m.TLSClientHello {
			return &m
		}
	}
	// HTTP parsing deliberately requires a complete header block in this packet.
	// Split TLS/HTTP records are left unknown; no speculative reassembly.
	if end := bytes.Index(b, []byte("\r\n\r\n")); end >= 0 {
		lines := strings.Split(string(b[:end]), "\r\n")
		first := strings.Fields(lines[0])
		if len(first) >= 2 {
			switch first[0] {
			case "GET", "POST", "HEAD", "PUT", "OPTIONS", "CONNECT", "DELETE", "PATCH":
				m.HTTPRequest = true
			}
			isResponse := strings.HasPrefix(first[0], "HTTP/1.")
			if m.HTTPRequest || isResponse {
				if m.HTTPRequest {
					if u, e := url.ParseRequestURI(first[1]); e == nil {
						ext := strings.ToLower(path.Ext(u.Path))
						switch ext {
						case ".exe", ".dll", ".msi", ".scr", ".ps1", ".hta", ".lnk", ".jar", ".apk", ".sh":
							m.Download = true
							m.DownloadExtension = ext
						}
					}
				}
				for _, line := range lines[1:] {
					name, value, ok := strings.Cut(line, ":")
					if !ok {
						continue
					}
					switch strings.ToLower(strings.TrimSpace(name)) {
					case "host":
						m.HTTPHost = domain(strings.TrimSpace(value))
					case "content-type":
						v := strings.ToLower(value)
						if strings.Contains(v, "application/x-msdownload") || strings.Contains(v, "application/x-sh") || strings.Contains(v, "application/hta") {
							m.Download = true
						}
					}
				}
				return &m
			}
		}
	}
	ircLine := b[:min(len(b), 4096)]
	if len(ircLine) > 0 && ircLine[0] == ':' {
		if at := bytes.IndexByte(ircLine, ' '); at > 0 {
			ircLine = ircLine[at+1:]
		}
	}
	for _, prefix := range [][]byte{[]byte("NICK "), []byte("USER "), []byte("PRIVMSG "), []byte("JOIN "), []byte("NOTICE "), []byte("PING "), []byte("PONG ")} {
		if bytes.HasPrefix(ircLine, prefix) {
			m.IRC = true
			return &m
		}
	}
	return nil
}
func domain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if h, _, ok := strings.Cut(s, ":"); ok {
		s = h
	}
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	for _, c := range s {
		valid := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if !valid {
			return ""
		}
	}
	return s
}
func tlsName(b []byte) (bool, string) {
	if len(b) < 9 || b[5] != 1 {
		return false, ""
	}
	size := int(binary.BigEndian.Uint16(b[3:]))
	if size < 4 || size+5 > len(b) {
		return false, ""
	}
	b = b[9 : 5+size]
	if len(b) < 35 {
		return false, ""
	}
	at := 34
	n := int(b[at])
	at++
	if at+n+2 > len(b) {
		return false, ""
	}
	at += n
	n = int(binary.BigEndian.Uint16(b[at:]))
	at += 2
	if at+n+1 > len(b) {
		return false, ""
	}
	at += n
	n = int(b[at])
	at++
	if at+n+2 > len(b) {
		return false, ""
	}
	at += n
	size = int(binary.BigEndian.Uint16(b[at:]))
	at += 2
	end := at + size
	if end > len(b) {
		return false, ""
	}
	for at+4 <= end {
		typ := binary.BigEndian.Uint16(b[at:])
		n = int(binary.BigEndian.Uint16(b[at+2:]))
		at += 4
		if at+n > end {
			return false, ""
		}
		if typ == 0 && n >= 5 {
			x := b[at : at+n]
			total := int(binary.BigEndian.Uint16(x))
			if total+2 > len(x) {
				return false, ""
			}
			pos := 2
			for pos+3 <= len(x) {
				kind := x[pos]
				ln := int(binary.BigEndian.Uint16(x[pos+1:]))
				pos += 3
				if pos+ln > len(x) {
					return false, ""
				}
				if kind == 0 {
					return true, domain(string(x[pos : pos+ln]))
				}
				pos += ln
			}
		}
		at += n
	}
	return true, ""
}

// LabelEntropy measures the leftmost DNS label in bits per character.
func LabelEntropy(name string) float64 {
	label, _, _ := strings.Cut(name, ".")
	if len(label) == 0 {
		return 0
	}
	counts := [256]int{}
	for _, b := range []byte(label) {
		counts[b]++
	}
	h := 0.0
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(label))
			h -= p * math.Log2(p)
		}
	}
	return h
}
