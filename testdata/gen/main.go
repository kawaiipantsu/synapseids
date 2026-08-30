// Command gen writes the small classic-pcap fixtures under testdata/pcap used by
// the golden feature tests and the integration test. Committing both the
// generator and its output keeps fixture provenance in the tree (PROJECT.md §25).
//
// Run from the repo root:  go run ./testdata/gen
package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := "testdata/pcap"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}
	write(filepath.Join(out, "http.pcap"), httpFlow())
	write(filepath.Join(out, "portscan.pcap"), portScan())
	write(filepath.Join(out, "udp.pcap"), udpExchange())
	log.Printf("wrote fixtures to %s/", out)
}

// ---- pcap container -------------------------------------------------------

type pkt struct {
	ts   time.Time
	data []byte
}

func write(path string, pkts []pkt) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var gh [24]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4) // classic, microsecond
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535) // snaplen
	binary.LittleEndian.PutUint32(gh[20:24], 1)     // DLT_EN10MB
	f.Write(gh[:])

	for _, p := range pkts {
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(p.ts.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(p.ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(p.data)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(p.data)))
		f.Write(rh[:])
		f.Write(p.data)
	}
}

// ---- frame construction -------------------------------------------------

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
)

const (
	finFlag = 1 << 0
	synFlag = 1 << 1
	rstFlag = 1 << 2
	pshFlag = 1 << 3
	ackFlag = 1 << 4
)

func eth(dst, src net.HardwareAddr, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], 0x0800) // IPv4
	copy(b[14:], payload)
	return b
}

func ipv4(src, dst net.IP, proto byte, payload []byte) []byte {
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = 64 // TTL
	b[9] = proto
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	// header checksum left zero — the decoder does not verify it
	copy(b[20:], payload)
	return b
}

func tcp(sport, dport uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = 5 << 4 // data offset 20 bytes
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], window)
	copy(b[20:], payload)
	return b
}

func udp(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	copy(b[8:], payload)
	return b
}

// ---- scenarios --------------------------------------------------------

// httpFlow: a clean client GET to a server, with a response and an orderly
// teardown. Should classify as normal.
func httpFlow() []pkt {
	cli := net.IPv4(192, 168, 1, 50)
	srv := net.IPv4(93, 184, 216, 34)
	t0 := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

	c2s := func(ts time.Time, flags byte, seq, ack uint32, pl []byte) pkt {
		return pkt{ts, eth(macB, macA, ipv4(cli, srv, 6, tcp(49712, 80, seq, ack, flags, 64240, pl)))}
	}
	s2c := func(ts time.Time, flags byte, seq, ack uint32, pl []byte) pkt {
		return pkt{ts, eth(macA, macB, ipv4(srv, cli, 6, tcp(80, 49712, seq, ack, flags, 65535, pl)))}
	}
	get := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
	resp := make([]byte, 1200)
	copy(resp, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1140\r\n\r\n"))

	return []pkt{
		c2s(at(0), synFlag, 1000, 0, nil),
		s2c(at(20), synFlag|ackFlag, 5000, 1001, nil),
		c2s(at(21), ackFlag, 1001, 5001, nil),
		c2s(at(25), pshFlag|ackFlag, 1001, 5001, get),
		s2c(at(60), pshFlag|ackFlag, 5001, 1001+uint32(len(get)), resp),
		c2s(at(62), ackFlag, 1001+uint32(len(get)), 5001+uint32(len(resp)), nil),
		c2s(at(90), finFlag|ackFlag, 1001+uint32(len(get)), 5001+uint32(len(resp)), nil),
		s2c(at(110), finFlag|ackFlag, 5001+uint32(len(resp)), 1002+uint32(len(get)), nil),
		c2s(at(111), ackFlag, 1002+uint32(len(get)), 5002+uint32(len(resp)), nil),
	}
}

// portScan: one source fires bare SYNs at 24 ports on one target; a few get a
// RST back, most get nothing. Each (src,dst,sport,dport) is its own flow, so the
// integration test asserts the *majority* verdict is scan.
func portScan() []pkt {
	atk := net.IPv4(10, 0, 0, 66)
	tgt := net.IPv4(10, 0, 0, 1)
	t0 := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	ports := []uint16{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200}

	var out []pkt
	for i, dp := range ports {
		ts := t0.Add(time.Duration(i) * 3 * time.Millisecond)
		sport := uint16(40000 + i)
		out = append(out, pkt{ts, eth(macA, macB, ipv4(atk, tgt, 6, tcp(sport, dp, uint32(7000+i), 0, synFlag, 1024, nil)))})
		if i%5 == 0 { // a closed port answers with RST
			out = append(out, pkt{ts.Add(time.Millisecond), eth(macB, macA, ipv4(tgt, atk, 6, tcp(dp, sport, 0, uint32(7001+i), rstFlag|ackFlag, 0, nil)))})
		}
	}
	return out
}

// udpExchange: a small DNS-style query/response pair. Classifies as normal.
func udpExchange() []pkt {
	cli := net.IPv4(192, 168, 1, 50)
	dns := net.IPv4(1, 1, 1, 1)
	t0 := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	q := append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, []byte("\x07example\x03com\x00\x00\x01\x00\x01")...)
	a := append([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, make([]byte, 40)...)
	return []pkt{
		{t0, eth(macA, macB, ipv4(cli, dns, 17, udp(52000, 53, q)))},
		{t0.Add(18 * time.Millisecond), eth(macB, macA, ipv4(dns, cli, 17, udp(53, 52000, a)))},
	}
}
