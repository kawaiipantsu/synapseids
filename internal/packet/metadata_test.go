package packet

import (
	"testing"
)

func TestMetadataDNSAndHTTP(t *testing.T) {
	b := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	m := metadata(Packet{Proto: ProtoUDP, DstPort: 53}, b)
	if m == nil || !m.DNSQuery || m.DNSNames[0] != "abc.test" {
		t.Fatal(m)
	}
	m = metadata(Packet{Proto: ProtoTCP, DstPort: 80}, []byte("GET /payload.exe?secret=discard HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer discarded\r\n\r\n"))
	if m == nil || !m.Download || m.HTTPHost != "example.test" || m.DownloadExtension != ".exe" {
		t.Fatal(m)
	}
	if LabelEntropy("abcdefghijklmnop.test") < 3.9 || LabelEntropy("aaaa.test") != 0 {
		t.Fatal("entropy")
	}
}
func TestMalformedMetadataDoesNotPanic(t *testing.T) {
	for size := 0; size < 256; size++ {
		b := make([]byte, 256)
		b[0] = 22
		b[1] = 3
		b[4] = byte(size)
		b[5] = 1
		for i := 6; i < len(b); i++ {
			b[i] = 255
		}
		_ = metadata(Packet{Proto: ProtoTCP, DstPort: 443}, b)
	}
	for n := 0; n < 100; n++ {
		_ = metadata(Packet{Proto: ProtoUDP, DstPort: 53}, make([]byte, n))
	}
}

func TestTruncatedCaptureIsNotMalformedDNS(t *testing.T) {
	p := Packet{Proto: ProtoUDP, SrcPort: 53, Truncated: true}
	if got := metadata(p, []byte{1, 2, 3}); got != nil {
		t.Fatal("capture truncation was treated as protocol evidence")
	}
}
