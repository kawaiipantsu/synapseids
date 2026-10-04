package dnswire

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestReverseUsesPTRPacket(t *testing.T) {
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close() }()
	go func() {
		b := make([]byte, 512)
		n, a, e := c.ReadFrom(b)
		if e != nil {
			return
		}
		b = b[:n]
		b[2] = 0x81
		b[3] = 0x80
		binary.BigEndian.PutUint16(b[6:], 1)
		target := []byte{3, 'p', 't', 'r', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
		b = append(b, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, byte(len(target)))
		b = append(b, target...)
		_, _ = c.WriteTo(b, a)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// localhost normally has a static mapping; it must not override the wire PTR.
	names, e := Reverse(ctx, "127.0.0.1", c.LocalAddr().String())
	if e != nil || len(names) != 1 || names[0] != "ptr.example.test" {
		t.Fatalf("%v %v", names, e)
	}
}
func TestMalformedDNSBounded(t *testing.T) {
	for _, b := range [][]byte{{}, make([]byte, 4), {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}, {0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0}} {
		if _, e := Parse(b); e == nil {
			t.Fatal("malformed accepted")
		}
	}
}
