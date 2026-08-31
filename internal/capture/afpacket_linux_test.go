//go:build linux

package capture

import (
	"os"
	"strings"
	"testing"
)

func TestNewAFPacketRejectsUnknownInterface(t *testing.T) {
	_, err := NewAFPacket(AFPacketConfig{Interface: "nonexistent-iface-zzz"})
	if err == nil {
		t.Fatal("expected an error for a missing interface")
	}
	if !strings.Contains(err.Error(), "nonexistent-iface-zzz") {
		t.Fatalf("error should name the interface: %v", err)
	}
}

func TestNewAFPacketRejectsEmptyInterface(t *testing.T) {
	if _, err := NewAFPacket(AFPacketConfig{}); err == nil {
		t.Fatal("expected an error for an empty interface name")
	}
}

func TestNewAFPacketRejectsBadFilterAndSnaplen(t *testing.T) {
	if _, err := NewAFPacket(AFPacketConfig{Interface: "lo", Filter: "tcp port 80"}); err == nil {
		t.Fatal("expected an error for an unknown filter preset (no expression compiler)")
	}
	if _, err := NewAFPacket(AFPacketConfig{Interface: "lo", Snaplen: DefaultSnaplen + 1}); err == nil {
		t.Fatal("expected an error for an oversized snaplen")
	}
}

func TestBuiltinFilterPrograms(t *testing.T) {
	for _, name := range BuiltinFilters() {
		if prog := builtinFilter(name); len(prog) == 0 {
			t.Errorf("builtinFilter(%q) returned no instructions", name)
		}
	}
	if prog := builtinFilter(""); prog != nil {
		t.Errorf(`builtinFilter("") = %v, want nil`, prog)
	}
	if prog := builtinFilter("bogus"); prog != nil {
		t.Errorf("builtinFilter(bogus) = %v, want nil", prog)
	}
	if !FilterKnown("") || !FilterKnown("not-arp") || FilterKnown("tcp port 80") {
		t.Fatal("FilterKnown disagrees with BuiltinFilters")
	}
}

func TestHtonsIsInvolution(t *testing.T) {
	for _, v := range []uint16{0, 1, 0x0003, 0x0800, 0x1234, 0xFFFF} {
		if got := htons(htons(v)); got != v {
			t.Fatalf("htons(htons(%#x)) = %#x", v, got)
		}
	}
}

// TestAFPacketOpenLive actually opens an AF_PACKET socket on loopback. It needs
// CAP_NET_RAW, which CI does not have, so it is opt-in.
func TestAFPacketOpenLive(t *testing.T) {
	if testing.Short() || os.Getenv("SYNAPSE_NIC_TEST") == "" {
		t.Skip("set SYNAPSE_NIC_TEST=1 and drop -short to open a real AF_PACKET socket (needs CAP_NET_RAW)")
	}
	ap, err := NewAFPacket(AFPacketConfig{Interface: "lo", Snaplen: 65536})
	if err != nil {
		t.Fatalf("open lo: %v", err)
	}
	defer func() { _ = ap.Close() }()
	if s := ap.Stats(); s.Drops != 0 {
		t.Logf("unexpected non-zero drops right after open: %d", s.Drops)
	}
}
