package enrichment

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func TestObservedNamesDoNotReplacePTRAndExpire(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	ip := netip.MustParseAddr("192.0.2.1")
	at := time.Now()
	s.now = func() time.Time { return at }
	s.localNames = map[netip.Addr][]AssociatedName{ip: {{Name: "local.example", Source: "local hosts file"}}}
	s.keepBindings(bindingBatch{at: at, bindings: []packet.NameBinding{{Name: "hosted.example", Address: ip, TTL: 30, Source: "observed DNS answer"}}})
	got := s.Get(ip)
	if len(got.AssociatedNames) != 2 || len(got.DNS.Names) != 0 {
		t.Fatal("associated name became PTR")
	}
	s.now = func() time.Time { return at.Add(time.Minute) }
	if len(s.Get(ip).AssociatedNames) != 1 {
		t.Fatal("observed TTL did not expire")
	}
}
