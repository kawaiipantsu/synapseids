package reputation

import (
	"net/netip"
	"testing"
)

func TestFeedParsing(t *testing.T) {
	e, c, err := parseFeed("spamhaus-v4", []byte("{\"cidr\":\"8.8.8.0/24\",\"sblid\":\"SBL-test\"}\n{\"copyright\":\"example copyright\"}\n"))
	if err != nil || len(e) != 1 || c != "example copyright" {
		t.Fatalf("%v %s %v", e, c, err)
	}
	for _, b := range []string{"<html>provider failed</html>", "0.0.0.0/0", "127.0.0.1", "192.168.1.0/24", ""} {
		if _, _, e := parseFeed("cins-army", []byte(b)); e == nil {
			t.Fatalf("accepted invalid feed %q", b)
		}
	}
	if e, _, err := parseFeed("cins-army", []byte("# Example\n8.8.8.8\n2606:4700::/32\n")); err != nil || len(e) != 2 {
		t.Fatal(err)
	}
}
func TestExplicitRBLReturnCodes(t *testing.T) {
	good := []DNSBL{{Name: "Example", Zone: "rbl.example.test", Codes: map[string]string{"127.0.0.2": "Listed"}}}
	if !validZones(good) {
		t.Fatal("valid zone")
	}
	good[0].Codes = map[string]string{"127.255.255.254": "provider error"}
	if validZones(good) {
		t.Fatal("error response must not be a listing")
	}
	if reverse(netip.MustParseAddr("192.0.2.3")) != "3.2.0.192" {
		t.Fatal("reverse IPv4")
	}
	if reverse(netip.MustParseAddr("2001:db8::1")) != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2" {
		t.Fatal("reverse IPv6")
	}
}
