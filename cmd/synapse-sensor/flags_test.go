package main

import (
	"strings"
	"testing"
)

// The flag surface grew three ways to get a capture (file, live NIC) and two
// transport postures (listen, connect). These are the combinations that must be
// refused before anything opens a socket or a BPF device.
func TestValidateSensorOptsRejectsBadCombinations(t *testing.T) {
	base := func(mutate func(*sensorOpts)) *sensorOpts {
		o := &sensorOpts{listen: ":4789", from: "capture.pcap"}
		mutate(o)
		return o
	}

	tests := []struct {
		name string
		opts *sensorOpts
		want int
	}{
		{"file source is fine", base(func(*sensorOpts) {}), 0},
		{"no source at all", base(func(o *sensorOpts) { o.from = "" }), 2},
		{"both sources", base(func(o *sensorOpts) { o.iface = "em0" }), 2},
		{"cert without key", base(func(o *sensorOpts) { o.certFile = "c.pem" }), 2},
		{"key without cert", base(func(o *sensorOpts) { o.keyFile = "k.pem" }), 2},
		{"unknown filter preset", base(func(o *sensorOpts) { o.filter = "tcp port 80" }), 2},
		{
			name: "live capture without --authorized",
			opts: base(func(o *sensorOpts) { o.from, o.iface = "", "em0" }),
			want: 2,
		},
		{
			name: "live capture with --authorized",
			opts: base(func(o *sensorOpts) { o.from, o.iface, o.authorized = "", "em0", true }),
			want: 0,
		},
		{
			name: "live-only flags without --iface",
			opts: base(func(o *sensorOpts) { o.promisc = true }),
			want: 2,
		},
		{
			name: "bpf-device without --iface",
			opts: base(func(o *sensorOpts) { o.device = "/dev/bpf3" }),
			want: 2,
		},
		{
			name: "client-ca in connect mode",
			opts: base(func(o *sensorOpts) { o.connect, o.clientCA = "ids:4789", "ca.pem" }),
			want: 2,
		},
		{
			name: "insecure-tls without --authorized",
			opts: base(func(o *sensorOpts) { o.connect, o.insecureTLS = "ids:4789", true }),
			want: 2,
		},
		{
			name: "insecure-tls with --authorized",
			opts: base(func(o *sensorOpts) { o.connect, o.insecureTLS, o.authorized = "ids:4789", true, true }),
			want: 0,
		},
		{
			name: "connect-only TLS flags in listen mode",
			opts: base(func(o *sensorOpts) { o.caFile = "ca.pem" }),
			want: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateSensorOpts(tc.opts); got != tc.want {
				t.Fatalf("validateSensorOpts = %d, want %d", got, tc.want)
			}
		})
	}
}

// The advertised filter is what the daemon shows in its capture-sources row, so
// it should describe the capture rather than being an opaque preset name.
func TestFilterLabel(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts sensorOpts
		want string
	}{
		{"file capture has no filter", sensorOpts{from: "a.pcap"}, ""},
		{"bare interface", sensorOpts{iface: "em0"}, "em0"},
		{"inbound only", sensorOpts{iface: "em0", direction: "in"}, "em0 in"},
		{"inout is the default and stays implicit", sensorOpts{iface: "em0", direction: "inout"}, "em0"},
		{"preset and promiscuous", sensorOpts{iface: "vtnet0", filter: "ip-any", promisc: true}, "vtnet0 ip-any promisc"},
		{"everything", sensorOpts{iface: "igb0", direction: "in", filter: "ip", promisc: true}, "igb0 in ip promisc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.filterLabel(); got != tc.want {
				t.Fatalf("filterLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A live-capture request on a platform without a kernel capture interface must
// fail with something an operator can act on, not a bare errno. On Linux CI
// this exercises the AF_PACKET path (no CAP_NET_RAW, or no such interface).
func TestOpenSourceLiveFailsLoudly(t *testing.T) {
	_, _, _, err := openSource(&sensorOpts{iface: "synapse-nonexistent-zzz", authorized: true})
	if err == nil {
		t.Fatal("expected an error opening a nonexistent interface")
	}
	if !strings.Contains(err.Error(), "synapse-nonexistent-zzz") {
		t.Fatalf("the error should name the interface: %v", err)
	}
}
