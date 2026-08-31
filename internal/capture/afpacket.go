package capture

// This file holds the platform-independent surface of the AF_PACKET live
// capture source. The socket itself is Linux-only: see afpacket_linux.go for the
// implementation and afpacket_other.go for the build stub used on developer
// machines. All four release targets are linux/* (PROJECT.md §27, §28.16).

// DefaultSnaplen is the per-frame capture length used when AFPacketConfig.Snaplen
// is 0. 262144 matches the ceiling the pcap file reader enforces and covers
// jumbo frames.
const DefaultSnaplen = 262144

// AFPacketConfig configures a live AF_PACKET capture source.
type AFPacketConfig struct {
	// Interface is the local NIC name to capture from (e.g. "eth0", "lo").
	Interface string
	// Promiscuous puts the interface into promiscuous mode (needs
	// CAP_NET_ADMIN). Without it only traffic addressed to the host is seen.
	Promiscuous bool
	// Snaplen bounds how many bytes of each frame are copied from the kernel.
	// 0 means DefaultSnaplen; values above DefaultSnaplen are rejected.
	Snaplen int
	// Filter names a built-in cBPF preset (see BuiltinFilters). "" captures
	// everything. A full tcpdump-expression compiler is deliberately out of
	// scope for Phase 3 and tracked separately.
	Filter string
}

// BuiltinFilters lists the cBPF filter presets AFPacketConfig.Filter accepts in
// addition to "" (capture everything). These are small hand-assembled classic
// BPF programs; SynapseIDS does not ship a pcap-filter-expression compiler and
// will not pull one in as a dependency (PROJECT.md §28.16).
func BuiltinFilters() []string { return []string{"ip", "ip6", "ip-any", "not-arp"} }

// FilterKnown reports whether name is "" or one of BuiltinFilters.
func FilterKnown(name string) bool {
	if name == "" {
		return true
	}
	for _, f := range BuiltinFilters() {
		if f == name {
			return true
		}
	}
	return false
}
