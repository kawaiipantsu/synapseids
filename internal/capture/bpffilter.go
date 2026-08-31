package capture

// The built-in classic-BPF filter presets, in a platform-neutral form.
//
// SynapseIDS ships no pcap-filter-expression compiler and will not take a
// dependency on one (PROJECT.md §28.16), so BuiltinFilters is a short list of
// hand-assembled programs. Both live sources use them: Linux AF_PACKET attaches
// them with SO_ATTACH_FILTER (afpacket_linux.go) and FreeBSD attaches them to a
// /dev/bpf descriptor with BIOCSETF (bpf_freebsd.go). Keeping the programs here,
// untagged, means one definition and one table test.

// bpfInsn is one classic-BPF instruction. The layout matches both Linux's
// struct sock_filter and FreeBSD's struct bpf_insn, which are byte-identical:
// u16 code, u8 jt, u8 jf, u32 k.
type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// Classic BPF opcodes used by the presets. These are a stable part of both
// ABIs. BPF_LD|BPF_H|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K
// respectively.
const (
	bpfLdHAbs = 0x28
	bpfJeqK   = 0x15
	bpfRetK   = 0x06
	ethTypeK  = 12 // byte offset of the EtherType field in an Ethernet header
)

// bpfRetKeep is the "accept this frame" return value AF_PACKET uses. In classic
// BPF the BPF_RET k is a *byte count*, so it doubles as the snaplen: 262144 is
// both tcpdump's conventional accept-everything value and DefaultSnaplen.
// FreeBSD relies on that second meaning and passes its configured snaplen
// instead — /dev/bpf has no separate snaplen ioctl.
const bpfRetKeep = 0x40000

// EtherTypes the presets match on.
const (
	ethTypeIPv4 = 0x0800
	ethTypeARP  = 0x0806
	ethTypeIPv6 = 0x86DD
)

// builtinFilterAcceptAll is the one-instruction program "accept keep bytes of
// every frame". FreeBSD installs it when no preset is named but a snaplen is
// configured; Linux never needs it, because not attaching a filter already
// accepts everything.
func builtinFilterAcceptAll(keep uint32) []bpfInsn {
	return []bpfInsn{{Code: bpfRetK, K: keep}}
}

// builtinFilterInsns returns the classic-BPF program for a preset name, or nil
// for "" and for an unknown name (callers validate the name with FilterKnown
// first). Each program loads the EtherType at offset 12 and returns keep bytes
// or 0 (drop).
func builtinFilterInsns(name string, keep uint32) []bpfInsn {
	accept := bpfInsn{Code: bpfRetK, K: keep}
	drop := bpfInsn{Code: bpfRetK, K: 0}
	ld := bpfInsn{Code: bpfLdHAbs, K: ethTypeK}

	switch name {
	case "ip":
		return []bpfInsn{ld, {Code: bpfJeqK, Jt: 0, Jf: 1, K: ethTypeIPv4}, accept, drop}
	case "ip6":
		return []bpfInsn{ld, {Code: bpfJeqK, Jt: 0, Jf: 1, K: ethTypeIPv6}, accept, drop}
	case "ip-any":
		return []bpfInsn{
			ld,
			{Code: bpfJeqK, Jt: 1, Jf: 0, K: ethTypeIPv4}, // IPv4 -> accept
			{Code: bpfJeqK, Jt: 0, Jf: 1, K: ethTypeIPv6}, // IPv6 -> accept, else drop
			accept,
			drop,
		}
	case "not-arp":
		return []bpfInsn{
			ld,
			{Code: bpfJeqK, Jt: 1, Jf: 0, K: ethTypeARP}, // ARP -> drop
			accept,
			drop,
		}
	default:
		return nil
	}
}
