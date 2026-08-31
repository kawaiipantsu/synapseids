package capture

import "time"

// This file holds the platform-independent surface of the FreeBSD /dev/bpf live
// capture source. The device itself is FreeBSD-only: see bpf_freebsd.go for the
// implementation and bpf_other.go for the build stub used everywhere else.
//
// FreeBSD matters because of the OPNsense sensor plugin (contrib/opnsense):
// an OPNsense firewall is a FreeBSD host, and its WAN interface is exactly the
// vantage point PROJECT.md §5.3 wants a sensor at. Linux keeps using AF_PACKET
// (afpacket_linux.go); the four Linux release targets are unchanged
// (PROJECT.md §27, §28.16).

// BPF tuning defaults.
const (
	// DefaultBPFBufferLen is the BIOCSBLEN request. FreeBSD clamps it to
	// net.bpf.maxbufsize (512 KiB out of the box) and reports the granted size
	// back through the same ioctl, which is what the source actually allocates.
	// A large buffer is how a BPF reader survives bursts: the kernel drops
	// whatever will not fit and only tells you afterwards, via BIOCGSTATS.
	DefaultBPFBufferLen = 512 * 1024

	// MinBPFBufferLen mirrors FreeBSD's BPF_MINBUFSIZE. Anything smaller is
	// clamped up by the kernel, so refusing it early gives a better error.
	MinBPFBufferLen = 32

	// MaxBPFBufferLen bounds what an operator may ask for, so a typo cannot
	// make the sensor allocate an absurd read buffer. FreeBSD would clamp it
	// anyway; this keeps the refusal local and legible.
	MaxBPFBufferLen = 16 * 1024 * 1024

	// DefaultBPFReadTimeout is the BIOCSRTIMEOUT value. It bounds how long a
	// single blocking read(2) parks, which is what makes Close and context
	// cancellation responsive on a silent interface — the same role
	// SO_RCVTIMEO plays for AF_PACKET.
	DefaultBPFReadTimeout = 250 * time.Millisecond
)

// BPFConfig configures a live capture source backed by a FreeBSD BPF device.
type BPFConfig struct {
	// Interface is the local NIC to capture from (e.g. "em0", "vtnet0", or an
	// OPNsense WAN device name). Required.
	Interface string

	// Device is an explicit BPF device path such as "/dev/bpf4". Empty means
	// probe: the cloning "/dev/bpf" first, then /dev/bpf0../dev/bpf255.
	// Naming one is useful when a devfs rule grants the sensor user access to
	// exactly one device.
	Device string

	// Promiscuous puts the interface into promiscuous mode (BIOCPROMISC).
	// Without it only traffic addressed to the host is seen — which is usually
	// wrong for a WAN sensor sitting on a routed edge.
	Promiscuous bool

	// Immediate sets BIOCIMMEDIATE: the kernel wakes the reader for every
	// packet instead of filling the store buffer first.
	//
	// Leave it false. ReadTimeout already bounds delivery latency, so immediate
	// mode adds nothing except one read(2) per frame — which defeats the store
	// buffer and turns any reader pause into kernel drops. It was on
	// unconditionally until a live WAN sensor measured 10% loss against
	// Suricata's 0.8% on the same interface at the same moment.
	//
	// Useful only for debugging a low-rate link where per-packet delivery makes
	// a trace easier to follow.
	Immediate bool

	// Snaplen bounds how many bytes of each frame the kernel copies. 0 means
	// DefaultSnaplen; values above DefaultSnaplen are rejected. Unlike
	// AF_PACKET, BPF has no snaplen ioctl: the limit is the accept length of
	// the attached filter's BPF_RET instruction, so setting a snaplen always
	// installs a filter (see bpffilter.go).
	Snaplen int

	// Filter names a built-in cBPF preset (see BuiltinFilters). "" captures
	// every frame. There is deliberately no filter-expression compiler
	// (PROJECT.md §28.16).
	Filter string

	// Direction selects which traffic the kernel hands over (BIOCSDIRECTION):
	// "in" for received frames only, "out" for transmitted only, "" or "inout"
	// for both. "in" is the natural choice for an inbound-WAN sensor.
	Direction string

	// BufferLen is the BIOCSBLEN request in bytes. 0 means
	// DefaultBPFBufferLen. The kernel may grant less.
	BufferLen int

	// ReadTimeout is the BIOCSRTIMEOUT value. 0 means DefaultBPFReadTimeout.
	ReadTimeout time.Duration
}

// BPFDirections lists the values BPFConfig.Direction accepts in addition to ""
// (which means "inout").
func BPFDirections() []string { return []string{"in", "out", "inout"} }

// bpfDirectionCode maps a Direction string to the BIOCSDIRECTION value, and
// reports whether the string was valid. A nil-direction ("" or "inout") still
// returns ok so callers can skip the ioctl entirely.
func bpfDirectionCode(s string) (code uint32, isDefault bool, ok bool) {
	switch s {
	case "", "inout":
		return bpfDirectionInOut, true, true
	case "in":
		return bpfDirectionIn, false, true
	case "out":
		return bpfDirectionOut, false, true
	default:
		return 0, false, false
	}
}
