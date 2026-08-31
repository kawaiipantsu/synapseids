package capture

import "errors"

// errUnsupportedPlatform is the sentinel every live-NIC source wraps when the
// build target has no kernel capture interface SynapseIDS speaks. There are two
// implementations — AF_PACKET on Linux (afpacket_linux.go) and /dev/bpf on
// FreeBSD (bpf_freebsd.go) — and each has a stub for the platforms it does not
// cover (afpacket_other.go, bpf_other.go). Keeping the sentinel in one untagged
// file lets both stubs share it without their build tags overlapping, and lets
// callers test with errors.Is regardless of which source they asked for.
var errUnsupportedPlatform = errors.New("capture: live NIC capture is not available on this platform")
