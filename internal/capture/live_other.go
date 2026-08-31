//go:build !linux && !freebsd

package capture

import "fmt"

// NewLive always fails on a platform with neither AF_PACKET nor /dev/bpf. The
// release targets are linux/{amd64,386,arm64,arm} plus freebsd/{amd64,arm64}
// (PROJECT.md §27, §28.16); this keeps the tree building on any other
// developer machine.
func NewLive(LiveConfig) (LiveSource, error) {
	return nil, fmt.Errorf("capture: live NIC capture needs Linux (AF_PACKET) or FreeBSD (/dev/bpf): %w",
		errUnsupportedPlatform)
}
