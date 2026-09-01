//go:build linux

package capture

import "fmt"

var _ LiveSource = (*AFPacket)(nil)

// NewLive opens the platform's live NIC capture source. On Linux that is an
// AF_PACKET raw socket.
func NewLive(cfg LiveConfig) (LiveSource, error) {
	if cfg.Device != "" {
		return nil, fmt.Errorf("capture: a capture device path (%q) is a FreeBSD /dev/bpf concept; "+
			"Linux AF_PACKET binds the interface directly", cfg.Device)
	}
	if _, isDefault, ok := bpfDirectionCode(cfg.Direction); !ok || !isDefault {
		return nil, fmt.Errorf("capture: direction %q is not supported on Linux — AF_PACKET has no "+
			"BIOCSDIRECTION equivalent, so both directions are always captured", cfg.Direction)
	}
	if cfg.BufferLen != 0 {
		return nil, fmt.Errorf("capture: buffer length %d is a FreeBSD BPF store-buffer (BIOCSBLEN) setting; "+
			"Linux AF_PACKET sizes its ring differently and does not take this knob", cfg.BufferLen)
	}
	return NewAFPacket(AFPacketConfig{
		Interface:   cfg.Interface,
		Promiscuous: cfg.Promiscuous,
		Snaplen:     cfg.Snaplen,
		Filter:      cfg.Filter,
	})
}
