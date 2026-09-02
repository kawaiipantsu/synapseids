//go:build freebsd

package capture

import "fmt"

var _ LiveSource = (*BPFDevice)(nil)

// NewLive opens the platform's live NIC capture source. On FreeBSD that is a
// BPF device bound to the interface — the path an OPNsense WAN sensor takes
// (contrib/opnsense, ADR 0014).
func NewLive(cfg LiveConfig) (LiveSource, error) {
	if cfg.Ring {
		return nil, fmt.Errorf("capture: \"ring\" is a Linux AF_PACKET (TPACKET_V3) option; " +
			"FreeBSD /dev/bpf uses its own store buffer — set buffer_len instead")
	}
	return NewBPFDevice(BPFConfig{
		Interface:   cfg.Interface,
		Device:      cfg.Device,
		Promiscuous: cfg.Promiscuous,
		Snaplen:     cfg.Snaplen,
		Filter:      cfg.Filter,
		Direction:   cfg.Direction,
		BufferLen:   cfg.BufferLen,
		Logf:        cfg.Logf,
	})
}
