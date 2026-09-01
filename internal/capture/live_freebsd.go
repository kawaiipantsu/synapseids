//go:build freebsd

package capture

var _ LiveSource = (*BPFDevice)(nil)

// NewLive opens the platform's live NIC capture source. On FreeBSD that is a
// BPF device bound to the interface — the path an OPNsense WAN sensor takes
// (contrib/opnsense, ADR 0014).
func NewLive(cfg LiveConfig) (LiveSource, error) {
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
