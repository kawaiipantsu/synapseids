package enrichment

import (
	"net/netip"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

type bindingBatch struct {
	bindings []packet.NameBinding
	at       time.Time
}

// ObserveBindings queues bounded packet-derived associations without resolving
// them or affecting PTR records. A full queue drops enrichment, never traffic.
func (s *Service) ObserveBindings(bindings []packet.NameBinding, at time.Time) {
	if s == nil || !s.opts.Enabled || len(bindings) == 0 {
		return
	}
	batch := bindingBatch{bindings: append([]packet.NameBinding{}, bindings[:min(16, len(bindings))]...), at: at}
	select {
	case s.namesQueue <- batch:
	default:
	}
}
func (s *Service) nameWorker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case batch := <-s.namesQueue:
			s.keepBindings(batch)
		}
	}
}
func (s *Service) keepBindings(batch bindingBatch) {
	now := s.now()
	if batch.at.After(now.Add(time.Minute)) || batch.at.Before(now.Add(-24*time.Hour)) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range batch.bindings {
		ip := b.Address.Unmap()
		if !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() || b.TTL == 0 || len(b.Name) > 253 || len(b.Name) == 0 {
			continue
		}
		switch b.Source {
		case "observed DNS answer", "observed TLS SNI", "observed HTTP Host":
		default:
			continue
		}
		expires := batch.at.Add(time.Duration(min(b.TTL, 86400)) * time.Second)
		if !expires.After(now) {
			continue
		}
		if len(s.observed) >= s.opts.MaxEntries && s.observed[ip] == nil {
			var oldest netip.Addr
			var at time.Time
			for k, rows := range s.observed {
				if len(rows) > 0 && (at.IsZero() || rows[0].ExpiresAt.Before(at)) {
					oldest = k
					at = rows[0].ExpiresAt
				}
			}
			delete(s.observed, oldest)
		}
		rows := s.observed[ip]
		out := make([]AssociatedName, 0, 16)
		for _, r := range rows {
			if r.ExpiresAt.After(now) && (r.Name != b.Name || r.Source != b.Source) {
				out = append(out, r)
			}
		}
		if len(out) >= 16 {
			out = out[len(out)-15:]
		}
		out = append(out, AssociatedName{Name: b.Name, Source: b.Source, ObservedAt: batch.at, ExpiresAt: expires})
		s.observed[ip] = out
	}
}
func (s *Service) names(ip netip.Addr) []AssociatedName {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]AssociatedName{}, s.localNames[ip]...)
	now := s.now()
	for _, n := range s.observed[ip] {
		if n.ExpiresAt.After(now) {
			out = append(out, n)
		}
	}
	return out
}
