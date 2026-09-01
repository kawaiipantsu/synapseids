package capture

import (
	"context"
	"fmt"
	"sync"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// LiveStreamer serves a live NIC over SYNPOIP. It is the sensor-side mirror of
// pcapoverip.PcapFileStream: where that replays a capture file to each
// connected daemon, this forwards live frames (PROJECT.md §5.3, §6).
//
// Like the file streamer it opens an **independent capture per connected
// client**, because a BPF descriptor or AF_PACKET socket has exactly one read
// loop. That is also what PROTOCOL.md §7 records as the v1 behaviour ("each
// client gets an independent replay/stream"). In the OPNsense deployment there
// is a single daemon, so it is one device.
type LiveStreamer struct {
	cfg  LiveConfig
	link packet.LinkType

	mu      sync.Mutex
	active  map[LiveSource]struct{}
	retired Stats
}

// NewLiveStreamer validates the configuration by opening the interface once,
// recording the link type it negotiated, and closing it again. Doing this at
// construction means a missing interface or a devfs permission problem fails
// the sensor at start-up with an actionable error, instead of when the first
// daemon happens to connect.
func NewLiveStreamer(cfg LiveConfig) (*LiveStreamer, error) {
	probe, err := NewLive(cfg)
	if err != nil {
		return nil, err
	}
	link := probe.LinkType()
	if err := probe.Close(); err != nil {
		return nil, fmt.Errorf("capture: closing the probe capture on %s: %w", cfg.Interface, err)
	}
	// The probe has already logged the BPF buffer report (issue #128). Drop the
	// logger from the stored config so a reconnect does not repeat it once per
	// daemon connection.
	cfg.Logf = nil
	return &LiveStreamer{cfg: cfg, link: link, active: make(map[LiveSource]struct{})}, nil
}

// LinkType is the libpcap DLT to advertise in a SYNPOIP ServerAccept.
func (s *LiveStreamer) LinkType() uint32 {
	return uint32(s.link) //nolint:gosec // a DLT is a small positive constant
}

// Interface is the NIC being captured, for logs and the advertised filter.
func (s *LiveStreamer) Interface() string { return s.cfg.Interface }

// Stream satisfies pcapoverip.StreamFunc. It opens a fresh capture for this
// client and forwards raw frames until ctx is cancelled or the capture fails.
func (s *LiveStreamer) Stream(ctx context.Context) (<-chan pcapoverip.Record, <-chan error) {
	out := make(chan pcapoverip.Record, 256)
	errc := make(chan error, 1)

	src, err := NewLive(s.cfg)
	if err != nil {
		errc <- err
		close(out)
		close(errc)
		return out, errc
	}
	// The DLT is authoritative in the handshake and was already sent to this
	// client, so a device that comes up with a different one must not stream.
	if got := src.LinkType(); got != s.link {
		_ = src.Close()
		errc <- fmt.Errorf("capture: %s changed link type from DLT %d to DLT %d mid-service",
			s.cfg.Interface, s.link, got)
		close(out)
		close(errc)
		return out, errc
	}

	s.track(src)
	frames, srcErr := src.RawPackets(ctx)

	go func() {
		defer close(out)
		defer close(errc)
		defer s.untrack(src)
		defer func() { _ = src.Close() }()

		for {
			select {
			case f, ok := <-frames:
				if !ok {
					return // capture ended cleanly
				}
				select {
				case out <- pcapoverip.Record{TS: f.TS, Raw: f.Data}:
				case <-ctx.Done():
					errc <- ctx.Err()
					return
				}
			case e, ok := <-srcErr:
				if !ok {
					srcErr = nil // drained; keep forwarding until frames closes
					continue
				}
				if e != nil {
					errc <- e
					return
				}
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()

	return out, errc
}

// Stats aggregates every capture this streamer has opened: the ones still
// running plus the totals of those that have finished. Drops is what a SYNPOIP
// keepalive reports to the daemon, so it must survive a client reconnect.
func (s *LiveStreamer) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := s.retired
	for src := range s.active {
		total = addStats(total, src.Stats())
	}
	return total
}

// Drops is the kernel drop counter across every capture, for keepalive frames.
func (s *LiveStreamer) Drops() uint64 { return s.Stats().Drops }

// Packets is the number of frames captured across every capture.
func (s *LiveStreamer) Packets() uint64 { return s.Stats().Packets }

func (s *LiveStreamer) track(src LiveSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[src] = struct{}{}
}

func (s *LiveStreamer) untrack(src LiveSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[src]; !ok {
		return
	}
	delete(s.active, src)
	s.retired = addStats(s.retired, src.Stats())
}

// addStats sums two counter snapshots, keeping the later LastTS.
func addStats(a, b Stats) Stats {
	out := Stats{
		Packets:   a.Packets + b.Packets,
		Decoded:   a.Decoded + b.Decoded,
		DecodeErr: a.DecodeErr + b.DecodeErr,
		Bytes:     a.Bytes + b.Bytes,
		Drops:     a.Drops + b.Drops,
		LastTS:    a.LastTS,
	}
	if b.LastTS.After(out.LastTS) {
		out.LastTS = b.LastTS
	}
	return out
}
