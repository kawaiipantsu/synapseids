package capture

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// sessionSource adapts an already-handshaken SYNPOIP session to capture.Source.
//
// PCAPOverIP dials the sensor and owns the whole lifecycle; sessionSource is the
// mirror image used by the daemon-side Collector, where the TLS connection was
// accepted and the SYNPOIP client handshake has already run. It never dials and
// never reconnects: when the session ends its packet channel closes and Done is
// closed, which is how the Collector learns to deregister the peer.
type sessionSource struct {
	sess      *pcapoverip.Session
	link      packet.LinkType
	readIdle  time.Duration
	keepalive time.Duration
	latencyMS int64
	logf      func(string, ...any)

	// route is where 0x04 / 0x05 record frames go in flow/feature mode. In raw
	// mode its channel is nil and only packets flow.
	route recordRoute
	rc    recordCounters

	stats struct {
		packets, decoded, decodeErr, bytes, drops uint64
		lastUnixNano                              int64
	}
	advFilter atomic.Pointer[string]

	mu     sync.Mutex
	cancel context.CancelFunc
	closed bool
	done   chan struct{}
}

// newSessionSource wraps sess. link must already be validated as Ethernet or
// RAW. latencyMS is the TLS + SYNPOIP handshake cost the Collector measured, or
// 0.
func newSessionSource(sess *pcapoverip.Session, link packet.LinkType, latencyMS int64, readIdle, keepalive time.Duration, route recordRoute, logf func(string, ...any)) *sessionSource {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if readIdle <= 0 {
		readIdle = pcapoverip.DefaultReadIdleTimeout
	}
	if keepalive <= 0 {
		keepalive = pcapoverip.DefaultKeepaliveInterval
	}
	s := &sessionSource{
		sess: sess, link: link, readIdle: readIdle, keepalive: keepalive,
		latencyMS: latencyMS, route: route, logf: logf, done: make(chan struct{}),
	}
	adv := sess.Filter()
	s.advFilter.Store(&adv)
	return s
}

// Done is closed once the streaming goroutine has exited — the session ended
// (goodbye / EOF / idle) or Close / the pipeline context cancelled it.
func (s *sessionSource) Done() <-chan struct{} { return s.done }

// Packets streams decoded packets off the session. The error channel carries at
// most one terminal error; a per-frame decode failure is counted, not fatal.
func (s *sessionSource) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, 256)
	errc := make(chan error, 1)

	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		close(out)
		errc <- errors.New("pcapoverip: session source is closed")
		close(errc)
		s.signalDone()
		return out, errc
	}
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(ctx, cancel, out, errc)
	return out, errc
}

func (s *sessionSource) run(ctx context.Context, cancel context.CancelFunc, out chan<- packet.Packet, errc chan<- error) {
	defer close(out)
	defer close(errc)
	defer cancel()
	defer s.signalDone()

	var wg sync.WaitGroup
	wg.Add(2)

	// Keepalive writer: an empty 0x02 frame on the sensor's cadence so a quiet
	// link is distinguishable from a dead one on both ends.
	go func() {
		defer wg.Done()
		t := time.NewTicker(s.keepalive)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.sess.WriteKeepalive(); err != nil {
					return
				}
			}
		}
	}()

	// On cancel (Close or pipeline shutdown): goodbye, then close to unblock the
	// reader.
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = s.sess.WriteGoodbye("collector closing")
		_ = s.sess.Close()
	}()

	termErr := s.readLoop(ctx, out)

	cancel()
	wg.Wait()
	_ = s.sess.Close()
	if termErr != nil {
		errc <- termErr
	}
}

func (s *sessionSource) readLoop(ctx context.Context, out chan<- packet.Packet) error {
	for {
		ft, payload, err := s.sess.ReadFrame(s.readIdle)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				return nil
			case isTimeout(err):
				return errors.New("pcapoverip: no frame from sensor within the read-idle timeout")
			case errors.Is(err, net.ErrClosed):
				return nil
			default:
				return err
			}
		}

		switch ft {
		case pcapoverip.FramePacket:
			ts, raw, perr := pcapoverip.ParsePacketFrame(payload)
			if perr != nil {
				atomic.AddUint64(&s.stats.decodeErr, 1)
				continue
			}
			when := time.Unix(0, ts).UTC()
			atomic.AddUint64(&s.stats.packets, 1)
			atomic.AddUint64(&s.stats.bytes, uint64(len(raw)))
			atomic.StoreInt64(&s.stats.lastUnixNano, when.UnixNano())

			pk, derr := packet.Decode(s.link, when, raw)
			if derr != nil {
				atomic.AddUint64(&s.stats.decodeErr, 1)
				continue
			}
			atomic.AddUint64(&s.stats.decoded, 1)
			select {
			case out <- pk:
			case <-ctx.Done():
				return nil
			}

		case pcapoverip.FrameFlowRecord, pcapoverip.FrameFeatureRecord:
			// A flow/feature-mode sensor's records bypass the packet channel
			// entirely: they enter the pipeline further along (issue #45).
			if gone := s.route.deliver(ctx, &s.rc, ft, payload); gone {
				return nil
			}

		case pcapoverip.FrameKeepalive:
			if _, drops, ok := pcapoverip.ParseKeepalive(payload); ok {
				atomic.StoreUint64(&s.stats.drops, drops)
			}

		case pcapoverip.FrameGoodbye:
			s.logf("collector: sensor closed the stream: %q", string(payload))
			return nil
		}
	}
}

func (s *sessionSource) signalDone() {
	s.mu.Lock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.mu.Unlock()
}

// Stats returns a counter snapshot.
func (s *sessionSource) Stats() Stats {
	last := atomic.LoadInt64(&s.stats.lastUnixNano)
	var lt time.Time
	if last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return s.rc.snapshot(Stats{
		Packets:   atomic.LoadUint64(&s.stats.packets),
		Decoded:   atomic.LoadUint64(&s.stats.decoded),
		DecodeErr: atomic.LoadUint64(&s.stats.decodeErr),
		Bytes:     atomic.LoadUint64(&s.stats.bytes),
		LastTS:    lt,
		Drops:     atomic.LoadUint64(&s.stats.drops),
	})
}

// ConnLatencyMS reports the accept-time TLS + SYNPOIP handshake cost.
func (s *sessionSource) ConnLatencyMS() int64 { return s.latencyMS }

// DynamicFilter reports the sensor-advertised capture filter.
func (s *sessionSource) DynamicFilter() (string, bool) {
	if p := s.advFilter.Load(); p != nil {
		return *p, true
	}
	return "", false
}

// Close ends the stream and releases the connection. Safe to call more than once.
func (s *sessionSource) Close() error {
	s.mu.Lock()
	s.closed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = s.sess.Close()
	return nil
}
