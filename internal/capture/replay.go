package capture

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// Speed controls how fast a Replay emits packets relative to their captured
// timestamps. A value <= 0 means "as fast as possible" (PROJECT.md §6).
type Speed float64

// SpeedMax replays with no pacing at all.
const SpeedMax Speed = 0

// ParseSpeed accepts "0.5", "1", "2", "10", "max", or any positive float.
func ParseSpeed(s string) (Speed, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "1", "1x":
		return 1, nil
	case "max", "0":
		return SpeedMax, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToLower(s), "x"), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("capture: invalid replay speed %q", s)
	}
	return Speed(f), nil
}

func (s Speed) String() string {
	if s <= 0 {
		return "max"
	}
	return strconv.FormatFloat(float64(s), 'g', -1, 64) + "x"
}

// Replay wraps a Source and paces its packets to wall-clock time, scaled by
// Speed. It preserves the inner Source's Stats.
type Replay struct {
	inner Source
	speed Speed
}

// NewReplay returns a Replay over inner at the given speed.
func NewReplay(inner Source, speed Speed) *Replay {
	return &Replay{inner: inner, speed: speed}
}

// Packets streams the inner source's packets with inter-packet delays derived
// from their timestamps.
func (r *Replay) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	inC, inErr := r.inner.Packets(ctx)
	out := make(chan packet.Packet, 256)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		var haveBase bool
		var baseCap, baseWall time.Time

		emit := func(pk packet.Packet) bool {
			if r.speed > 0 {
				if !haveBase {
					haveBase, baseCap, baseWall = true, pk.TS, time.Now()
				} else {
					want := time.Duration(float64(pk.TS.Sub(baseCap)) / float64(r.speed))
					if d := time.Until(baseWall.Add(want)); d > 0 {
						t := time.NewTimer(d)
						select {
						case <-t.C:
						case <-ctx.Done():
							t.Stop()
							return false
						}
					}
				}
			}
			select {
			case out <- pk:
				return true
			case <-ctx.Done():
				return false
			}
		}

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case err, ok := <-inErr:
				if ok && err != nil {
					errc <- err
					return
				}
			case pk, ok := <-inC:
				if !ok {
					return
				}
				if !emit(pk) {
					return
				}
			}
		}
	}()

	return out, errc
}

// Stats proxies the inner source.
func (r *Replay) Stats() Stats { return r.inner.Stats() }

// Close proxies the inner source.
func (r *Replay) Close() error { return r.inner.Close() }
