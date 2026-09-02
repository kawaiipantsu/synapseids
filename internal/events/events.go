// Package events is the in-process publish/subscribe bus that decouples the
// packet path from the API, storage and live UI. Publishing never blocks: a
// subscriber that cannot keep up drops events, which are counted, rather than
// stalling ingestion (PROJECT.md §17, §22). Kafka/NATS are deliberately out of
// scope until distribution requires them (#52, EPIC Phase 8).
//
// Extension point for distribution. When a message bus is eventually needed, it
// attaches as an ordinary subscriber, not a rewrite of this package: a relay
// goroutine calls Bus.Subscribe, serialises each Event (already the frozen
// event-envelope-v1 shape) and forwards it to the external transport, with the
// existing bounded-queue backpressure applying to the relay exactly as to any
// other slow consumer. Producers that should target something other than the
// concrete *Bus take a Sink (below); a fan-out Sink over {*Bus, relay} is then
// the only new code. The in-process Bus stays the source of truth (§17).
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Type is an event type name (see schemas/events/event-envelope-v1.json).
type Type string

// Event types.
const (
	CaptureSourceConnected    Type = "CaptureSourceConnected"
	CaptureSourceDisconnected Type = "CaptureSourceDisconnected"
	FlowStarted               Type = "FlowStarted"
	FlowUpdated               Type = "FlowUpdated"
	FlowClosed                Type = "FlowClosed"
	FeaturesGenerated         Type = "FeaturesGenerated"
	ClassificationCreated     Type = "ClassificationCreated"
	ModelDisagreementDetected Type = "ModelDisagreementDetected"
	AlertCreated              Type = "AlertCreated"
	ReviewUpdated             Type = "ReviewUpdated"
	ReplayStarted             Type = "ReplayStarted"
	ReplayProgress            Type = "ReplayProgress"
	ReplayFinished            Type = "ReplayFinished"
	ModelRegistered           Type = "ModelRegistered"
	ModelActivated            Type = "ModelActivated"
	ModelDeactivated          Type = "ModelDeactivated"
	SensorConnected           Type = "SensorConnected"
	SensorDisconnected        Type = "SensorDisconnected"
)

// Event is the envelope every bus message uses (event-envelope-v1).
type Event struct {
	Type Type   `json:"type"`
	TS   string `json:"ts"`
	Seq  uint64 `json:"seq"`
	Data any    `json:"data"`
}

// Sink is the write side of the bus: everything a producer needs to emit an
// event. *Bus satisfies it. Code that may later publish to more than the
// in-process bus (a distribution relay, #52) depends on Sink rather than *Bus
// so that seam costs no change here. A fan-out implementation lives with the
// relay, not in this package, until there is one.
type Sink interface {
	Publish(t Type, data any)
}

// Bus is a fan-out event bus with bounded per-subscriber queues.
type Bus struct {
	mu     sync.RWMutex
	subs   map[int]*Subscription
	nextID int
	seq    uint64

	published atomic.Uint64
	dropped   atomic.Uint64
}

// Subscription is a live feed. Call Close when done.
type Subscription struct {
	C       <-chan Event
	ch      chan Event
	bus     *Bus
	id      int
	dropped atomic.Uint64
}

// New returns an empty Bus.
func New() *Bus { return &Bus{subs: make(map[int]*Subscription)} }

// Subscribe registers a subscriber with a queue of the given depth (min 1).
func (b *Bus) Subscribe(depth int) *Subscription {
	if depth < 1 {
		depth = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	ch := make(chan Event, depth)
	s := &Subscription{C: ch, ch: ch, bus: b, id: id}
	b.subs[id] = s
	return s
}

// Close removes the subscription and releases its channel.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if _, ok := s.bus.subs[s.id]; ok {
		delete(s.bus.subs, s.id)
		close(s.ch)
	}
}

// Dropped reports how many events this subscriber missed because its queue was full.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Publish delivers an event to every subscriber without blocking. A full
// subscriber queue increments that subscriber's and the bus's drop counter.
func (b *Bus) Publish(t Type, data any) {
	ev := Event{Type: t, TS: time.Now().UTC().Format(time.RFC3339Nano), Data: data}
	b.mu.RLock()
	ev.Seq = atomic.AddUint64(&b.seq, 1)
	for _, s := range b.subs {
		select {
		case s.ch <- ev:
		default:
			s.dropped.Add(1)
			b.dropped.Add(1)
		}
	}
	b.mu.RUnlock()
	b.published.Add(1)
}

// Stats returns bus-wide counters.
func (b *Bus) Stats() (published, dropped uint64, subscribers int) {
	b.mu.RLock()
	n := len(b.subs)
	b.mu.RUnlock()
	return b.published.Load(), b.dropped.Load(), n
}
