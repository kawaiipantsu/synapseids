package events

import (
	"sync"
	"testing"
	"time"
)

func TestPublishFanOut(t *testing.T) {
	b := New()
	s1 := b.Subscribe(4)
	s2 := b.Subscribe(4)
	defer s1.Close()
	defer s2.Close()

	b.Publish(FlowClosed, map[string]int{"id": 1})
	for _, s := range []*Subscription{s1, s2} {
		select {
		case ev := <-s.C:
			if ev.Type != FlowClosed || ev.Seq == 0 {
				t.Fatalf("bad event: %+v", ev)
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive the event")
		}
	}
}

func TestSlowSubscriberDropsNotBlocks(t *testing.T) {
	b := New()
	s := b.Subscribe(2)
	defer s.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish(FeaturesGenerated, i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if s.Dropped() == 0 {
		t.Fatal("expected drops on an unread subscriber")
	}
	_, dropped, _ := b.Stats()
	if dropped == 0 {
		t.Fatal("bus drop counter not incremented")
	}
}

// *Bus satisfies Sink, and a subscriber can relay every event it receives into
// another Sink with no change to this package — the shape a distribution bridge
// (#52) takes.
func TestSubscriptionRelaysIntoAnotherSink(t *testing.T) {
	var _ Sink = (*Bus)(nil)

	upstream := New()
	downstream := New()

	sub := upstream.Subscribe(16)
	relayed := downstream.Subscribe(16)
	defer sub.Close()
	defer relayed.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.C {
			var sink Sink = downstream
			sink.Publish(ev.Type, ev.Data)
		}
	}()

	upstream.Publish(AlertCreated, map[string]string{"class": "scan"})
	select {
	case ev := <-relayed.C:
		if ev.Type != AlertCreated {
			t.Fatalf("relayed event type = %q, want AlertCreated", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not relayed downstream")
	}

	sub.Close() // ends the relay goroutine
	<-done
}

func TestConcurrentPublishers(t *testing.T) {
	b := New()
	s := b.Subscribe(1024)
	defer s.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Publish(ClassificationCreated, j)
			}
		}()
	}
	wg.Wait()
	pub, _, _ := b.Stats()
	if pub != 800 {
		t.Fatalf("published = %d, want 800", pub)
	}
}
