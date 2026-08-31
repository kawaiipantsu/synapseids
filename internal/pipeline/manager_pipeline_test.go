package pipeline_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/packet"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// synthSource emits a fixed packet slice then closes its channels — a stand-in
// for a live NIC that lets the pipeline+Manager path be tested without one.
type synthSource struct{ pkts []packet.Packet }

func (s *synthSource) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for _, p := range s.pkts {
			select {
			case out <- p:
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			}
		}
	}()
	return out, errc
}

func (s *synthSource) Stats() capture.Stats {
	return capture.Stats{Packets: uint64(len(s.pkts)), Decoded: uint64(len(s.pkts))}
}
func (s *synthSource) Close() error { return nil }

// TestPipelineConsumesManager: packets from a Manager-managed source become a
// flow and a classification, exactly as they do from a PCAP replay.
func TestPipelineConsumesManager(t *testing.T) {
	a := netip.MustParseAddr("10.1.1.2")
	b := netip.MustParseAddr("10.1.1.9")
	base := time.Unix(1_700_000_000, 0).UTC()
	mk := func(i int, fromA bool, flags uint8) packet.Packet {
		p := packet.Packet{
			TS:        base.Add(time.Duration(i) * time.Millisecond),
			Proto:     packet.ProtoTCP,
			IPVersion: 4,
			TCPFlags:  flags,
			TotalLen:  60,
		}
		if fromA {
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = a, b, 44100, 80
		} else {
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = b, a, 80, 44100
		}
		return p
	}
	src := &synthSource{pkts: []packet.Packet{
		mk(0, true, packet.FlagSYN),
		mk(1, false, packet.FlagSYN|packet.FlagACK),
		mk(2, true, packet.FlagACK),
		mk(3, true, packet.FlagPSH|packet.FlagACK),
		mk(4, false, packet.FlagACK),
		mk(5, true, packet.FlagFIN|packet.FlagACK),
		mk(6, false, packet.FlagFIN|packet.FlagACK),
		mk(7, true, packet.FlagACK),
	}}

	m := capture.NewManager()
	if err := m.Add("fake-nic", src, capture.SourceMeta{Kind: "nic"}); err != nil {
		t.Fatal(err)
	}

	bus := events.New()
	sub := bus.Subscribe(256)
	defer sub.Close()
	store := storage.NewMem(100, 100)
	rt := inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan pipeline.Stats, 1)
	go func() {
		// Manager streams live semantics: it never closes on its own, so the
		// pipeline runs until ctx is cancelled or the merged channel closes.
		st, _ := pipeline.Run(ctx, m, rt, bus, store, pipeline.Options{
			Flow:   flow.Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute},
			Sensor: "test",
		})
		done <- st
	}()

	// The two-sided FIN closes the flow, so a classification lands mid-stream.
	deadline := time.Now().Add(5 * time.Second)
	for len(store.RecentClassifications(10)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no classification produced from the manager-fed flow")
		}
		time.Sleep(5 * time.Millisecond)
	}

	_ = m.Close()
	cancel()
	st := <-done
	if st.Packets < 7 {
		t.Fatalf("pipeline consumed %d packets, want >= 7", st.Packets)
	}
	if st.Flows == 0 || st.Classifications == 0 {
		t.Fatalf("pipeline stats show no flow/classification: %+v", st)
	}
	cls := store.RecentClassifications(10)
	if len(cls) == 0 || cls[0].Proto != "TCP" {
		t.Fatalf("unexpected classifications: %+v", cls)
	}
}
