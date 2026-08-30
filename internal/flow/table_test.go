package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func mkPkt(ts time.Time, src, dst string, sp, dp uint16, proto packet.Proto, flags uint8, size int) packet.Packet {
	return packet.Packet{
		TS:       ts,
		SrcIP:    netip.MustParseAddr(src),
		DstIP:    netip.MustParseAddr(dst),
		SrcPort:  sp,
		DstPort:  dp,
		Proto:    proto,
		TCPFlags: flags,
		TotalLen: size,
	}
}

func TestKeyNormalization(t *testing.T) {
	a := mkPkt(time.Now(), "10.0.0.1", "10.0.0.2", 1111, 80, packet.ProtoTCP, packet.FlagSYN, 60)
	b := mkPkt(time.Now(), "10.0.0.2", "10.0.0.1", 80, 1111, packet.ProtoTCP, packet.FlagACK, 60)
	ka, _ := KeyOf(a)
	kb, _ := KeyOf(b)
	if ka != kb {
		t.Fatalf("both directions must share a key:\n %+v\n %+v", ka, kb)
	}
}

func TestFINTeardownClosesFlow(t *testing.T) {
	var got []Record
	tbl := NewTable(Options{IdleTimeout: time.Minute, MaxLifetime: time.Hour}, func(r Record) { got = append(got, r) })
	t0 := time.Unix(1000, 0)
	tbl.Observe(mkPkt(t0, "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagSYN, 60))
	tbl.Observe(mkPkt(t0.Add(time.Millisecond), "10.0.0.2", "10.0.0.1", 80, 5000, packet.ProtoTCP, packet.FlagSYN|packet.FlagACK, 60))
	tbl.Observe(mkPkt(t0.Add(2*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagACK, 52))
	tbl.Observe(mkPkt(t0.Add(10*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagFIN|packet.FlagACK, 52))
	tbl.Observe(mkPkt(t0.Add(12*time.Millisecond), "10.0.0.2", "10.0.0.1", 80, 5000, packet.ProtoTCP, packet.FlagFIN|packet.FlagACK, 52))
	if len(got) != 1 {
		t.Fatalf("want 1 closed record, got %d", len(got))
	}
	if got[0].Reason != ReasonFINRST {
		t.Fatalf("reason = %s, want fin_rst", got[0].Reason)
	}
	if got[0].FwdPackets != 3 || got[0].BwdPackets != 2 {
		t.Fatalf("packet counts fwd=%d bwd=%d", got[0].FwdPackets, got[0].BwdPackets)
	}
	// A trailing ACK after teardown must not spawn a phantom flow.
	tbl.Observe(mkPkt(t0.Add(13*time.Millisecond), "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoTCP, packet.FlagACK, 52))
	tbl.Flush()
	if len(got) != 1 {
		t.Fatalf("trailing ACK created %d extra records", len(got)-1)
	}
}

func TestIdleAndMaxLifetime(t *testing.T) {
	var got []Record
	tbl := NewTable(Options{IdleTimeout: 30 * time.Second, MaxLifetime: 5 * time.Minute}, func(r Record) { got = append(got, r) })
	t0 := time.Unix(2000, 0)
	tbl.Observe(mkPkt(t0, "10.0.0.1", "10.0.0.2", 5000, 80, packet.ProtoUDP, 0, 100))
	tbl.Tick(t0.Add(10 * time.Second))
	if len(got) != 0 {
		t.Fatalf("closed too early: %d", len(got))
	}
	tbl.Tick(t0.Add(31 * time.Second))
	if len(got) != 1 || got[0].Reason != ReasonIdle {
		t.Fatalf("want one idle close, got %+v", got)
	}
}

func TestSnapshotsForLongFlow(t *testing.T) {
	var snaps, closes int
	tbl := NewTable(Options{
		IdleTimeout: 10 * time.Minute, MaxLifetime: time.Hour, SnapshotInterval: time.Minute,
	}, func(r Record) {
		if r.Reason == ReasonSnapshot {
			snaps++
		} else {
			closes++
		}
	})
	t0 := time.Unix(3000, 0)
	tbl.Observe(mkPkt(t0, "10.0.0.1", "10.0.0.2", 5000, 443, packet.ProtoTCP, packet.FlagSYN, 60))
	for i := 1; i <= 5; i++ {
		tbl.Observe(mkPkt(t0.Add(time.Duration(i)*30*time.Second), "10.0.0.1", "10.0.0.2", 5000, 443, packet.ProtoTCP, packet.FlagACK, 60))
		tbl.Tick(t0.Add(time.Duration(i) * 30 * time.Second))
	}
	if snaps < 2 {
		t.Fatalf("expected >=2 snapshots for a 2.5 min flow, got %d", snaps)
	}
	tbl.Flush()
	if closes != 1 {
		t.Fatalf("expected exactly one terminal record, got %d", closes)
	}
}

func TestMaxFlowsEviction(t *testing.T) {
	var evicted int
	tbl := NewTable(Options{IdleTimeout: time.Hour, MaxLifetime: time.Hour, MaxFlows: 3}, func(r Record) {
		if r.Reason == ReasonEvicted {
			evicted++
		}
	})
	t0 := time.Unix(4000, 0)
	for i := 0; i < 5; i++ {
		tbl.Observe(mkPkt(t0.Add(time.Duration(i)*time.Second), "10.0.0.1", "10.0.0.2", uint16(6000+i), 80, packet.ProtoUDP, 0, 80))
	}
	if evicted != 2 {
		t.Fatalf("want 2 evictions, got %d", evicted)
	}
	if s := tbl.Stats(); s.Active != 3 || s.Evicted != 2 {
		t.Fatalf("stats: %+v", s)
	}
}
