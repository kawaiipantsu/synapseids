//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// putU32 / putU16 write a native-endian field, matching what the kernel does
// into the mmap ring.
func putU32(b []byte, off int, v uint32) { binary.NativeEndian.PutUint32(b[off:], v) }
func putU16(b []byte, off int, v uint16) { binary.NativeEndian.PutUint16(b[off:], v) }

// buildBlock hand-assembles one TPACKET_V3 block: a block descriptor followed by
// `frames`, each {snaplen, macOffset, payloadByte, nextOffset}. It returns the
// backing buffer; the block starts at offset 0.
type testFrame struct {
	snaplen    uint32
	macOff     uint16
	payload    byte
	nextOffset uint32 // 0 = last
}

func buildBlock(blockSz int, firstPkt uint32, frames []testFrame) []byte {
	buf := make([]byte, blockSz)
	putU32(buf, bdBlockStatus, tpStatusUser)
	putU32(buf, bdNumPkts, uint32(len(frames)))
	putU32(buf, bdOffsetToFirstPkt, firstPkt)

	cur := int(firstPkt)
	for i, f := range frames {
		putU32(buf, cur+t3NextOffset, f.nextOffset)
		putU32(buf, cur+t3Sec, uint32(1_700_000_000+i))
		putU32(buf, cur+t3Nsec, uint32(1000*(i+1)))
		putU32(buf, cur+t3Snaplen, f.snaplen)
		putU16(buf, cur+t3Mac, f.macOff)
		start := cur + int(f.macOff)
		for j := 0; j < int(f.snaplen) && start+j < blockSz; j++ {
			buf[start+j] = f.payload
		}
		if f.nextOffset == 0 {
			break
		}
		cur += int(f.nextOffset)
	}
	return buf
}

func TestRingWalkBlockEmitsFramesOldestFirst(t *testing.T) {
	a := &AFPacket{}
	const blockSz = 4096
	buf := buildBlock(blockSz, 64, []testFrame{
		{snaplen: 20, macOff: 32, payload: 0x11, nextOffset: 128},
		{snaplen: 24, macOff: 32, payload: 0x22, nextOffset: 0},
	})

	var got [][]byte
	var stamps []time.Time
	cont := a.ringWalkBlock(buf, 0, blockSz, func(ts time.Time, frame []byte) bool {
		cp := make([]byte, len(frame))
		copy(cp, frame)
		got = append(got, cp)
		stamps = append(stamps, ts)
		return true
	})
	if !cont {
		t.Fatal("walk reported a stop it was not asked for")
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d frames, want 2", len(got))
	}
	if len(got[0]) != 20 || got[0][0] != 0x11 {
		t.Errorf("frame 0 = %d bytes of %#x, want 20 of 0x11", len(got[0]), got[0][0])
	}
	if len(got[1]) != 24 || got[1][0] != 0x22 {
		t.Errorf("frame 1 = %d bytes of %#x, want 24 of 0x22", len(got[1]), got[1][0])
	}
	if !stamps[1].After(stamps[0]) {
		t.Errorf("timestamps not oldest-first: %v then %v", stamps[0], stamps[1])
	}
	if p := atomic.LoadUint64(&a.stats.packets); p != 2 {
		t.Errorf("stats.packets = %d, want 2", p)
	}
	if b := atomic.LoadUint64(&a.stats.bytes); b != 44 {
		t.Errorf("stats.bytes = %d, want 44", b)
	}
	if e := atomic.LoadUint64(&a.stats.decodeErr); e != 0 {
		t.Errorf("stats.decodeErr = %d, want 0", e)
	}
}

func TestRingWalkBlockStopsAndCountsAMalformedFrame(t *testing.T) {
	a := &AFPacket{}
	const blockSz = 4096
	// Two good frames, then a third whose snaplen runs off the end of the block.
	buf := buildBlock(blockSz, 64, []testFrame{
		{snaplen: 16, macOff: 32, payload: 0xAA, nextOffset: 128},
		{snaplen: 16, macOff: 32, payload: 0xBB, nextOffset: 128},
		{snaplen: 99999, macOff: 32, payload: 0xCC, nextOffset: 0},
	})

	var n int
	a.ringWalkBlock(buf, 0, blockSz, func(time.Time, []byte) bool { n++; return true })
	if n != 2 {
		t.Fatalf("emitted %d frames, want 2 before the malformed one", n)
	}
	if e := atomic.LoadUint64(&a.stats.decodeErr); e != 1 {
		t.Errorf("stats.decodeErr = %d, want 1", e)
	}
}

func TestRingWalkBlockHonoursEmitStop(t *testing.T) {
	a := &AFPacket{}
	const blockSz = 4096
	buf := buildBlock(blockSz, 64, []testFrame{
		{snaplen: 10, macOff: 32, payload: 1, nextOffset: 128},
		{snaplen: 10, macOff: 32, payload: 2, nextOffset: 0},
	})

	var n int
	cont := a.ringWalkBlock(buf, 0, blockSz, func(time.Time, []byte) bool { n++; return false })
	if cont {
		t.Fatal("walk should report the emit stop")
	}
	if n != 1 {
		t.Fatalf("emitted %d frames after emit said stop, want 1", n)
	}
}

func TestRingWalkBlockRejectsAnOutOfRangeBase(t *testing.T) {
	a := &AFPacket{}
	buf := make([]byte, 64)
	// blockSz larger than the buffer: the guard must fire, not panic.
	cont := a.ringWalkBlock(buf, 0, 4096, func(time.Time, []byte) bool {
		t.Fatal("emit called for a block that does not fit the mapping")
		return true
	})
	if !cont {
		t.Fatal("walk should continue (skip the bad block), not report a stop")
	}
	if e := atomic.LoadUint64(&a.stats.decodeErr); e != 1 {
		t.Errorf("stats.decodeErr = %d, want 1", e)
	}
}

// TestAFPacketRingOpenLive opens a real TPACKET_V3 ring on loopback. It needs
// CAP_NET_RAW, which CI does not have, so it is opt-in like TestAFPacketOpenLive.
func TestAFPacketRingOpenLive(t *testing.T) {
	if testing.Short() || os.Getenv("SYNAPSE_NIC_TEST") == "" {
		t.Skip("set SYNAPSE_NIC_TEST=1 and drop -short to open a real AF_PACKET RX ring (needs CAP_NET_RAW)")
	}
	ap, err := NewAFPacket(AFPacketConfig{Interface: "lo", Snaplen: 65536, Ring: true})
	if err != nil {
		t.Fatalf("open lo with ring: %v", err)
	}
	defer func() { _ = ap.Close() }()
	if ap.ring == nil {
		t.Fatal("Ring: true did not install a ring")
	}
}

// TestAFPacketRingCapturesLoopbackTraffic drives real UDP through the RX ring
// and checks the decoded frames come out of Packets(). Opt-in (CAP_NET_RAW).
func TestAFPacketRingCapturesLoopbackTraffic(t *testing.T) {
	if testing.Short() || os.Getenv("SYNAPSE_NIC_TEST") == "" {
		t.Skip("set SYNAPSE_NIC_TEST=1 and drop -short to capture through a real RX ring (needs CAP_NET_RAW)")
	}
	ap, err := NewAFPacket(AFPacketConfig{Interface: "lo", Snaplen: 65536, Ring: true})
	if err != nil {
		t.Fatalf("open lo with ring: %v", err)
	}
	defer func() { _ = ap.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pkts, errc := ap.Packets(ctx)

	conn, err := net.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = conn.Write([]byte("synapse-ring-probe"))
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	defer close(stop)

	select {
	case pk, ok := <-pkts:
		if !ok {
			t.Fatal("packet channel closed before any frame arrived")
		}
		t.Logf("first frame through the ring: proto=%s len=%d", pk.Proto, pk.TotalLen)
	case err := <-errc:
		t.Fatalf("capture error before any frame: %v", err)
	case <-ctx.Done():
		t.Fatal("no frame captured through the RX ring within 5s")
	}

	if s := ap.Stats(); s.Packets == 0 {
		t.Fatal("Stats.Packets stayed 0 after capturing through the ring")
	}
}
