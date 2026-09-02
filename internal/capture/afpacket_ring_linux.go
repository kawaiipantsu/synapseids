//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
)

// This file adds an opt-in TPACKET_V3 mmap RX ring to the AF_PACKET source
// (issue #163). The default path in afpacket_linux.go does one Recvfrom per
// frame; at a high packet rate that syscall dominates the capture cost. With a
// TPACKET_V3 ring the kernel fills a block of shared memory directly and hands
// whole blocks to userspace, so a burst of frames is read with no per-frame
// syscall — only an epoll wait when the ring is empty.
//
// It is deliberately NOT the default. PROJECT.md §22/§26 say capture is not
// optimised before a measurement shows the per-packet syscall is the
// bottleneck (issue #127). `Ring: true` on an AFPacketConfig (from a "nic"
// capture source with `ring: true`) turns it on for an operator who has taken
// that measurement; making it the default stays gated on #127.
//
// Everything here is stdlib syscall only. The tpacket structs are packed and
// parsed by hand; every field this code touches is 16- or 32-bit at a fixed
// offset, so the layout is identical on amd64/386/arm64/arm (cf. ADR 0010 for
// the same reasoning about PACKET_STATISTICS). syscall on Linux exports
// PACKET_RX_RING; PACKET_VERSION, TPACKET_V3 and the status flags are not in the
// package and are defined below.
const (
	// packetVersion is PACKET_VERSION from <linux/if_packet.h>. stdlib syscall
	// exports PACKET_RX_RING and PACKET_STATISTICS but not this one.
	packetVersion = 10
	// tpacketV3 selects TPACKET_V3 for the PACKET_VERSION sockopt.
	tpacketV3 = 2

	// Block-status values in tpacket_hdr_v1.block_status.
	tpStatusKernel = 0 // the kernel owns the block
	tpStatusUser   = 1 // TP_STATUS_USER — userspace owns the block

	// Ring geometry. afpRingBlockSize is a multiple of every Linux page size
	// (4 KiB / 16 KiB / 64 KiB all divide 1 MiB); afpRingBlocks blocks give a
	// 32 MiB ring — enough to ride out a scheduler gap near line rate without
	// being a surprising allocation for a mode the operator explicitly enabled.
	// afpRingRetireMs bounds how long a partially-filled block is withheld, so
	// latency on a quiet link stays comparable to the Recvfrom path's timeout.
	afpRingBlockSize = 1 << 20
	afpRingBlocks    = 32
	afpRingFrameSize = 2048 // afpRingBlockSize % afpRingFrameSize == 0
	afpRingRetireMs  = 60

	// Field offsets from <linux/if_packet.h>.
	//
	// struct tpacket_block_desc { u32 version; u32 offset_to_priv;
	//   union { struct tpacket_hdr_v1 { u32 block_status; u32 num_pkts;
	//   u32 offset_to_first_pkt; u32 blk_len; ... } } }
	bdBlockStatus      = 8
	bdNumPkts          = 12
	bdOffsetToFirstPkt = 16

	// struct tpacket3_hdr { u32 tp_next_offset; u32 tp_sec; u32 tp_nsec;
	//   u32 tp_snaplen; u32 tp_len; u32 tp_status; u16 tp_mac; u16 tp_net; ... }
	t3NextOffset = 0
	t3Sec        = 4
	t3Nsec       = 8
	t3Snaplen    = 12
	t3Mac        = 24
	t3HdrRead    = 28 // bytes read out of each tpacket3_hdr (covers tp_mac at 24..25)

	// tpacketReq3Size is sizeof(struct tpacket_req3): seven unsigned ints, and
	// unsigned int is 32-bit on every Linux arch including the 64-bit ones.
	tpacketReq3Size = 28
)

// afpRing owns the mmap'd RX ring and the epoll fd used to wait on it.
type afpRing struct {
	mem     []byte
	epfd    int
	blockSz int
	blocks  int
	cursor  int // index of the next block to inspect
}

// newAFPRing switches fd to TPACKET_V3, installs the RX ring and maps it. On any
// failure it leaves fd untouched (the caller closes it) and releases whatever it
// had already acquired.
func newAFPRing(fd int) (*afpRing, error) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetVersion, tpacketV3); err != nil {
		return nil, fmt.Errorf("PACKET_VERSION TPACKET_V3: %w", err)
	}

	blockSz := afpRingBlockSize
	if ps := syscall.Getpagesize(); ps > 0 && blockSz%ps != 0 {
		blockSz = ((blockSz / ps) + 1) * ps
	}
	frameNr := (blockSz / afpRingFrameSize) * afpRingBlocks

	var req [tpacketReq3Size]byte
	binary.NativeEndian.PutUint32(req[0:], uint32(blockSz))          // tp_block_size
	binary.NativeEndian.PutUint32(req[4:], uint32(afpRingBlocks))    // tp_block_nr
	binary.NativeEndian.PutUint32(req[8:], uint32(afpRingFrameSize)) // tp_frame_size
	binary.NativeEndian.PutUint32(req[12:], uint32(frameNr))         // tp_frame_nr
	binary.NativeEndian.PutUint32(req[16:], uint32(afpRingRetireMs)) // tp_retire_blk_tov
	// tp_sizeof_priv and tp_feature_req_word stay 0.
	if err := syscall.SetsockoptString(fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, string(req[:])); err != nil {
		return nil, fmt.Errorf("PACKET_RX_RING: %w", err)
	}

	mem, err := syscall.Mmap(fd, 0, blockSz*afpRingBlocks,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap RX ring (%d bytes): %w", blockSz*afpRingBlocks, err)
	}

	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		_ = syscall.Munmap(mem)
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	ev := syscall.EpollEvent{Events: uint32(syscall.EPOLLIN), Fd: int32(fd)}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &ev); err != nil {
		_ = syscall.Close(epfd)
		_ = syscall.Munmap(mem)
		return nil, fmt.Errorf("epoll_ctl ADD: %w", err)
	}

	return &afpRing{mem: mem, epfd: epfd, blockSz: blockSz, blocks: afpRingBlocks}, nil
}

// close releases the ring. It is safe on a nil receiver and safe to call twice.
func (r *afpRing) close() {
	if r == nil {
		return
	}
	if r.epfd >= 0 {
		_ = syscall.Close(r.epfd)
		r.epfd = -1
	}
	if r.mem != nil {
		_ = syscall.Munmap(r.mem)
		r.mem = nil
	}
}

// ringReadLoop is the TPACKET_V3 equivalent of readLoop: it drains every block
// the kernel has handed up, then epoll-waits (with a timeout, so Close and ctx
// cancellation stay responsive) for the next one. It returns when emit says
// stop, ctx is cancelled, or the socket is closed.
func (a *AFPacket) ringReadLoop(ctx context.Context, errc chan<- error, emit func(time.Time, []byte) bool) {
	r := a.ring
	evs := make([]syscall.EpollEvent, 1)
	waitMS := int(afpReadTimeout / time.Millisecond)

	for {
		if err := ctx.Err(); err != nil {
			errc <- err
			return
		}
		if a.closed.Load() {
			return
		}

		progressed := false
		for a.ringBlockReady(r) {
			progressed = true
			if !a.ringConsumeBlock(r, emit) {
				return // emit asked to stop
			}
			if a.closed.Load() {
				return
			}
		}
		if progressed {
			continue // more blocks may have filled while we drained
		}

		n, err := syscall.EpollWait(r.epfd, evs, waitMS)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EINTR):
				continue
			case a.closed.Load(), errors.Is(err, syscall.EBADF):
				return
			default:
				errc <- fmt.Errorf("afpacket: epoll_wait %s: %w", a.ifName, err)
				return
			}
		}
		_ = n // EPOLLIN only means "look at the ring"; block ownership is the real signal
	}
}

// ringBlockReady reports whether the block at the cursor is owned by userspace.
func (a *AFPacket) ringBlockReady(r *afpRing) bool {
	base := r.cursor * r.blockSz
	if base+bdBlockStatus+4 > len(r.mem) {
		return false
	}
	return binary.NativeEndian.Uint32(r.mem[base+bdBlockStatus:])&tpStatusUser != 0
}

// ringConsumeBlock walks the cursor block, hands it back to the kernel and
// advances the cursor. It returns false when emit asked to stop.
func (a *AFPacket) ringConsumeBlock(r *afpRing, emit func(time.Time, []byte) bool) bool {
	base := r.cursor * r.blockSz
	cont := a.ringWalkBlock(r.mem, base, r.blockSz, emit)
	binary.NativeEndian.PutUint32(r.mem[base+bdBlockStatus:], tpStatusKernel)
	r.cursor = (r.cursor + 1) % r.blocks
	return cont
}

// ringWalkBlock hands each frame in one TPACKET_V3 block to emit, oldest first.
// It returns false as soon as emit does. A header whose offsets fall outside the
// block is counted in decodeErr and ends the walk — a corrupt block descriptor
// must never index out of range (PROJECT.md §28.11).
func (a *AFPacket) ringWalkBlock(mem []byte, base, blockSz int, emit func(time.Time, []byte) bool) bool {
	end := base + blockSz
	if base < 0 || end > len(mem) || base+bdOffsetToFirstPkt+4 > len(mem) {
		atomic.AddUint64(&a.stats.decodeErr, 1)
		return true
	}
	numPkts := binary.NativeEndian.Uint32(mem[base+bdNumPkts:])
	cur := base + int(binary.NativeEndian.Uint32(mem[base+bdOffsetToFirstPkt:]))

	for i := uint32(0); i < numPkts; i++ {
		if cur < base || cur+t3HdrRead > end {
			atomic.AddUint64(&a.stats.decodeErr, 1)
			return true
		}
		next := binary.NativeEndian.Uint32(mem[cur+t3NextOffset:])
		sec := binary.NativeEndian.Uint32(mem[cur+t3Sec:])
		nsec := binary.NativeEndian.Uint32(mem[cur+t3Nsec:])
		snap := binary.NativeEndian.Uint32(mem[cur+t3Snaplen:])
		mac := binary.NativeEndian.Uint16(mem[cur+t3Mac:])

		start := cur + int(mac)
		fend := start + int(snap)
		if mac == 0 || snap == 0 || start < cur || fend > end {
			atomic.AddUint64(&a.stats.decodeErr, 1)
			return true
		}

		atomic.AddUint64(&a.stats.packets, 1)
		atomic.AddUint64(&a.stats.bytes, uint64(snap))
		ts := time.Unix(int64(sec), int64(nsec)).UTC()
		atomic.StoreInt64(&a.stats.lastUnixNano, ts.UnixNano())

		if !emit(ts, mem[start:fend:fend]) {
			return false
		}

		if next == 0 {
			break
		}
		cur += int(next)
	}
	return true
}
