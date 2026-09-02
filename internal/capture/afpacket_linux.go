//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// afpReadTimeout bounds a single blocking Recvfrom so context cancellation and
// Close take effect within this window even on a completely idle interface.
const afpReadTimeout = 250 * time.Millisecond

// AFPacket is a live Source backed by a Linux AF_PACKET raw socket. Each frame
// is decoded through the same packet.Decode path a PCAP replay uses, so the
// pipeline and UI behave identically for live and replayed traffic
// (PROJECT.md §6).
//
// It needs CAP_NET_RAW (and CAP_NET_ADMIN when Promiscuous is set); it never
// requires running as root (PROJECT.md §21). The contrib/systemd unit already
// grants both via AmbientCapabilities.
type AFPacket struct {
	ifName  string
	ifIndex int
	snaplen int
	filter  string

	fd    int
	buf   []byte
	stopc chan struct{}

	// ring is non-nil when the source was opened with Ring: true; the read
	// loop then drains a TPACKET_V3 mmap ring instead of calling Recvfrom
	// (issue #163, afpacket_ring_linux.go).
	ring *afpRing

	closed  atomic.Bool
	started atomic.Bool

	statMu sync.Mutex // serialises the PACKET_STATISTICS read (drain-on-read)
	stats  struct {
		packets, decoded, decodeErr, bytes uint64
		drops                              uint64
		lastUnixNano                       int64
	}
}

// NewAFPacket opens a raw socket bound to cfg.Interface and returns a Source. It
// does not start reading until Packets is called. An EPERM/EACCES failure names
// the missing capability rather than demanding root.
func NewAFPacket(cfg AFPacketConfig) (*AFPacket, error) {
	if cfg.Interface == "" {
		return nil, errors.New("afpacket: interface name is required")
	}
	if !FilterKnown(cfg.Filter) {
		return nil, fmt.Errorf("afpacket: unknown filter %q (want \"\" or one of %v)", cfg.Filter, BuiltinFilters())
	}
	snap := cfg.Snaplen
	if snap <= 0 {
		snap = DefaultSnaplen
	}
	if snap > DefaultSnaplen {
		return nil, fmt.Errorf("afpacket: snaplen %d exceeds the %d ceiling", snap, DefaultSnaplen)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afpacket: interface %q: %w", cfg.Interface, err)
	}

	proto := int(htons(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, afpErr(cfg.Interface, "socket(AF_PACKET, SOCK_RAW)", err)
	}

	a := &AFPacket{
		ifName:  iface.Name,
		ifIndex: iface.Index,
		snaplen: snap,
		filter:  cfg.Filter,
		fd:      fd,
		buf:     make([]byte, snap),
		stopc:   make(chan struct{}),
	}

	// Attach the cBPF filter BEFORE bind so no unfiltered frame is ever queued
	// (the classic attach-after-bind race). An empty filter attaches nothing.
	//
	// staticcheck flags AttachLsf as deprecated in favour of golang.org/x/net/bpf,
	// but that is a third-party dependency and this repo is stdlib-only
	// (PROJECT.md §27, §28.16). AttachLsf is a thin, stable
	// setsockopt(SO_ATTACH_FILTER) wrapper; the deprecation is advisory, not a
	// removal. Keeping it here avoids hand-rolling a per-arch raw setsockopt
	// (386 has no direct SYS_SETSOCKOPT).
	if prog := builtinFilter(cfg.Filter); len(prog) > 0 {
		if err := syscall.AttachLsf(fd, prog); err != nil { //nolint:staticcheck // SA1019: stdlib-only; see comment above
			_ = syscall.Close(fd)
			return nil, afpErr(cfg.Interface, "SO_ATTACH_FILTER", err)
		}
	}

	// A recv timeout is what makes Close and ctx cancellation responsive on an
	// idle link: Recvfrom returns EAGAIN every afpReadTimeout and the read loop
	// re-checks its exit conditions.
	tv := syscall.NsecToTimeval(int64(afpReadTimeout))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return nil, afpErr(cfg.Interface, "SO_RCVTIMEO", err)
	}

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		_ = syscall.Close(fd)
		return nil, afpErr(cfg.Interface, "bind", err)
	}

	if cfg.Promiscuous {
		if err := a.addPromisc(); err != nil {
			_ = syscall.Close(fd)
			return nil, afpErr(cfg.Interface, "PACKET_ADD_MEMBERSHIP (promiscuous)", err)
		}
	}

	// Opt-in TPACKET_V3 mmap ring. Set up after bind/promiscuous so the ring
	// only ever receives frames matching the attached filter and the bound
	// interface (issue #163).
	if cfg.Ring {
		ring, rerr := newAFPRing(fd)
		if rerr != nil {
			_ = syscall.Close(fd)
			return nil, afpErr(cfg.Interface, "PACKET_RX_RING (ring buffer)", rerr)
		}
		a.ring = ring
	}

	// Drain any drop counter accumulated during setup so the first real sample
	// starts from zero.
	a.pollDrops()
	atomic.StoreUint64(&a.stats.drops, 0)

	return a, nil
}

// LinkType is the link layer AF_PACKET SOCK_RAW delivers. It is always
// Ethernet: real NICs and loopback both frame that way, and a non-Ethernet
// link type decode-errors in the read loop rather than being negotiated.
func (a *AFPacket) LinkType() packet.LinkType { return packet.LinkEthernet }

// Packets streams decoded frames until ctx is cancelled or Close is called. The
// spawned goroutine owns fd teardown.
func (a *AFPacket) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, 512)
	errc := make(chan error, 1)

	a.start(ctx, errc, func(ts time.Time, frame []byte) bool {
		// AF_PACKET SOCK_RAW delivers the link-layer header; Ethernet framing
		// covers real NICs and loopback. Non-Ethernet link types (SLL, raw
		// tunnels) decode-error here and are counted, not fatal — richer link
		// handling is tracked for a follow-up.
		pk, derr := packet.Decode(packet.LinkEthernet, ts, frame)
		if derr != nil {
			atomic.AddUint64(&a.stats.decodeErr, 1)
			return true
		}
		atomic.AddUint64(&a.stats.decoded, 1)
		select {
		case out <- pk:
			return true
		case <-ctx.Done():
			errc <- ctx.Err()
			return false
		case <-a.stopc:
			return false
		}
	}, func() { close(out) })

	return out, errc
}

// RawPackets streams undecoded link-layer frames, for a sensor that forwards
// records to a remote synapsed instead of classifying them locally
// (PROJECT.md §5.3). Each frame is copied out of the shared receive buffer,
// because the receiver keeps it past the next read; the decoded Packets path
// deliberately keeps its zero-copy decode. A forwarded frame counts as
// "decoded" in Stats: the decode happens on the daemon.
func (a *AFPacket) RawPackets(ctx context.Context) (<-chan RawFrame, <-chan error) {
	out := make(chan RawFrame, 512)
	errc := make(chan error, 1)

	a.start(ctx, errc, func(ts time.Time, frame []byte) bool {
		cp := make([]byte, len(frame))
		copy(cp, frame)
		atomic.AddUint64(&a.stats.decoded, 1)
		select {
		case out <- RawFrame{TS: ts, Data: cp}:
			return true
		case <-ctx.Done():
			errc <- ctx.Err()
			return false
		case <-a.stopc:
			return false
		}
	}, func() { close(out) })

	return out, errc
}

// start launches the single read goroutine. closeOut closes whichever output
// channel the caller created.
func (a *AFPacket) start(ctx context.Context, errc chan error, emit func(time.Time, []byte) bool, closeOut func()) {
	a.started.Store(true)
	go func() {
		defer closeOut()
		defer close(errc)
		defer func() {
			a.ring.close() // nil-safe; unmaps the RX ring and closes its epoll fd
			_ = syscall.Close(a.fd)
		}()
		a.readLoop(ctx, errc, emit)
	}()
}

// readLoop pulls frames off the socket and hands each to emit until emit says
// stop, ctx is cancelled or Close is called. The slice passed to emit aliases
// the shared receive buffer and is only valid for that call.
func (a *AFPacket) readLoop(ctx context.Context, errc chan<- error, emit func(time.Time, []byte) bool) {
	if a.ring != nil {
		a.ringReadLoop(ctx, errc, emit)
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			errc <- err
			return
		}
		if a.closed.Load() {
			return
		}

		n, _, err := syscall.Recvfrom(a.fd, a.buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
				continue // recv timeout tick — loop back to the exit checks
			case a.closed.Load(), errors.Is(err, syscall.EBADF):
				return
			default:
				errc <- fmt.Errorf("afpacket: recvfrom %s: %w", a.ifName, err)
				return
			}
		}
		if n <= 0 {
			continue
		}

		atomic.AddUint64(&a.stats.packets, 1)
		atomic.AddUint64(&a.stats.bytes, uint64(n))
		ts := time.Now().UTC()
		atomic.StoreInt64(&a.stats.lastUnixNano, ts.UnixNano())

		if !emit(ts, a.buf[:n]) {
			return
		}
	}
}

// Stats returns a counter snapshot, refreshing the kernel drop counter as a side
// effect (PACKET_STATISTICS drains on read, so drops accumulate here).
func (a *AFPacket) Stats() Stats {
	a.pollDrops()
	var lt time.Time
	if last := atomic.LoadInt64(&a.stats.lastUnixNano); last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return Stats{
		Packets:   atomic.LoadUint64(&a.stats.packets),
		Decoded:   atomic.LoadUint64(&a.stats.decoded),
		DecodeErr: atomic.LoadUint64(&a.stats.decodeErr),
		Bytes:     atomic.LoadUint64(&a.stats.bytes),
		LastTS:    lt,
		Drops:     atomic.LoadUint64(&a.stats.drops),
	}
}

// Close unblocks the reader and releases the socket. It is safe to call more than
// once and safe to call before Packets.
func (a *AFPacket) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	close(a.stopc)
	if !a.started.Load() {
		// No read loop will ever run, so nobody else owns the fd or the ring.
		a.ring.close()
		return syscall.Close(a.fd)
	}
	// The read loop notices a.closed within afpReadTimeout and closes the fd on
	// its way out.
	return nil
}

// addPromisc joins the interface's promiscuous multicast membership. stdlib
// syscall has no PacketMreq helper, so the 16-byte struct packet_mreq
// { int mr_ifindex; u16 mr_type; u16 mr_alen; u8 mr_address[8] } is packed by
// hand and passed through SetsockoptString (which is just
// setsockopt(fd, level, opt, ptr, len)). Native byte order: the kernel reads
// these fields as host-endian.
func (a *AFPacket) addPromisc() error {
	var mreq [16]byte
	binary.NativeEndian.PutUint32(mreq[0:4], uint32(a.ifIndex))
	binary.NativeEndian.PutUint16(mreq[4:6], syscall.PACKET_MR_PROMISC)
	// mr_alen stays 0, mr_address stays zero.
	return syscall.SetsockoptString(a.fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, string(mreq[:]))
}

// pollDrops reads PACKET_STATISTICS and folds tp_drops into the running total.
// The kernel resets the counter on every read, so this must accumulate.
//
// stdlib syscall has no raw getsockopt for an arbitrary struct, so this reuses
// GetsockoptIPMreqn: its 12-byte buffer is large enough for
// struct tpacket_stats { u32 tp_packets; u32 tp_drops }, and tp_drops lands in
// the second 4-byte field (IPMreqn.Address). This keeps the read stdlib-only and
// byte-for-byte identical on amd64/386/arm64/arm (see ADR 0010).
func (a *AFPacket) pollDrops() {
	if a.closed.Load() {
		return
	}
	a.statMu.Lock()
	defer a.statMu.Unlock()
	v, err := syscall.GetsockoptIPMreqn(a.fd, syscall.SOL_PACKET, syscall.PACKET_STATISTICS)
	if err != nil {
		return
	}
	if drops := binary.NativeEndian.Uint32(v.Address[:]); drops != 0 {
		atomic.AddUint64(&a.stats.drops, uint64(drops))
	}
}

// htons converts a uint16 from host to network byte order without assuming the
// host is little-endian (all four release targets are, but this stays correct
// either way and needs no unsafe).
func htons(v uint16) uint16 {
	return binary.NativeEndian.Uint16([]byte{byte(v >> 8), byte(v)})
}

// builtinFilter returns the classic-BPF program for a preset name in the shape
// SO_ATTACH_FILTER wants, or nil for "" / an unknown name (NewAFPacket has
// already validated the name). The programs themselves live in bpffilter.go so
// the FreeBSD /dev/bpf source attaches byte-identical filters; struct
// sock_filter and struct bpf_insn have the same layout, so this is a field
// copy. Linux keeps bpfRetKeep as the accept length — unlike BPF on FreeBSD,
// AF_PACKET truncates to its own receive buffer rather than to the filter's
// return value, so the snaplen is not expressed here.
func builtinFilter(name string) []syscall.SockFilter {
	insns := builtinFilterInsns(name, bpfRetKeep)
	if len(insns) == 0 {
		return nil
	}
	prog := make([]syscall.SockFilter, len(insns))
	for i, in := range insns {
		prog[i] = syscall.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	return prog
}

// afpErr wraps a setup failure, turning a permission error into actionable
// capability guidance instead of a bare "operation not permitted" (PROJECT.md §21).
func afpErr(iface, op string, err error) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("afpacket: %s on %s failed: %w — grant CAP_NET_RAW "+
			"(and CAP_NET_ADMIN for promiscuous mode), e.g. "+
			"`setcap cap_net_raw,cap_net_admin+eip /usr/bin/synapsed`, or run under the "+
			"contrib/systemd unit which sets AmbientCapabilities; running as root is not required",
			op, iface, err)
	}
	return fmt.Errorf("afpacket: %s on %s failed: %w", op, iface, err)
}
