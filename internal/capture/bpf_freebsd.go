//go:build freebsd

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// BPF ioctl request numbers for the ABI this binary is built for. They are
// derived from the FreeBSD sys/ioccom.h encoding in bpfioctl.go rather than
// taken from syscall.BIOC*, so the derivation is reviewable and testable on
// Linux; the sizes come from the real local struct layouts, so the numbers are
// right on any FreeBSD GOARCH. bpf_freebsd_assert.go pins them against
// syscall.BIOC* at compile time on the two release arches.
var (
	biocSBLEN      = bpfIOWR(bpfCmdSBLEN, unsafe.Sizeof(uint32(0)))
	biocSETF       = bpfIOW(bpfCmdSETF, unsafe.Sizeof(syscall.BpfProgram{}))
	biocFLUSH      = bpfIO(bpfCmdFLUSH)
	biocPROMISC    = bpfIO(bpfCmdPROMISC)
	biocGDLT       = bpfIOR(bpfCmdGDLT, unsafe.Sizeof(uint32(0)))
	biocSETIF      = bpfIOW(bpfCmdSETIF, unsafe.Sizeof(bpfIfreq{}))
	biocSRTIMEOUT  = bpfIOW(bpfCmdSRTIMEOUT, unsafe.Sizeof(syscall.Timeval{}))
	biocGSTATS     = bpfIOR(bpfCmdGSTATS, unsafe.Sizeof(syscall.BpfStat{}))
	biocIMMEDIATE  = bpfIOW(bpfCmdIMMEDIATE, unsafe.Sizeof(uint32(0)))
	biocSDIRECTION = bpfIOW(bpfCmdSDIRECTION, unsafe.Sizeof(uint32(0)))
)

// bpfIfreq is FreeBSD's struct ifreq as BIOCSETIF wants it: a NUL-padded
// IFNAMSIZ interface name followed by the 16-byte ifr_ifru union, which
// BIOCSETIF ignores and we leave zeroed.
type bpfIfreq struct {
	Name [16]byte // IFNAMSIZ
	Pad  [16]byte // union ifr_ifru; widest member is struct sockaddr
}

// FreeBSD DLT values BIOCGDLT can report. Note that DLT_RAW is 12 in the
// FreeBSD kernel but 101 in a libpcap savefile (LINKTYPE_RAW), and
// packet.LinkRaw uses the libpcap number — so the two are mapped, not equated.
const (
	dltNull   = 0   // BSD loopback: a 4-byte host-order address family, then IP
	dltEN10MB = 1   // Ethernet
	dltRawBSD = 12  // FreeBSD DLT_RAW
	dltRawPC  = 101 // LINKTYPE_RAW as it appears in savefiles
	dltLoop   = 108 // OpenBSD loopback framing
)

// bpfMaxDeviceIndex bounds the /dev/bpfN probe. FreeBSD has cloned bpf devices
// since 5.x, so the loop is a fallback for a devfs that pre-creates them.
const bpfMaxDeviceIndex = 256

// BPFDevice is a live Source backed by a FreeBSD BPF device (/dev/bpf). Every
// frame goes through the same packet.Decode path a PCAP replay uses, so the
// pipeline and UI behave identically for live and replayed traffic
// (PROJECT.md §6).
//
// It needs read access to a bpf device, which on FreeBSD is a group/devfs
// concern, not a root one: the sensor runs as a dedicated unprivileged user in
// the "net" group with a devfs rule over bpf* (PROJECT.md §21). The device is
// opened read-only, so this source cannot transmit even in principle
// (PROJECT.md §28.17).
type BPFDevice struct {
	statMu sync.Mutex // serialises the BIOCGSTATS read
	stats  struct {
		packets, decoded, decodeErr, bytes uint64
		drops                              uint64
		lastUnixNano                       int64
	}

	ifName  string
	device  string
	filter  string
	link    packet.LinkType
	layout  bpfHdrLayout
	bufLen  int
	snaplen int

	fd    int
	stopc chan struct{}

	closed  atomic.Bool
	started atomic.Bool
}

// NewBPFDevice opens a BPF device, binds it to cfg.Interface and configures it.
// It does not start reading until Packets or RawPackets is called. An
// EACCES/EPERM failure explains the devfs/group fix instead of demanding root.
func NewBPFDevice(cfg BPFConfig) (*BPFDevice, error) {
	if cfg.Interface == "" {
		return nil, errors.New("bpf: interface name is required")
	}
	if len(cfg.Interface) >= len(bpfIfreq{}.Name) {
		return nil, fmt.Errorf("bpf: interface name %q is longer than the %d-byte IFNAMSIZ limit",
			cfg.Interface, len(bpfIfreq{}.Name)-1)
	}
	if !FilterKnown(cfg.Filter) {
		return nil, fmt.Errorf("bpf: unknown filter %q (want \"\" or one of %v)", cfg.Filter, BuiltinFilters())
	}
	direction, defaultDirection, ok := bpfDirectionCode(cfg.Direction)
	if !ok {
		return nil, fmt.Errorf("bpf: unknown direction %q (want \"\" or one of %v)", cfg.Direction, BPFDirections())
	}
	snap := cfg.Snaplen
	if snap <= 0 {
		snap = DefaultSnaplen
	}
	if snap > DefaultSnaplen {
		return nil, fmt.Errorf("bpf: snaplen %d exceeds the %d ceiling", snap, DefaultSnaplen)
	}
	bufLen := cfg.BufferLen
	if bufLen <= 0 {
		bufLen = DefaultBPFBufferLen
	}
	if bufLen < MinBPFBufferLen || bufLen > MaxBPFBufferLen {
		return nil, fmt.Errorf("bpf: buffer length %d out of range [%d, %d]", bufLen, MinBPFBufferLen, MaxBPFBufferLen)
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultBPFReadTimeout
	}

	fd, device, err := openBPFDevice(cfg.Device)
	if err != nil {
		return nil, err
	}

	d := &BPFDevice{
		ifName:  cfg.Interface,
		device:  device,
		filter:  cfg.Filter,
		bufLen:  bufLen,
		snaplen: snap,
		fd:      fd,
		stopc:   make(chan struct{}),
		layout:  bpfHostLayout(),
	}
	fail := func(op string, err error) (*BPFDevice, error) {
		_ = syscall.Close(fd)
		return nil, bpfErr(device, cfg.Interface, op, err)
	}

	// BIOCSBLEN must precede BIOCSETIF: FreeBSD refuses a buffer resize once
	// the descriptor is attached to an interface. The kernel clamps the value
	// to net.bpf.maxbufsize and writes back what it granted.
	granted := uint32(bufLen) //nolint:gosec // bounded by MaxBPFBufferLen above
	if err := bpfIoctl(fd, biocSBLEN, unsafe.Pointer(&granted)); err != nil {
		return fail("BIOCSBLEN", err)
	}
	if granted < MinBPFBufferLen || granted > MaxBPFBufferLen {
		return fail("BIOCSBLEN", fmt.Errorf("kernel granted an unusable buffer of %d bytes", granted))
	}
	d.bufLen = int(granted)

	// Attach the filter BEFORE binding the interface so no unfiltered frame is
	// ever queued (the classic attach-after-bind race). BPF has no snaplen
	// ioctl, so the accept length of the program's BPF_RET *is* the snaplen —
	// which is why a filter is installed even when no preset was named.
	insns := builtinFilterInsns(cfg.Filter, uint32(snap)) //nolint:gosec // snap <= DefaultSnaplen
	if len(insns) == 0 {
		insns = builtinFilterAcceptAll(uint32(snap)) //nolint:gosec // snap <= DefaultSnaplen
	}
	if err := d.setFilter(insns); err != nil {
		return fail("BIOCSETF", err)
	}

	var ifr bpfIfreq
	copy(ifr.Name[:], cfg.Interface)
	if err := bpfIoctl(fd, biocSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail("BIOCSETIF", err)
	}

	if cfg.Promiscuous {
		if err := bpfIoctl(fd, biocPROMISC, nil); err != nil {
			return fail("BIOCPROMISC", err)
		}
	}

	// Deliver each batch as soon as a packet arrives rather than waiting for
	// the store buffer to fill — an idle link must not sit on a packet for
	// minutes (PROJECT.md §22, §17).
	immediate := uint32(1)
	if err := bpfIoctl(fd, biocIMMEDIATE, unsafe.Pointer(&immediate)); err != nil {
		return fail("BIOCIMMEDIATE", err)
	}

	// The read timeout is what makes Close and context cancellation
	// responsive: read(2) returns 0 bytes when it expires and the loop
	// re-checks its exit conditions.
	tv := syscall.NsecToTimeval(int64(readTimeout))
	if err := bpfIoctl(fd, biocSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fail("BIOCSRTIMEOUT", err)
	}

	if !defaultDirection {
		dir := direction
		if err := bpfIoctl(fd, biocSDIRECTION, unsafe.Pointer(&dir)); err != nil {
			return fail("BIOCSDIRECTION", err)
		}
	}

	var dlt uint32
	if err := bpfIoctl(fd, biocGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail("BIOCGDLT", err)
	}
	link, err := bpfLinkType(dlt, cfg.Interface)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	d.link = link

	// BIOCFLUSH drops whatever queued during setup and, on FreeBSD, also zeroes
	// the descriptor's receive/drop counters — so BIOCGSTATS reads from here on
	// are a clean cumulative total for this capture.
	if err := bpfIoctl(fd, biocFLUSH, nil); err != nil {
		return fail("BIOCFLUSH", err)
	}
	return d, nil
}

// LinkType is the link layer BIOCGDLT reported, as a libpcap DLT.
func (d *BPFDevice) LinkType() packet.LinkType { return d.link }

// Device is the BPF device path in use, for logs and the capture-sources view.
func (d *BPFDevice) Device() string { return d.device }

// Packets streams decoded frames until ctx is cancelled or Close is called. The
// spawned goroutine owns fd teardown.
func (d *BPFDevice) Packets(ctx context.Context) (<-chan packet.Packet, <-chan error) {
	out := make(chan packet.Packet, 512)
	errc := make(chan error, 1)

	d.start(ctx, errc, func(rec bpfRecord) bool {
		pk, derr := packet.Decode(d.link, rec.TS, rec.Frame)
		if derr != nil {
			atomic.AddUint64(&d.stats.decodeErr, 1)
			return true
		}
		atomic.AddUint64(&d.stats.decoded, 1)
		select {
		case out <- pk:
			return true
		case <-ctx.Done():
			errc <- ctx.Err()
			return false
		case <-d.stopc:
			return false
		}
	}, func() { close(out) })

	return out, errc
}

// RawPackets streams undecoded link-layer frames, for a sensor that forwards
// records to a remote synapsed instead of classifying them locally
// (PROJECT.md §5.3). Each frame is copied out of the shared read buffer,
// because the receiver keeps it past the next read. A forwarded frame counts
// as "decoded" in Stats: the decode happens on the daemon.
func (d *BPFDevice) RawPackets(ctx context.Context) (<-chan RawFrame, <-chan error) {
	out := make(chan RawFrame, 512)
	errc := make(chan error, 1)

	d.start(ctx, errc, func(rec bpfRecord) bool {
		frame := make([]byte, len(rec.Frame))
		copy(frame, rec.Frame)
		atomic.AddUint64(&d.stats.decoded, 1)
		select {
		case out <- RawFrame{TS: rec.TS, Data: frame}:
			return true
		case <-ctx.Done():
			errc <- ctx.Err()
			return false
		case <-d.stopc:
			return false
		}
	}, func() { close(out) })

	return out, errc
}

// start launches the single read goroutine. closeOut closes whichever output
// channel the caller created.
func (d *BPFDevice) start(ctx context.Context, errc chan error, emit func(bpfRecord) bool, closeOut func()) {
	d.started.Store(true)
	go func() {
		defer closeOut()
		defer close(errc)
		defer func() { _ = syscall.Close(d.fd) }()
		d.readLoop(ctx, errc, emit)
	}()
}

// readLoop pulls chunks off the BPF device, splits each into records and hands
// them to emit until emit says stop, ctx is cancelled or Close is called.
func (d *BPFDevice) readLoop(ctx context.Context, errc chan<- error, emit func(bpfRecord) bool) {
	buf := make([]byte, d.bufLen)
	recs := make([]bpfRecord, 0, 256)

	for {
		if err := ctx.Err(); err != nil {
			errc <- err
			return
		}
		if d.closed.Load() {
			return
		}

		n, err := syscall.Read(d.fd, buf)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EINTR), errors.Is(err, syscall.EAGAIN):
				continue
			case d.closed.Load(), errors.Is(err, syscall.EBADF):
				return
			default:
				errc <- bpfErr(d.device, d.ifName, "read", err)
				return
			}
		}
		// n == 0 is the BIOCSRTIMEOUT tick with an empty store buffer, NOT
		// end-of-file: a character device that reports 0 here has simply gone
		// quiet for a read timeout.
		if n <= 0 {
			continue
		}

		var perr error
		recs, perr = parseBPFChunk(recs[:0], buf[:n], d.layout)
		if perr != nil {
			// Untrusted kernel-buffer contents: count it and keep the good
			// records from the same chunk (PROJECT.md §28.11).
			atomic.AddUint64(&d.stats.decodeErr, 1)
		}
		for _, rec := range recs {
			atomic.AddUint64(&d.stats.packets, 1)
			atomic.AddUint64(&d.stats.bytes, uint64(rec.OrigLen))
			atomic.StoreInt64(&d.stats.lastUnixNano, rec.TS.UnixNano())
			if !emit(rec) {
				return
			}
		}
	}
}

// Stats returns a counter snapshot, refreshing the kernel drop counter from
// BIOCGSTATS as a side effect. Unlike AF_PACKET's PACKET_STATISTICS the
// FreeBSD counters are cumulative for the descriptor's lifetime, so this
// assigns rather than accumulates.
func (d *BPFDevice) Stats() Stats {
	d.pollDrops()
	var lt time.Time
	if last := atomic.LoadInt64(&d.stats.lastUnixNano); last != 0 {
		lt = time.Unix(0, last).UTC()
	}
	return Stats{
		Packets:   atomic.LoadUint64(&d.stats.packets),
		Decoded:   atomic.LoadUint64(&d.stats.decoded),
		DecodeErr: atomic.LoadUint64(&d.stats.decodeErr),
		Bytes:     atomic.LoadUint64(&d.stats.bytes),
		LastTS:    lt,
		Drops:     atomic.LoadUint64(&d.stats.drops),
	}
}

// Close unblocks the reader and releases the device. It is safe to call more
// than once and safe to call before Packets.
func (d *BPFDevice) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	close(d.stopc)
	if !d.started.Load() {
		return syscall.Close(d.fd)
	}
	// The read loop notices d.closed within the BIOCSRTIMEOUT window and
	// closes the fd on its way out.
	return nil
}

// pollDrops reads BIOCGSTATS and stores bs_drop as the current drop total.
func (d *BPFDevice) pollDrops() {
	if d.closed.Load() {
		return
	}
	d.statMu.Lock()
	defer d.statMu.Unlock()
	var st syscall.BpfStat
	if err := bpfIoctl(d.fd, biocGSTATS, unsafe.Pointer(&st)); err != nil {
		return
	}
	atomic.StoreUint64(&d.stats.drops, uint64(st.Drop))
}

// setFilter installs a classic-BPF program with BIOCSETF. The instruction slice
// must stay reachable for the duration of the ioctl, which the KeepAlive in
// bpfIoctl plus the local variable here guarantee.
func (d *BPFDevice) setFilter(insns []bpfInsn) error {
	prog := make([]syscall.BpfInsn, len(insns))
	for i, in := range insns {
		prog[i] = syscall.BpfInsn{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	bp := syscall.BpfProgram{
		Len:   uint32(len(prog)), //nolint:gosec // preset programs are a handful of instructions
		Insns: &prog[0],
	}
	err := bpfIoctl(d.fd, biocSETF, unsafe.Pointer(&bp))
	runtime.KeepAlive(prog)
	return err
}

// openBPFDevice opens the named device, or probes for a free one when name is
// empty: the cloning /dev/bpf first, then /dev/bpf0../dev/bpf255. It returns
// the fd and the path that was opened.
func openBPFDevice(name string) (int, string, error) {
	// Read-only: SynapseIDS observes, it never injects (PROJECT.md §28.17).
	const flags = syscall.O_RDONLY | syscall.O_CLOEXEC

	if name != "" {
		fd, err := syscall.Open(name, flags, 0)
		if err != nil {
			return -1, "", bpfErr(name, "", "open", err)
		}
		return fd, name, nil
	}

	fd, err := syscall.Open("/dev/bpf", flags, 0)
	if err == nil {
		return fd, "/dev/bpf", nil
	}
	// A permission problem on the cloning device will repeat on every /dev/bpfN,
	// so surface it now with the actionable message rather than after 256 tries.
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return -1, "", bpfErr("/dev/bpf", "", "open", err)
	}
	firstErr := err

	for i := range bpfMaxDeviceIndex {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(path, flags, 0)
		if err == nil {
			return fd, path, nil
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return -1, "", bpfErr(path, "", "open", err)
		}
		if errors.Is(err, syscall.ENOENT) {
			break // the devfs does not pre-create them; nothing further to try
		}
	}
	return -1, "", fmt.Errorf("bpf: no usable BPF device: /dev/bpf: %w "+
		"(and no free /dev/bpfN) — every device is busy or devfs exposes none", firstErr)
}

// bpfLinkType maps a BIOCGDLT value onto the libpcap DLT the decoder speaks,
// rejecting anything else with advice rather than a bare number.
func bpfLinkType(dlt uint32, iface string) (packet.LinkType, error) {
	switch dlt {
	case dltEN10MB:
		return packet.LinkEthernet, nil
	case dltRawBSD, dltRawPC:
		return packet.LinkRaw, nil
	case dltNull, dltLoop:
		return 0, fmt.Errorf("bpf: interface %q uses BSD loopback framing (DLT %d), which SynapseIDS "+
			"cannot decode — capture on the physical parent interface instead", iface, dlt)
	default:
		return 0, fmt.Errorf("bpf: interface %q reports link type DLT %d; SynapseIDS decodes only "+
			"Ethernet (DLT %d) and raw IP (DLT %d)", iface, dlt, dltEN10MB, dltRawBSD)
	}
}

// bpfHostLayout describes this host's BPF record header. The offsets are taken
// from syscall.BpfHdr, the kernel's own struct bpf_hdr for this GOARCH, so the
// parser needs no per-arch table. FreeBSD's default timestamp format is
// BPF_T_MICROTIME, which is the struct timeval form BpfHdr models; SynapseIDS
// does not issue BIOCSTSTAMP, so that is what arrives.
func bpfHostLayout() bpfHdrLayout {
	var h syscall.BpfHdr
	base := int(unsafe.Offsetof(h.Tstamp))
	return bpfHdrLayout{
		order:       binary.NativeEndian,
		tsSecOff:    base + int(unsafe.Offsetof(h.Tstamp.Sec)),
		tsSecWidth:  int(unsafe.Sizeof(h.Tstamp.Sec)),
		tsFracOff:   base + int(unsafe.Offsetof(h.Tstamp.Usec)),
		tsFracWidth: int(unsafe.Sizeof(h.Tstamp.Usec)),
		fracPerSec:  1e6, // microseconds
		fracNanos:   1000,
		capLenOff:   int(unsafe.Offsetof(h.Caplen)),
		dataLenOff:  int(unsafe.Offsetof(h.Datalen)),
		hdrLenOff:   int(unsafe.Offsetof(h.Hdrlen)),
		minHdrLen:   int(unsafe.Offsetof(h.Hdrlen)) + int(unsafe.Sizeof(h.Hdrlen)),
		// BPF_ALIGNMENT is sizeof(long), which is the pointer width on every
		// FreeBSD ABI Go targets.
		align: int(unsafe.Sizeof(uintptr(0))),
	}
}

// bpfIoctl issues one ioctl on a BPF descriptor. arg may be nil for the
// argument-less _IO requests. The KeepAlive holds the referenced object across
// the call, since the compiler only sees a uintptr.
func bpfIoctl(fd int, req uint32, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	runtime.KeepAlive(arg)
	if errno != 0 {
		return errno
	}
	return nil
}

// bpfErr wraps a setup or read failure. A permission error becomes concrete
// devfs guidance rather than "operation not permitted", because the whole point
// is that the sensor does not run as root (PROJECT.md §21).
func bpfErr(device, iface, op string, err error) error {
	where := device
	if iface != "" {
		where = device + " on " + iface
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("bpf: %s on %s failed: %w — the capture user needs read access to the bpf "+
			"devices. Add it to the \"net\" group and install a devfs rule, e.g. in /etc/devfs.rules:\n"+
			"    [synapseids_bpf=10]\n"+
			"    add path 'bpf*' mode 0640 group net\n"+
			"then set devfs_system_ruleset=\"synapseids_bpf\" in /etc/rc.conf and restart devfs. "+
			"Running as root is not required", op, where, err)
	}
	if errors.Is(err, syscall.ENXIO) {
		return fmt.Errorf("bpf: %s on %s failed: %w — the interface does not exist or has gone away",
			op, where, err)
	}
	return fmt.Errorf("bpf: %s on %s failed: %w", op, where, err)
}
