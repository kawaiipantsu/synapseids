package capture

// FreeBSD BPF ioctl request numbers, derived by hand.
//
// SynapseIDS is stdlib-only (PROJECT.md §27, §28.16), so it cannot pull in
// golang.org/x/sys/unix for these. Go's own syscall package *does* ship the
// BIOC* constants for freebsd/amd64 and freebsd/arm64, but only for those
// GOARCHes and only as opaque magic numbers. Deriving them here from the
// documented FreeBSD encoding gives three things the stdlib constants do not:
// a build that is correct on any FreeBSD GOARCH (the sizes are taken from the
// local struct layouts at compile time in bpf_freebsd.go), a written-out
// derivation a reviewer can check, and a table test that runs on Linux
// (bpfioctl_test.go). bpf_freebsd_assert.go additionally pins the derived
// values against syscall.BIOC* at FreeBSD compile time on the two release
// arches, so a mistake here cannot reach a binary.
//
// The encoding is FreeBSD sys/ioccom.h:
//
//	#define IOCPARM_SHIFT   13
//	#define IOCPARM_MASK    ((1 << IOCPARM_SHIFT) - 1)   /* 0x1fff */
//	#define IOC_VOID        0x20000000
//	#define IOC_OUT         0x40000000                   /* kernel -> user */
//	#define IOC_IN          0x80000000                   /* user -> kernel */
//	#define IOC_INOUT       (IOC_IN|IOC_OUT)
//
//	#define _IOC(inout,group,num,len) \
//	    ((unsigned long)((inout) | (((len) & IOCPARM_MASK) << 16) | \
//	                     ((group) << 8) | (num)))
//	#define _IO(g,n)     _IOC(IOC_VOID,  (g), (n), 0)
//	#define _IOR(g,n,t)  _IOC(IOC_OUT,   (g), (n), sizeof(t))
//	#define _IOW(g,n,t)  _IOC(IOC_IN,    (g), (n), sizeof(t))
//	#define _IOWR(g,n,t) _IOC(IOC_INOUT, (g), (n), sizeof(t))
//
// Note the direction is expressed from the *kernel's* point of view: _IOR is a
// value the kernel writes out to userspace, _IOW one userspace passes in.
const (
	iocParmShift = 13
	iocParmMask  = (1 << iocParmShift) - 1 // 0x1fff

	iocVoid  = 0x20000000
	iocOut   = 0x40000000
	iocIn    = 0x80000000
	iocInOut = iocIn | iocOut

	// iocGroupBPF is the 'B' ioctl group every BIOC* request lives in
	// (FreeBSD net/bpf.h). 'B' is 0x42.
	iocGroupBPF = 'B'
)

// BPF command numbers from FreeBSD net/bpf.h. Only the ones SynapseIDS issues
// are listed; the numbering is a stable part of the FreeBSD ABI.
const (
	bpfCmdGBLEN      = 102 // BIOCGBLEN      _IOR('B', 102, u_int)
	bpfCmdSBLEN      = 102 // BIOCSBLEN      _IOWR('B', 102, u_int)
	bpfCmdSETF       = 103 // BIOCSETF       _IOW('B', 103, struct bpf_program)
	bpfCmdFLUSH      = 104 // BIOCFLUSH      _IO('B', 104)
	bpfCmdPROMISC    = 105 // BIOCPROMISC    _IO('B', 105)
	bpfCmdGDLT       = 106 // BIOCGDLT       _IOR('B', 106, u_int)
	bpfCmdSETIF      = 108 // BIOCSETIF      _IOW('B', 108, struct ifreq)
	bpfCmdSRTIMEOUT  = 109 // BIOCSRTIMEOUT  _IOW('B', 109, struct timeval)
	bpfCmdGSTATS     = 111 // BIOCGSTATS     _IOR('B', 111, struct bpf_stat)
	bpfCmdIMMEDIATE  = 112 // BIOCIMMEDIATE  _IOW('B', 112, u_int)
	bpfCmdSHDRCMPLT  = 117 // BIOCSHDRCMPLT  _IOW('B', 117, u_int)
	bpfCmdSDIRECTION = 119 // BIOCSDIRECTION _IOW('B', 119, u_int)
)

// Argument sizes for the FreeBSD 64-bit ABI (amd64 and arm64, both LP64).
// bpf_freebsd.go does not use these — it measures the real Go structs with
// unsafe.Sizeof so the code is right on any GOARCH — but they let the derived
// request numbers below be plain constants, which is what makes both the
// Linux-side table test and the FreeBSD-side compile assertions possible.
const (
	// sizeofUint is sizeof(u_int): 4 on every FreeBSD ABI.
	sizeofUint = 4
	// sizeofIfreq64 is sizeof(struct ifreq): char ifr_name[IFNAMSIZ=16] plus a
	// 16-byte ifr_ifru union (its widest member is struct sockaddr).
	sizeofIfreq64 = 16 + 16
	// sizeofTimeval64 is sizeof(struct timeval) under LP64: time_t (8) +
	// suseconds_t (8).
	sizeofTimeval64 = 8 + 8
	// sizeofBPFProgram64 is sizeof(struct bpf_program) under LP64:
	// u_int bf_len (4) + 4 bytes of padding + struct bpf_insn *bf_insns (8).
	sizeofBPFProgram64 = 4 + 4 + 8
	// sizeofBPFStat is sizeof(struct bpf_stat): u_int bs_recv + u_int bs_drop.
	sizeofBPFStat = 4 + 4
)

// The derived request numbers for the FreeBSD 64-bit ABI. Kept as constants so
// they can be asserted at compile time (bpf_freebsd_assert.go) and in a plain
// table test (bpfioctl_test.go).
const (
	biocGBLEN64      = iocOut | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdGBLEN         // 0x40044266
	biocSBLEN64      = iocInOut | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSBLEN       // 0xc0044266
	biocSETF64       = iocIn | (sizeofBPFProgram64&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSETF   // 0x80104267
	biocFLUSH64      = iocVoid | iocGroupBPF<<8 | bpfCmdFLUSH                                       // 0x20004268
	biocPROMISC64    = iocVoid | iocGroupBPF<<8 | bpfCmdPROMISC                                     // 0x20004269
	biocGDLT64       = iocOut | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdGDLT          // 0x4004426a
	biocSETIF64      = iocIn | (sizeofIfreq64&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSETIF       // 0x8020426c
	biocSRTIMEOUT64  = iocIn | (sizeofTimeval64&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSRTIMEOUT // 0x8010426d
	biocGSTATS64     = iocOut | (sizeofBPFStat&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdGSTATS     // 0x4008426f
	biocIMMEDIATE64  = iocIn | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdIMMEDIATE      // 0x80044270
	biocSHDRCMPLT64  = iocIn | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSHDRCMPLT      // 0x80044275
	biocSDIRECTION64 = iocIn | (sizeofUint&iocParmMask)<<16 | iocGroupBPF<<8 | bpfCmdSDIRECTION     // 0x80044277
)

// bpfIOC encodes one ioctl request in the 'B' group the way FreeBSD's _IOC
// macro does. size is the argument size in bytes; it is masked to IOCPARM_MASK
// exactly as the macro does, so an over-large struct silently truncates there
// too (no BPF argument comes close to 8191 bytes).
func bpfIOC(dir uint32, num uint32, size uintptr) uint32 {
	return dir | (uint32(size)&iocParmMask)<<16 | iocGroupBPF<<8 | num
}

// bpfIO builds an argument-less BPF request: _IO('B', num).
func bpfIO(num uint32) uint32 { return bpfIOC(iocVoid, num, 0) }

// bpfIOR builds a read-out BPF request: _IOR('B', num, t).
func bpfIOR(num uint32, size uintptr) uint32 { return bpfIOC(iocOut, num, size) }

// bpfIOW builds a write-in BPF request: _IOW('B', num, t).
func bpfIOW(num uint32, size uintptr) uint32 { return bpfIOC(iocIn, num, size) }

// bpfIOWR builds a read-write BPF request: _IOWR('B', num, t).
func bpfIOWR(num uint32, size uintptr) uint32 { return bpfIOC(iocInOut, num, size) }

// BPF packet directions for BIOCSDIRECTION (FreeBSD net/bpf.h). A WAN sensor
// that only wants traffic arriving from the internet sets bpfDirectionIn.
const (
	bpfDirectionIn    = 0 // BPF_D_IN
	bpfDirectionInOut = 1 // BPF_D_INOUT (the kernel default)
	bpfDirectionOut   = 2 // BPF_D_OUT
)
