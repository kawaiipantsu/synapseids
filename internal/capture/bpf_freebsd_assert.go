//go:build freebsd && (amd64 || arm64)

package capture

import (
	"syscall"
	"unsafe"
)

// Compile-time cross-check of the hand-derived BPF ioctl numbers.
//
// bpfioctl.go derives every request number from the FreeBSD sys/ioccom.h
// encoding, and bpfioctl_test.go checks that derivation on Linux against the
// published values. This file closes the loop on the two FreeBSD release
// arches by comparing the same constants with the ones Go's own syscall
// package generates from the system headers. Each pair of constant
// subtractions is an equality assertion: if the two sides differ, one of them
// underflows and the build fails with a "constant ... overflows uint32" error
// naming the offending request.
//
// It is deliberately limited to amd64 and arm64 — the arches the Makefile
// ships — because the sizeof* constants in bpfioctl.go describe the LP64 ABI.
// bpf_freebsd.go itself measures the real structs with unsafe.Sizeof, so it
// stays correct on any FreeBSD GOARCH even where this file is not built.

// The ABI sizes the derivation assumes must match the real local structs.
const (
	_ uint32 = uint32(unsafe.Sizeof(bpfIfreq{})) - sizeofIfreq64
	_ uint32 = sizeofIfreq64 - uint32(unsafe.Sizeof(bpfIfreq{}))

	_ uint32 = uint32(unsafe.Sizeof(syscall.Timeval{})) - sizeofTimeval64
	_ uint32 = sizeofTimeval64 - uint32(unsafe.Sizeof(syscall.Timeval{}))

	_ uint32 = uint32(unsafe.Sizeof(syscall.BpfProgram{})) - sizeofBPFProgram64
	_ uint32 = sizeofBPFProgram64 - uint32(unsafe.Sizeof(syscall.BpfProgram{}))

	_ uint32 = uint32(unsafe.Sizeof(syscall.BpfStat{})) - sizeofBPFStat
	_ uint32 = sizeofBPFStat - uint32(unsafe.Sizeof(syscall.BpfStat{}))
)

// The derived request numbers must match syscall's generated ones.
const (
	_ uint32 = biocGBLEN64 - uint32(syscall.BIOCGBLEN)
	_ uint32 = uint32(syscall.BIOCGBLEN) - biocGBLEN64

	_ uint32 = biocSBLEN64 - uint32(syscall.BIOCSBLEN)
	_ uint32 = uint32(syscall.BIOCSBLEN) - biocSBLEN64

	_ uint32 = biocSETF64 - uint32(syscall.BIOCSETF)
	_ uint32 = uint32(syscall.BIOCSETF) - biocSETF64

	_ uint32 = biocFLUSH64 - uint32(syscall.BIOCFLUSH)
	_ uint32 = uint32(syscall.BIOCFLUSH) - biocFLUSH64

	_ uint32 = biocPROMISC64 - uint32(syscall.BIOCPROMISC)
	_ uint32 = uint32(syscall.BIOCPROMISC) - biocPROMISC64

	_ uint32 = biocGDLT64 - uint32(syscall.BIOCGDLT)
	_ uint32 = uint32(syscall.BIOCGDLT) - biocGDLT64

	_ uint32 = biocSETIF64 - uint32(syscall.BIOCSETIF)
	_ uint32 = uint32(syscall.BIOCSETIF) - biocSETIF64

	_ uint32 = biocSRTIMEOUT64 - uint32(syscall.BIOCSRTIMEOUT)
	_ uint32 = uint32(syscall.BIOCSRTIMEOUT) - biocSRTIMEOUT64

	_ uint32 = biocGSTATS64 - uint32(syscall.BIOCGSTATS)
	_ uint32 = uint32(syscall.BIOCGSTATS) - biocGSTATS64

	_ uint32 = biocIMMEDIATE64 - uint32(syscall.BIOCIMMEDIATE)
	_ uint32 = uint32(syscall.BIOCIMMEDIATE) - biocIMMEDIATE64

	_ uint32 = biocSHDRCMPLT64 - uint32(syscall.BIOCSHDRCMPLT)
	_ uint32 = uint32(syscall.BIOCSHDRCMPLT) - biocSHDRCMPLT64

	_ uint32 = biocSDIRECTION64 - uint32(syscall.BIOCSDIRECTION)
	_ uint32 = uint32(syscall.BIOCSDIRECTION) - biocSDIRECTION64
)

// Together these two blocks also pin the *runtime*-derived numbers that
// bpf_freebsd.go issues: those are computed with unsafe.Sizeof over the very
// structs whose sizes the first block just fixed, so equal sizes plus equal
// constants means equal requests. No third assertion is needed.
