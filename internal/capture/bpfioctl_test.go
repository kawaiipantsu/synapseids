package capture

import "testing"

// The published FreeBSD BPF ioctl request numbers for the LP64 ABI (amd64 and
// arm64). They are reproduced here as literals on purpose: the point of the
// test is to catch a mistake in the derivation in bpfioctl.go, so the expected
// side must not be computed the same way. These match FreeBSD's net/bpf.h and
// the constants Go's own syscall package generates for freebsd/amd64 and
// freebsd/arm64 — which bpf_freebsd_assert.go additionally pins at compile
// time when actually building for FreeBSD.
func TestBPFIoctlNumbersMatchFreeBSD(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"BIOCGBLEN", biocGBLEN64, 0x40044266},
		{"BIOCSBLEN", biocSBLEN64, 0xc0044266},
		{"BIOCSETF", biocSETF64, 0x80104267},
		{"BIOCFLUSH", biocFLUSH64, 0x20004268},
		{"BIOCPROMISC", biocPROMISC64, 0x20004269},
		{"BIOCGDLT", biocGDLT64, 0x4004426a},
		{"BIOCSETIF", biocSETIF64, 0x8020426c},
		{"BIOCSRTIMEOUT", biocSRTIMEOUT64, 0x8010426d},
		{"BIOCGSTATS", biocGSTATS64, 0x4008426f},
		{"BIOCIMMEDIATE", biocIMMEDIATE64, 0x80044270},
		{"BIOCSHDRCMPLT", biocSHDRCMPLT64, 0x80044275},
		{"BIOCSDIRECTION", biocSDIRECTION64, 0x80044277},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#08x, want %#08x", tc.name, tc.got, tc.want)
		}
	}
}

// The helper functions must produce the same numbers as the constants, since
// bpf_freebsd.go builds its requests through them with sizes measured by
// unsafe.Sizeof rather than with the constants.
func TestBPFIoctlHelpers(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"_IOR('B',102,u_int)", bpfIOR(bpfCmdGBLEN, sizeofUint), 0x40044266},
		{"_IOWR('B',102,u_int)", bpfIOWR(bpfCmdSBLEN, sizeofUint), 0xc0044266},
		{"_IOW('B',103,struct bpf_program)", bpfIOW(bpfCmdSETF, sizeofBPFProgram64), 0x80104267},
		{"_IO('B',104)", bpfIO(bpfCmdFLUSH), 0x20004268},
		{"_IO('B',105)", bpfIO(bpfCmdPROMISC), 0x20004269},
		{"_IOR('B',106,u_int)", bpfIOR(bpfCmdGDLT, sizeofUint), 0x4004426a},
		{"_IOW('B',108,struct ifreq)", bpfIOW(bpfCmdSETIF, sizeofIfreq64), 0x8020426c},
		{"_IOW('B',109,struct timeval)", bpfIOW(bpfCmdSRTIMEOUT, sizeofTimeval64), 0x8010426d},
		{"_IOR('B',111,struct bpf_stat)", bpfIOR(bpfCmdGSTATS, sizeofBPFStat), 0x4008426f},
		{"_IOW('B',112,u_int)", bpfIOW(bpfCmdIMMEDIATE, sizeofUint), 0x80044270},
		{"_IOW('B',117,u_int)", bpfIOW(bpfCmdSHDRCMPLT, sizeofUint), 0x80044275},
		{"_IOW('B',119,u_int)", bpfIOW(bpfCmdSDIRECTION, sizeofUint), 0x80044277},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#08x, want %#08x", tc.name, tc.got, tc.want)
		}
	}
}

// The 'B' group and the field packing must land where sys/ioccom.h says.
func TestBPFIOCEncoding(t *testing.T) {
	if iocGroupBPF != 0x42 {
		t.Fatalf("the BPF ioctl group is 'B' = 0x42, got %#x", iocGroupBPF)
	}
	// Direction bits occupy the top three bits, the size the next 13, then the
	// group byte and the command number.
	got := bpfIOC(iocIn, 108, 32)
	if got>>29 != 0x4 { // IOC_IN alone
		t.Errorf("direction bits = %#x, want IOC_IN", got>>29)
	}
	if (got>>16)&iocParmMask != 32 {
		t.Errorf("size field = %d, want 32", (got>>16)&iocParmMask)
	}
	if (got>>8)&0xff != 'B' {
		t.Errorf("group byte = %#x, want 'B'", (got>>8)&0xff)
	}
	if got&0xff != 108 {
		t.Errorf("command number = %d, want 108", got&0xff)
	}

	// The size field is 13 bits wide, so it wraps exactly as the C macro does.
	if got, want := bpfIOC(iocIn, 1, iocParmMask+1), uint32(iocIn|'B'<<8|1); got != want {
		t.Errorf("oversized argument: got %#08x, want %#08x (size masked to zero)", got, want)
	}
}

func TestBPFDirectionCode(t *testing.T) {
	for _, tc := range []struct {
		in        string
		code      uint32
		isDefault bool
		ok        bool
	}{
		{"", bpfDirectionInOut, true, true},
		{"inout", bpfDirectionInOut, true, true},
		{"in", bpfDirectionIn, false, true},
		{"out", bpfDirectionOut, false, true},
		{"both", 0, false, false},
		{"IN", 0, false, false},
	} {
		code, isDefault, ok := bpfDirectionCode(tc.in)
		if code != tc.code || isDefault != tc.isDefault || ok != tc.ok {
			t.Errorf("bpfDirectionCode(%q) = (%d, %v, %v), want (%d, %v, %v)",
				tc.in, code, isDefault, ok, tc.code, tc.isDefault, tc.ok)
		}
	}
}
