package capture

import "testing"

// Every advertised preset must assemble, and nothing else may.
func TestBuiltinFilterInsns(t *testing.T) {
	for _, name := range BuiltinFilters() {
		prog := builtinFilterInsns(name, bpfRetKeep)
		if len(prog) == 0 {
			t.Errorf("builtinFilterInsns(%q) returned no instructions", name)
			continue
		}
		if prog[0].Code != bpfLdHAbs || prog[0].K != ethTypeK {
			t.Errorf("%q: first instruction should load the EtherType at offset %d, got %+v",
				name, ethTypeK, prog[0])
		}
		last := prog[len(prog)-1]
		if last.Code != bpfRetK || last.K != 0 {
			t.Errorf("%q: the fall-through must be a drop, got %+v", name, last)
		}
	}

	if prog := builtinFilterInsns("", bpfRetKeep); prog != nil {
		t.Errorf(`builtinFilterInsns("") = %v, want nil`, prog)
	}
	if prog := builtinFilterInsns("tcp port 80", bpfRetKeep); prog != nil {
		t.Errorf("an unknown preset must assemble to nil, got %v", prog)
	}
}

// On FreeBSD the accept length of BPF_RET *is* the snaplen, so the keep value
// has to be threaded through rather than fixed at bpfRetKeep.
func TestBuiltinFilterInsnsHonoursKeepLength(t *testing.T) {
	const snap = 1514
	for _, name := range BuiltinFilters() {
		for _, in := range builtinFilterInsns(name, snap) {
			if in.Code == bpfRetK && in.K != 0 && in.K != snap {
				t.Errorf("%q: accept instruction returns %d bytes, want the %d snaplen", name, in.K, snap)
			}
		}
	}

	all := builtinFilterAcceptAll(snap)
	if len(all) != 1 || all[0].Code != bpfRetK || all[0].K != snap {
		t.Fatalf("builtinFilterAcceptAll(%d) = %+v, want a single BPF_RET of %d", snap, all, snap)
	}
}

// bpfRetKeep doubles as the default snaplen; if they ever diverge, the Linux
// filter would silently start truncating.
func TestBPFRetKeepMatchesDefaultSnaplen(t *testing.T) {
	if bpfRetKeep != DefaultSnaplen {
		t.Fatalf("bpfRetKeep = %d, DefaultSnaplen = %d; they must agree", bpfRetKeep, DefaultSnaplen)
	}
}
