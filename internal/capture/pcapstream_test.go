package capture

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", "pcap", name)
}

// collectViaPCAPFile is the reference: the committed PCAPFile.Packets path.
func collectViaPCAPFile(t *testing.T, name string) []packet.Packet {
	t.Helper()
	pf, err := OpenPCAPFile(fixturePath(name))
	if err != nil {
		t.Fatalf("OpenPCAPFile(%s): %v", name, err)
	}
	pkts, errc := pf.Packets(context.Background())
	var got []packet.Packet
	for p := range pkts {
		got = append(got, p)
	}
	if err := <-errc; err != nil {
		t.Fatalf("%s: terminal error from PCAPFile: %v", name, err)
	}
	return got
}

// collectViaStream drives the extracted decodePCAPStream over a plain file
// reader — the code path tcpdump/ssh subprocess sources use.
func collectViaStream(t *testing.T, name string) ([]packet.Packet, streamStats) {
	t.Helper()
	f, err := os.Open(fixturePath(name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()

	out := make(chan packet.Packet, 16)
	errc := make(chan error, 1)
	var st streamStats
	go func() {
		defer close(out)
		defer close(errc)
		decodePCAPStream(context.Background(), f, out, errc, &st)
	}()

	var got []packet.Packet
	for p := range out {
		got = append(got, p)
	}
	if err := <-errc; err != nil {
		t.Fatalf("%s: terminal error from decodePCAPStream: %v", name, err)
	}
	return got, st
}

// TestDecodePCAPStreamMatchesPCAPFile is the behaviour-preservation gate for the
// refactor: for every committed fixture (classic pcap and pcapng), the shared
// decodePCAPStream engine must yield exactly the packets PCAPFile yields, and
// the same counters.
func TestDecodePCAPStreamMatchesPCAPFile(t *testing.T) {
	for _, name := range []string{"http.pcap", "portscan.pcap", "udp.pcap", "http.pcapng"} {
		t.Run(name, func(t *testing.T) {
			want := collectViaPCAPFile(t, name)
			got, st := collectViaStream(t, name)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: %d packets via stream vs %d via PCAPFile; first mismatch differs", name, len(got), len(want))
			}
			if len(want) == 0 {
				t.Fatalf("%s: fixture produced no packets — test is not exercising anything", name)
			}
			if st.packets != uint64(len(want)) || st.decoded != uint64(len(want)) {
				t.Fatalf("%s: stream counters packets=%d decoded=%d, want %d/%d",
					name, st.packets, st.decoded, len(want), len(want))
			}

			// The reference PCAPFile.Stats() must agree with the stream counters.
			pf, _ := OpenPCAPFile(fixturePath(name))
			pkts, errc := pf.Packets(context.Background())
			for range pkts { //nolint:revive // drain
			}
			<-errc
			if s := pf.Stats(); s.Packets != st.packets || s.Decoded != st.decoded || s.Bytes != st.bytes {
				t.Fatalf("%s: PCAPFile.Stats %+v disagrees with stream counters packets=%d decoded=%d bytes=%d",
					name, s, st.packets, st.decoded, st.bytes)
			}
		})
	}
}

// TestDecodePCAPStreamRejectsGarbage: a non-pcap byte stream is a terminal
// ErrNotPCAP, never a panic.
func TestDecodePCAPStreamRejectsGarbage(t *testing.T) {
	out := make(chan packet.Packet, 1)
	errc := make(chan error, 1)
	var st streamStats
	go func() {
		defer close(out)
		defer close(errc)
		decodePCAPStream(context.Background(), strings.NewReader("not a pcap at all, just text"), out, errc, &st)
	}()
	for range out { //nolint:revive // drain
	}
	if err := <-errc; err != ErrNotPCAP {
		t.Fatalf("garbage stream: err = %v, want ErrNotPCAP", err)
	}
}
