package capture

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTcpdumpArgsAssembly(t *testing.T) {
	ts, err := NewTcpdumpStream(TcpdumpConfig{
		Binary:    fakecapBin,
		Interface: "eth0",
		Filter:    "tcp port 80 or icmp",
		Snaplen:   65535,
		ExtraArgs: []string{"-p"},
	})
	if err != nil {
		t.Fatalf("NewTcpdumpStream: %v", err)
	}
	got := ts.Argv()
	if got[0] != fakecapBin {
		t.Fatalf("argv[0] = %q, want the resolved binary %q", got[0], fakecapBin)
	}
	want := []string{
		"-U", "--immediate-mode", "-w", "-", "-i", "eth0", "-s", "65535",
		"-p", "tcp", "port", "80", "or", "icmp",
	}
	if !reflect.DeepEqual(got[1:], want) {
		t.Fatalf("tcpdump argv = %v\nwant %v", got[1:], want)
	}
}

func TestTcpdumpStreamYieldsFixturePackets(t *testing.T) {
	t.Setenv("FAKECAP_PCAP", absFixture(t, "http.pcap"))

	ts, err := NewTcpdumpStream(TcpdumpConfig{Binary: fakecapBin, Interface: "lo"})
	if err != nil {
		t.Fatalf("NewTcpdumpStream: %v", err)
	}
	got, termErr := drainSource(t, context.Background(), ts)
	if termErr != nil {
		t.Fatalf("terminal error: %v", termErr)
	}
	mustSameField(t, "tcpdump(http.pcap)", got, collectViaPCAPFile(t, "http.pcap"))

	if s := ts.Stats(); s.Packets != uint64(len(got)) || s.Decoded != uint64(len(got)) {
		t.Fatalf("stats %+v disagree with %d packets", s, len(got))
	}
}

func TestTcpdumpStreamSurfacesNonZeroExit(t *testing.T) {
	t.Setenv("FAKECAP_STDERR", "tcpdump: eth0: You don't have permission to capture on that device")
	t.Setenv("FAKECAP_EXIT", "2")

	ts, err := NewTcpdumpStream(TcpdumpConfig{Binary: fakecapBin, Interface: "eth0"})
	if err != nil {
		t.Fatalf("NewTcpdumpStream: %v", err)
	}
	got, termErr := drainSource(t, context.Background(), ts)
	if len(got) != 0 {
		t.Fatalf("expected no packets, got %d", len(got))
	}
	if termErr == nil || !strings.Contains(termErr.Error(), "tcpdump: exit 2:") {
		t.Fatalf("terminal error = %v, want it to carry \"tcpdump: exit 2:\"", termErr)
	}
	if !strings.Contains(termErr.Error(), "permission to capture") {
		t.Fatalf("terminal error %v should include the stderr tail", termErr)
	}
}

func TestTcpdumpStreamMissingBinary(t *testing.T) {
	_, err := NewTcpdumpStream(TcpdumpConfig{
		Binary:    "synapse-no-such-tcpdump-binary",
		Interface: "eth0",
	})
	if err == nil || !strings.Contains(err.Error(), "not found on PATH") {
		t.Fatalf("err = %v, want a LookPath failure", err)
	}
}

func TestTcpdumpStreamNeedsInterface(t *testing.T) {
	if _, err := NewTcpdumpStream(TcpdumpConfig{Binary: fakecapBin}); err == nil {
		t.Fatal("expected an error when interface is empty")
	}
}

func TestTcpdumpStreamKilledOnContextCancel(t *testing.T) {
	t.Setenv("FAKECAP_SLEEP_MS", "60000") // would hang for a minute if not killed

	ts, err := NewTcpdumpStream(TcpdumpConfig{Binary: fakecapBin, Interface: "lo"})
	if err != nil {
		t.Fatalf("NewTcpdumpStream: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pkts, errc := ts.Packets(ctx)

	// Give the child a moment to start, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		for range pkts { //nolint:revive // drain
		}
		<-errc
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Packets did not return promptly after ctx cancel — the child was not killed")
	}
}
