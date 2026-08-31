package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/packet"
)

// fakecapBin is the compiled testdata/fakecap stub, built once for the whole
// package test binary by TestMain. The tcpdump/ssh subprocess tests point their
// Binary / SSHBinary at it.
var fakecapBin string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "capture-fakecap")
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakecap tmpdir:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	bin := filepath.Join(dir, "fakecap")
	build := exec.Command("go", "build", "-o", bin, "../../testdata/fakecap")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build fakecap: %v\n%s", err, out)
		return 1
	}
	fakecapBin = bin
	return m.Run()
}

func absFixture(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(fixturePath(name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// drainSource collects every packet a Source emits plus its terminal error.
func drainSource(t *testing.T, ctx context.Context, src Source) ([]packet.Packet, error) { //nolint:revive // t first is the test convention here
	t.Helper()
	pkts, errc := src.Packets(ctx)
	var got []packet.Packet
	for p := range pkts {
		got = append(got, p)
	}
	return got, <-errc
}

func mustSameField(t *testing.T, name string, got, want []packet.Packet) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %d packets, want %d (contents differ)", name, len(got), len(want))
	}
	if len(want) == 0 {
		t.Fatalf("%s: no packets — fixture/plumbing broken", name)
	}
}
