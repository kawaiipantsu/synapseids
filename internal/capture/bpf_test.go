package capture

import (
	"strconv"
	"strings"
	"testing"
)

// TestBPFBufferReport covers the open-time buffer message (issue #128): a plain
// line when the kernel honoured the request, and the sysctl remedy when it
// clamped it to net.bpf.maxbufsize.
func TestBPFBufferReport(t *testing.T) {
	t.Run("granted in full", func(t *testing.T) {
		line, clamped := bpfBufferReport("/dev/bpf0", 512*1024, 512*1024)
		if clamped {
			t.Fatal("clamped=true when granted == requested")
		}
		if !strings.Contains(line, "requested 524288") || !strings.Contains(line, "granted 524288") {
			t.Errorf("line missing the sizes: %q", line)
		}
		if strings.Contains(line, "sysctl") {
			t.Errorf("no remedy expected when nothing was clamped: %q", line)
		}
	})

	t.Run("clamped", func(t *testing.T) {
		req := 4 * 1024 * 1024
		line, clamped := bpfBufferReport("/dev/bpf7", req, 512*1024)
		if !clamped {
			t.Fatal("clamped=false when granted < requested")
		}
		for _, want := range []string{
			"/dev/bpf7", "requested 4194304", "granted 524288",
			"net.bpf.maxbufsize", "/etc/sysctl.conf",
			"sysctl net.bpf.maxbufsize=" + strconv.Itoa(req),
		} {
			if !strings.Contains(line, want) {
				t.Errorf("clamp advice missing %q in:\n%s", want, line)
			}
		}
	})

	t.Run("granted above requested is not a clamp", func(t *testing.T) {
		// The kernel can round up; that is not something to warn about.
		_, clamped := bpfBufferReport("/dev/bpf0", 100000, 131072)
		if clamped {
			t.Error("a kernel round-up must not read as a clamp")
		}
	})
}
