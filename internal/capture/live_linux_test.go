//go:build linux

package capture

import (
	"strings"
	"testing"
)

// TestNewLiveRejectsFreeBSDOnlyKnobs: LiveConfig carries fields that only mean
// something on a FreeBSD BPF device. On Linux, NewLive must refuse them with an
// explanation rather than silently ignore them — the same contract issue #128
// applies to BufferLen, alongside the pre-existing Device and Direction rules.
func TestNewLiveRejectsFreeBSDOnlyKnobs(t *testing.T) {
	cases := []struct {
		name string
		cfg  LiveConfig
		want string
	}{
		{"device path", LiveConfig{Interface: "lo", Device: "/dev/bpf4"}, "FreeBSD"},
		{"direction", LiveConfig{Interface: "lo", Direction: "in"}, "not supported on Linux"},
		{"buffer length", LiveConfig{Interface: "lo", BufferLen: 2 << 20}, "does not take this knob"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLive(tc.cfg)
			if err == nil {
				t.Fatalf("NewLive accepted a FreeBSD-only setting (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the refusal (want substring %q)", err, tc.want)
			}
		})
	}
}
