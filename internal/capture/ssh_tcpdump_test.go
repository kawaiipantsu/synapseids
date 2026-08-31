package capture

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSSHArgsAssembly(t *testing.T) {
	s, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:      fakecapBin,
		Destination:    "sensor@10.0.0.9",
		Port:           2222,
		IdentityFile:   "/keys/id_ed25519",
		Interface:      "eth0",
		Filter:         "tcp port 80",
		ExtraSSHArgs:   []string{"-o", "ConnectTimeout=5"},
		KnownHostsMode: "accept-new",
		Authorized:     true,
	})
	if err != nil {
		t.Fatalf("NewSSHTcpdump: %v", err)
	}

	got := s.Argv()
	if got[0] != fakecapBin {
		t.Fatalf("argv[0] = %q, want %q", got[0], fakecapBin)
	}
	want := []string{
		"-p", "2222",
		"-i", "/keys/id_ed25519",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=5",
		"sensor@10.0.0.9",
		"tcpdump -U -w - -i eth0 -s 0 tcp port 80",
	}
	if !reflect.DeepEqual(got[1:], want) {
		t.Fatalf("ssh argv =\n  %v\nwant\n  %v", got[1:], want)
	}
	if s.RemoteCommand() != "tcpdump -U -w - -i eth0 -s 0 tcp port 80" {
		t.Fatalf("remote command = %q", s.RemoteCommand())
	}
}

func TestSSHArgsDefaultStrictHostKey(t *testing.T) {
	s, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:   fakecapBin,
		Destination: "host",
		Interface:   "any",
		Authorized:  true,
	})
	if err != nil {
		t.Fatalf("NewSSHTcpdump: %v", err)
	}
	joined := strings.Join(s.Argv(), " ")
	if !strings.Contains(joined, "-o BatchMode=yes") {
		t.Fatalf("argv must force BatchMode=yes: %s", joined)
	}
	if !strings.Contains(joined, "-o StrictHostKeyChecking=yes") {
		t.Fatalf("default known-hosts mode must be strict (=yes): %s", joined)
	}
}

func TestSSHRemoteCommandQuotesDangerousFilterTokens(t *testing.T) {
	s, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:   fakecapBin,
		Destination: "host",
		Interface:   "eth0",
		Filter:      "tcp port 80 ; rm -rf /",
		Authorized:  true,
	})
	if err != nil {
		t.Fatalf("NewSSHTcpdump: %v", err)
	}
	rc := s.RemoteCommand()
	// The ";" token must be single-quoted so the remote shell cannot run it.
	if !strings.Contains(rc, "';'") {
		t.Fatalf("remote command did not quote the ';' token: %q", rc)
	}
	if strings.Contains(rc, "-i eth0 -s 0 tcp port 80 ; rm") {
		t.Fatalf("remote command left an unquoted shell separator: %q", rc)
	}
}

func TestSSHUnauthorizedIsRejected(t *testing.T) {
	_, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:   fakecapBin,
		Destination: "sensor@10.0.0.9",
		Interface:   "eth0",
		Authorized:  false,
	})
	if err == nil || !strings.Contains(err.Error(), `"authorized": true`) {
		t.Fatalf("err = %v, want the §28.18 authorization gate", err)
	}
	if !strings.Contains(err.Error(), "sensor@10.0.0.9") {
		t.Fatalf("authorization error should name the destination: %v", err)
	}
}

func TestSSHBadKnownHostsMode(t *testing.T) {
	_, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:      fakecapBin,
		Destination:    "host",
		Interface:      "eth0",
		Authorized:     true,
		KnownHostsMode: "no",
	})
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Fatalf("err = %v, want a known_hosts validation error", err)
	}
}

// TestSSHExecPassesArgvToChild proves the assembled argv actually reaches the
// spawned process (fakecap echoes its argv to a file) and that a fixture piped
// back as the remote tcpdump's stdout decodes end to end.
func TestSSHExecPassesArgvToChild(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv.txt")
	t.Setenv("FAKECAP_ARGV_FILE", argvFile)
	t.Setenv("FAKECAP_PCAP", absFixture(t, "udp.pcap"))

	s, err := NewSSHTcpdump(SSHConfig{
		SSHBinary:    fakecapBin,
		Destination:  "sensor@host",
		Port:         22,
		Interface:    "eth1",
		Filter:       "udp",
		Authorized:   true,
		IdentityFile: "/k/id",
	})
	if err != nil {
		t.Fatalf("NewSSHTcpdump: %v", err)
	}

	got, termErr := drainSource(t, context.Background(), s)
	if termErr != nil {
		t.Fatalf("terminal error: %v", termErr)
	}
	mustSameField(t, "ssh(udp.pcap)", got, collectViaPCAPFile(t, "udp.pcap"))

	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv file: %v", err)
	}
	argv := string(raw)
	for _, want := range []string{
		"BatchMode=yes",
		"StrictHostKeyChecking=yes",
		"-p\n22",
		"-i\n/k/id",
		"sensor@host",
		"tcpdump -U -w - -i eth1 -s 0 udp",
	} {
		if !strings.Contains(argv, want) {
			t.Fatalf("child argv missing %q\nfull argv:\n%s", want, argv)
		}
	}
}
