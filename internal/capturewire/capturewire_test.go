package capturewire

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/config"
)

func TestMetaFilterLabel(t *testing.T) {
	if m := Meta(config.CaptureSource{Kind: "nic"}); m.Filter != "(all)" || m.Kind != "nic" {
		t.Fatalf("Meta empty filter = %+v", m)
	}
	if m := Meta(config.CaptureSource{Kind: "tcpdump", Filter: "tcp port 80"}); m.Filter != "tcp port 80" {
		t.Fatalf("Meta explicit filter = %+v", m)
	}
}

func TestBuildPCAPOverIPLoopback(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "poip.tok")
	if err := os.WriteFile(tok, []byte("token-abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := config.CaptureSource{
		Name: "hq", Kind: "pcap-over-ip", Addr: "127.0.0.1:4789", TokenFile: tok,
	}
	if err := config.ValidateCaptureSource(cs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	src, target, err := Build(cs, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = src.Close() }()
	if target != "127.0.0.1:4789" {
		t.Fatalf("target = %q", target)
	}
}

func TestBuildTcpdumpMissingBinary(t *testing.T) {
	cs := config.CaptureSource{
		Name: "span", Kind: "tcpdump", Interface: "lo", Binary: "synapse-no-such-binary-xyz",
	}
	if _, _, err := Build(cs, nil); err == nil {
		t.Fatal("expected an error for a missing tcpdump binary")
	}
}

func TestResolvePOIPToken(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "t")
	if err := os.WriteFile(tok, []byte("  file-token  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePOIPToken(config.CaptureSource{TokenFile: tok})
	if err != nil || got != "file-token" {
		t.Fatalf("from file = %q, %v", got, err)
	}

	t.Setenv("SYNAPSE_POIP_TOKEN", "env-token")
	got, err = ResolvePOIPToken(config.CaptureSource{})
	if err != nil || got != "env-token" {
		t.Fatalf("from env = %q, %v", got, err)
	}
}
