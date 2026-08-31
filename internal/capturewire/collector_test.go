package capturewire

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/capture/pcapoverip"
	"github.com/kawaiipantsu/synapseids/internal/config"
)

func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	_, certPEM, keyPEM, err := pcapoverip.SelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "collector.crt")
	keyPath = filepath.Join(dir, "collector.key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestBuildCollectorLoadsTLSAndToken(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSigned(t, dir)
	tokFile := filepath.Join(dir, "collector.token")
	if err := os.WriteFile(tokFile, []byte("  reverse-secret \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cc := config.Collector{
		Listen: "127.0.0.1:0", CertFile: cert, KeyFile: key,
		TokenFile: tokFile, Authorized: true, MaxSensors: 4,
	}
	if err := config.ValidateCollector(cc); err != nil {
		t.Fatalf("validate: %v", err)
	}
	col, err := BuildCollector(cc, nil, nil)
	if err != nil {
		t.Fatalf("BuildCollector: %v", err)
	}
	if col == nil {
		t.Fatal("nil collector")
	}
}

func TestBuildCollectorMissingCert(t *testing.T) {
	cc := config.Collector{Listen: "127.0.0.1:0", CertFile: "/no/such.crt", KeyFile: "/no/such.key", Authorized: true}
	if _, err := BuildCollector(cc, nil, nil); err == nil {
		t.Fatal("expected an error for unreadable TLS material")
	}
}

func TestBuildCollectorBadClientCA(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSigned(t, dir)
	bad := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cc := config.Collector{Listen: "127.0.0.1:0", CertFile: cert, KeyFile: key, ClientCAFile: bad, Authorized: true}
	if _, err := BuildCollector(cc, nil, nil); err == nil {
		t.Fatal("expected an error for a client_ca_file with no certificate")
	}
}

func TestResolveCollectorToken(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "t")
	if err := os.WriteFile(tok, []byte("  file-tok \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveCollectorToken(config.Collector{TokenFile: tok})
	if err != nil || got != "file-tok" {
		t.Fatalf("from file = %q, %v", got, err)
	}

	t.Setenv("SYNAPSE_COLLECTOR_TOKEN", "env-tok")
	got, err = ResolveCollectorToken(config.Collector{})
	if err != nil || got != "env-tok" {
		t.Fatalf("from env = %q, %v", got, err)
	}
}
