package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
)

func TestLogAppendsJSONL(t *testing.T) {
	dir := t.TempDir()
	var logged int
	l := audit.New(dir, func(string, ...any) { logged++ })

	l.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "hash=sha256:abc")
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	l.Log(audit.EventModelDeactivated, audit.ActorLocal, "m-1", "restored heuristic")

	if logged != 3 {
		t.Fatalf("structured-log mirror fired %d times, want 3", logged)
	}

	f, err := os.Open(filepath.Join(dir, audit.FileName))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var recs []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("line is not JSON: %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if recs[0].Event != "ModelRegistered" || recs[0].ModelID != "m-1" || recs[0].Actor != "local" {
		t.Fatalf("record 0 = %+v", recs[0])
	}
	if _, err := time.Parse(time.RFC3339, recs[0].TS); err != nil {
		t.Fatalf("ts %q not RFC3339: %v", recs[0].TS, err)
	}
	if recs[2].Event != "ModelDeactivated" || !strings.Contains(recs[2].Detail, "heuristic") {
		t.Fatalf("record 2 = %+v", recs[2])
	}
}

func TestLogAppendsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	audit.New(dir, nil).Log(audit.EventModelRegistered, audit.ActorLocal, "a", "")
	audit.New(dir, nil).Log(audit.EventModelRegistered, audit.ActorLocal, "b", "")

	blob, err := os.ReadFile(filepath.Join(dir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(blob)), "\n"); n != 1 {
		t.Fatalf("want 2 lines (1 newline separator), got %d newlines:\n%s", n, blob)
	}
}

func TestNilLoggerIsNoOp(t *testing.T) {
	var l *audit.Logger
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m", "detail") // must not panic
	if l.Path() != "" {
		t.Fatalf("nil logger Path() = %q", l.Path())
	}
}
