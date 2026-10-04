package workbench

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeaseCancelAndRestart(t *testing.T) {
	s, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.dir, "uploads", "capture.pcap"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	req := Request{Kind: "prepare", Task: "attack", CaptureID: "capture", Label: "normal"}
	j, e := s.Enqueue(req)
	if e != nil {
		t.Fatal(e)
	}
	claim, ok, e := s.Claim()
	if e != nil || !ok || claim.ID != j.ID || claim.Lease == "" {
		t.Fatal("claim", e)
	}
	if _, ok, _ = s.Claim(); ok {
		t.Fatal("concurrent work leased")
	}
	list, online := s.List()
	if !online || list[0].Lease != "" {
		t.Fatal("lease exposed or heartbeat missing")
	}
	if e = s.Update(j.ID, "wrong", "completed", "", "", "bad"); e == nil {
		t.Fatal("wrong lease accepted")
	}
	if e = s.Cancel(j.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Update(j.ID, claim.Lease, "completed", "", "", "late"); e == nil {
		t.Fatal("cancelled lease accepted")
	}
	j, e = s.Enqueue(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _, _ = s.Claim()
	reopened, e := Open(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.jobs[j.ID].Status != "failed" {
		t.Fatal("restart left a worker lease valid")
	}
}
func TestBoundsAndExpiry(t *testing.T) {
	s, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Enqueue(Request{Kind: "train", Task: "attack", Corpora: []string{"../../secret"}}); e == nil {
		t.Fatal("unknown corpus accepted")
	}
	if ValidID("../x") {
		t.Fatal("path traversal accepted")
	}
	s.jobs["stale"] = Job{ID: "stale", Status: "running", Lease: "lease", UpdatedAt: time.Now().Add(-3 * time.Minute)}
	list, _ := s.List()
	if list[0].Status != "failed" || list[0].Lease != "" {
		t.Fatal("expired lease retained")
	}
}
