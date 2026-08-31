package training

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
)

func quiet(string, ...any) {}

func epochDict(n int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"event":"epoch","status":"running","epoch":%d,"epochs":10,"train_loss":%.3f,"val_loss":%.3f,"val_accuracy":0.9,"lr":0.001,"elapsed_s":%d}`,
		n, 1.0/float64(n), 1.2/float64(n), n))
}

func doneDict() json.RawMessage {
	return json.RawMessage(`{"accuracy":0.95,"macro_f1":0.94,"macro_precision":0.93,"macro_recall":0.95,` +
		`"per_class":[{"class":"NORMAL","precision":0.9,"recall":0.9,"f1":0.9,"support":100}],` +
		`"confusion":[[10,0],[1,9]],"test":{"accuracy":0.93}}`)
}

func TestStartAppendFinish(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)

	run, err := st.Start(Meta{Name: "run-a", EpochsTotal: 10, TrainerVersion: "0.1.0", Recipe: json.RawMessage(`{"name":"r"}`)})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if run.Status != StatusRunning || run.Epoch != 0 || run.ID == "" {
		t.Fatalf("unexpected fresh run: %+v", run)
	}

	for i := 1; i <= 4; i++ {
		if err := st.AppendProgress(run.ID, epochDict(i)); err != nil {
			t.Fatalf("AppendProgress %d: %v", i, err)
		}
	}
	got, ok := st.Get(run.ID)
	if !ok {
		t.Fatal("Get after append: not found")
	}
	if got.Epoch != 4 {
		t.Fatalf("Epoch = %d, want 4", got.Epoch)
	}
	if len(got.History) != 4 {
		t.Fatalf("history length = %d, want 4", len(got.History))
	}
	if got.UpdatedAt < got.StartedAt {
		t.Fatalf("UpdatedAt %q is before StartedAt %q", got.UpdatedAt, got.StartedAt)
	}

	if err := st.Finish(run.ID, doneDict()); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	got, _ = st.Get(run.ID)
	if got.Status != StatusCompleted {
		t.Fatalf("status = %q, want completed", got.Status)
	}
	if len(got.Final) == 0 {
		t.Fatal("Final not populated")
	}
	var final map[string]any
	if err := json.Unmarshal(got.Final, &final); err != nil {
		t.Fatalf("Final is not valid JSON: %v", err)
	}
	if final["accuracy"].(float64) != 0.95 {
		t.Fatalf("final accuracy = %v", final["accuracy"])
	}
	if got.FinishedAt == "" {
		t.Fatal("FinishedAt not set")
	}

	// A finished run takes no more updates.
	if err := st.AppendProgress(run.ID, epochDict(5)); err != ErrClosed {
		t.Fatalf("AppendProgress after finish: err = %v, want ErrClosed", err)
	}
	if err := st.Finish(run.ID, doneDict()); err != ErrClosed {
		t.Fatalf("Finish twice: err = %v, want ErrClosed", err)
	}
}

func TestHistoryCap(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)
	run, err := st.Start(Meta{Name: "cap", EpochsTotal: HistoryCap + 50})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 1; i <= HistoryCap+25; i++ {
		if err := st.AppendProgress(run.ID, epochDict(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got, _ := st.Get(run.ID)
	if len(got.History) != HistoryCap {
		t.Fatalf("history length = %d, want %d (capped)", len(got.History), HistoryCap)
	}
	if got.Epoch != HistoryCap+25 {
		t.Fatalf("Epoch = %d, want %d", got.Epoch, HistoryCap+25)
	}
	// Oldest dropped: the first retained entry should be epoch 26.
	var first map[string]any
	if err := json.Unmarshal(got.History[0], &first); err != nil {
		t.Fatalf("history[0]: %v", err)
	}
	if int(first["epoch"].(float64)) != 26 {
		t.Fatalf("history[0] epoch = %v, want 26 (oldest dropped first)", first["epoch"])
	}
}

func TestStaleTransition(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)
	run, err := st.Start(Meta{Name: "stale", EpochsTotal: 10})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if got, _ := st.Get(run.ID); got.Status != StatusRunning {
		t.Fatalf("fresh run status = %q, want running", got.Status)
	}

	// Jump the clock past the stale threshold.
	st.now = func() time.Time { return time.Now().Add(StaleAfter + time.Minute) }
	if got, _ := st.Get(run.ID); got.Status != StatusStale {
		t.Fatalf("after %v idle, status = %q, want stale", StaleAfter, got.Status)
	}
	for _, r := range st.List() {
		if r.ID == run.ID && r.Status != StatusStale {
			t.Fatalf("List: stale run status = %q", r.Status)
		}
	}

	// Stale is a read-time view only — the file on disk still says running.
	raw, err := os.ReadFile(filepath.Join(dir, run.ID+".json"))
	if err != nil {
		t.Fatalf("read run file: %v", err)
	}
	if !strings.Contains(string(raw), `"status": "running"`) {
		t.Fatalf("persisted status should still be running, file:\n%s", raw)
	}

	// A later progress update clears the stale view.
	if err := st.AppendProgress(run.ID, epochDict(1)); err != nil {
		t.Fatalf("AppendProgress: %v", err)
	}
	if got, _ := st.Get(run.ID); got.Status != StatusRunning {
		t.Fatalf("after new progress, status = %q, want running", got.Status)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)

	a, _ := st.Start(Meta{Name: "alpha", EpochsTotal: 5})
	time.Sleep(1100 * time.Millisecond) // distinct RFC3339 second so ordering is deterministic
	b, _ := st.Start(Meta{Name: "beta", EpochsTotal: 5})
	_ = st.AppendProgress(a.ID, epochDict(1))
	_ = st.AppendProgress(a.ID, epochDict(2))
	_ = st.Finish(a.ID, doneDict())
	_ = st.AppendProgress(b.ID, epochDict(1))

	// Reopen from the same directory.
	st2 := Open(dir, nil, quiet)
	list := st2.List()
	if len(list) != 2 {
		t.Fatalf("reloaded %d runs, want 2", len(list))
	}
	if list[0].ID != b.ID || list[1].ID != a.ID {
		t.Fatalf("List not newest-first: %s, %s", list[0].ID, list[1].ID)
	}
	ra, ok := st2.Get(a.ID)
	if !ok {
		t.Fatal("alpha not reloaded")
	}
	if ra.Status != StatusCompleted || len(ra.History) != 2 || len(ra.Final) == 0 {
		t.Fatalf("alpha reloaded wrong: status=%q history=%d final=%d", ra.Status, len(ra.History), len(ra.Final))
	}
	rb, _ := st2.Get(b.ID)
	if rb.Status != StatusRunning || rb.Epoch != 1 {
		t.Fatalf("beta reloaded wrong: status=%q epoch=%d", rb.Status, rb.Epoch)
	}
}

func TestCorruptFileTolerated(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)
	good, _ := st.Start(Meta{Name: "good", EpochsTotal: 3})

	// Drop a garbage file and a valid-JSON-but-no-id file alongside the good one.
	if err := os.WriteFile(filepath.Join(dir, "garbage.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "noid.json"), []byte(`{"status":"running"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	st2 := Open(dir, nil, quiet)
	if len(st2.List()) != 1 {
		t.Fatalf("expected only the 1 good run, got %d", len(st2.List()))
	}
	if _, ok := st2.Get(good.ID); !ok {
		t.Fatal("good run should survive a corrupt sibling")
	}
}

func TestFail(t *testing.T) {
	dir := t.TempDir()
	st := Open(dir, nil, quiet)
	run, _ := st.Start(Meta{Name: "doomed", EpochsTotal: 10})
	_ = st.AppendProgress(run.ID, epochDict(1))

	if err := st.Fail(run.ID, "cuda oom"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	got, _ := st.Get(run.ID)
	if got.Status != StatusFailed || got.FailReason != "cuda oom" {
		t.Fatalf("after Fail: status=%q reason=%q", got.Status, got.FailReason)
	}
	if got.FinishedAt == "" {
		t.Fatal("FinishedAt not set on Fail")
	}
	if err := st.Fail(run.ID, "again"); err != ErrClosed {
		t.Fatalf("Fail twice: err = %v, want ErrClosed", err)
	}
}

func TestUnknownID(t *testing.T) {
	st := Open(t.TempDir(), nil, quiet)
	if err := st.AppendProgress("nope", epochDict(1)); err != ErrNotFound {
		t.Fatalf("AppendProgress unknown: %v", err)
	}
	if err := st.Finish("nope", doneDict()); err != ErrNotFound {
		t.Fatalf("Finish unknown: %v", err)
	}
	if err := st.Fail("nope", "x"); err != ErrNotFound {
		t.Fatalf("Fail unknown: %v", err)
	}
	if _, ok := st.Get("nope"); ok {
		t.Fatal("Get unknown returned ok")
	}
}

func TestInvalidInput(t *testing.T) {
	st := Open(t.TempDir(), nil, quiet)
	if _, err := st.Start(Meta{Name: "bad", EpochsTotal: -1}); err == nil {
		t.Fatal("negative epochs_total should be rejected")
	}
	run, _ := st.Start(Meta{Name: "ok", EpochsTotal: 1})
	if err := st.AppendProgress(run.ID, json.RawMessage("{not json")); err == nil {
		t.Fatal("invalid JSON progress should be rejected")
	}
}

func TestAuditWired(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	aud := audit.New(auditDir, quiet)
	st := Open(dir, aud, quiet)

	run, _ := st.Start(Meta{Name: "audited", EpochsTotal: 2})
	_ = st.Finish(run.ID, doneDict())
	run2, _ := st.Start(Meta{Name: "audited2", EpochsTotal: 2})
	_ = st.Fail(run2.ID, "boom")

	raw, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	log := string(raw)
	for _, want := range []string{
		audit.EventTrainingStarted, audit.EventTrainingCompleted, audit.EventTrainingFailed,
		`"subject_type":"training"`, run.ID, run2.ID,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("audit log missing %q\n%s", want, log)
		}
	}
}
