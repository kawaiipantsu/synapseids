package audit_test

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

// events returns the Event field of each record, in the order Tail returned
// them, so a test can assert newest-first ordering compactly.
func events(recs []audit.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Event
	}
	return out
}

func TestTailRoundTripNewestFirst(t *testing.T) {
	dir := t.TempDir()
	l := audit.New(dir, nil)
	l.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "hash=sha256:abc")
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	l.Log(audit.EventModelDeactivated, audit.ActorLocal, "m-1", "restored heuristic")

	recs, err := l.Tail(0, audit.Filter{})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	want := []string{
		audit.EventModelDeactivated,
		audit.EventModelActivated,
		audit.EventModelRegistered,
	}
	if got := events(recs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Tail order = %v, want newest-first %v", got, want)
	}
	// Fields survive the round trip.
	if recs[0].Detail != "restored heuristic" || recs[0].Subject != "m-1" ||
		recs[0].ModelID != "m-1" || recs[0].SubjectType != audit.SubjectModel ||
		recs[0].Actor != audit.ActorLocal {
		t.Fatalf("newest record = %+v", recs[0])
	}
	if _, err := time.Parse(time.RFC3339, recs[0].TS); err != nil {
		t.Fatalf("ts %q not RFC3339: %v", recs[0].TS, err)
	}
}

// The package-level Tail is the same read against an explicit path.
func TestTailByPath(t *testing.T) {
	dir := t.TempDir()
	audit.New(dir, nil).Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "")

	recs, err := audit.Tail(filepath.Join(dir, audit.FileName), 10, audit.Filter{})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(recs) != 1 || recs[0].Event != audit.EventModelRegistered {
		t.Fatalf("got %+v", recs)
	}
}

func TestTailMissingFileIsEmptyNotError(t *testing.T) {
	recs, err := audit.Tail(filepath.Join(t.TempDir(), "nope.log"), 10, audit.Filter{})
	if err != nil {
		t.Fatalf("missing file must not be an error, got %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records from a missing file", len(recs))
	}

	// A nil Logger reads as empty too, so callers need no nil checks.
	var nilLogger *audit.Logger
	recs, err = nilLogger.Tail(10, audit.Filter{})
	if err != nil || len(recs) != 0 {
		t.Fatalf("nil Logger Tail = %v, %v", recs, err)
	}
}

func TestTailEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Tail(path, 10, audit.Filter{})
	if err != nil || len(recs) != 0 {
		t.Fatalf("empty file Tail = %v, %v", recs, err)
	}
}

func TestTailFilters(t *testing.T) {
	dir := t.TempDir()
	l := audit.New(dir, nil)
	l.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "")
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")
	l.Log(audit.EventModelRegistered, audit.ActorLocal, "m-2", "")
	l.LogSubject(audit.EventDatasetCreated, audit.ActorLocal, audit.SubjectDataset, "thugs/lab@v1", "")
	l.LogSubject(audit.EventTrainingStarted, audit.ActorLocal, audit.SubjectTraining, "run-7", "")

	for _, tc := range []struct {
		name   string
		filter audit.Filter
		want   int
	}{
		{"all", audit.Filter{}, 5},
		{"subject_type=model", audit.Filter{SubjectType: audit.SubjectModel}, 3},
		{"subject_type=dataset", audit.Filter{SubjectType: audit.SubjectDataset}, 1},
		{"subject_type=training", audit.Filter{SubjectType: audit.SubjectTraining}, 1},
		{"subject", audit.Filter{Subject: "m-1"}, 2},
		{"event", audit.Filter{Event: audit.EventModelRegistered}, 2},
		{"subject+event", audit.Filter{Subject: "m-1", Event: audit.EventModelActivated}, 1},
		{"no match", audit.Filter{Subject: "nope"}, 0},
		// An unknown subject type is not rejected — it simply matches
		// nothing today and will match issue #42's review lines once they
		// are written, with no change to this package.
		{"unknown subject_type", audit.Filter{SubjectType: "review"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := l.Tail(0, tc.filter)
			if err != nil {
				t.Fatalf("Tail: %v", err)
			}
			if len(recs) != tc.want {
				t.Fatalf("got %d records, want %d: %+v", len(recs), tc.want, events(recs))
			}
		})
	}
}

// A subject type this package has no constant for round-trips through the
// filter, which is what keeps the reader generic (issue #42's review lines).
func TestTailUnknownSubjectTypeIsFilterable(t *testing.T) {
	dir := t.TempDir()
	l := audit.New(dir, nil)
	l.LogSubject("ReviewLabelChanged", audit.ActorLocal, "review", "flow-42", "SCAN -> NORMAL")
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")

	recs, err := l.Tail(0, audit.Filter{SubjectType: "review"})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(recs) != 1 || recs[0].Subject != "flow-42" || recs[0].Event != "ReviewLabelChanged" {
		t.Fatalf("got %+v", recs)
	}
	if recs[0].ModelID != "" {
		t.Errorf("non-model subject set model_id = %q", recs[0].ModelID)
	}
}

func TestTailTimeRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)

	// Hand-write records with controlled timestamps: Log always stamps now.
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var buf strings.Builder
	for i := range 5 {
		rec := audit.Record{
			TS:          base.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
			Event:       audit.EventModelActivated,
			Actor:       audit.ActorLocal,
			SubjectType: audit.SubjectModel,
			Subject:     fmt.Sprintf("m-%d", i),
			ModelID:     fmt.Sprintf("m-%d", i),
		}
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		from time.Time
		to   time.Time
		want []string // subjects, newest first
	}{
		{"unbounded", time.Time{}, time.Time{}, []string{"m-4", "m-3", "m-2", "m-1", "m-0"}},
		{"from only", base.Add(3 * time.Hour), time.Time{}, []string{"m-4", "m-3"}},
		{"to only", time.Time{}, base.Add(1 * time.Hour), []string{"m-1", "m-0"}},
		{"both", base.Add(1 * time.Hour), base.Add(2 * time.Hour), []string{"m-2", "m-1"}},
		// Bounds are inclusive on both ends.
		{"single instant", base, base, []string{"m-0"}},
		{"empty window", base.Add(90 * time.Minute), base.Add(100 * time.Minute), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, err := audit.Tail(path, 0, audit.Filter{From: tc.from, To: tc.to})
			if err != nil {
				t.Fatalf("Tail: %v", err)
			}
			got := make([]string, len(recs))
			for i, r := range recs {
				got[i] = r.Subject
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A record whose ts is unparseable cannot satisfy a bounded window, but must
// still be visible in an unfiltered tail — a bad timestamp must not hide a line.
func TestTailUnparseableTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	line := `{"ts":"not-a-time","event":"ModelActivated","actor":"local","subject_type":"model","subject":"m-1","model_id":"m-1"}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	recs, err := audit.Tail(path, 0, audit.Filter{})
	if err != nil || len(recs) != 1 {
		t.Fatalf("unfiltered Tail = %v, %v", recs, err)
	}
	recs, err = audit.Tail(path, 0, audit.Filter{From: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("bad-ts record matched a bounded window: %+v", recs)
	}
}

// A crash mid-append leaves a torn line with no trailing newline. It must be
// skipped, and every complete line before it must still be readable.
func TestTailSkipsCorruptTrailingLine(t *testing.T) {
	dir := t.TempDir()
	l := audit.New(dir, nil)
	l.Log(audit.EventModelRegistered, audit.ActorLocal, "m-1", "")
	l.Log(audit.EventModelActivated, audit.ActorLocal, "m-1", "")

	path := filepath.Join(dir, audit.FileName)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":"2026-03-01T12:00:00Z","event":"ModelDeac`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	recs, err := audit.Tail(path, 0, audit.Filter{})
	if err != nil {
		t.Fatalf("torn trailing line must not be fatal: %v", err)
	}
	if got := events(recs); len(got) != 2 ||
		got[0] != audit.EventModelActivated || got[1] != audit.EventModelRegistered {
		t.Fatalf("got %v, want the two complete records newest-first", got)
	}
}

// Junk anywhere in the file — blank lines, non-JSON, JSON without an event — is
// skipped without hiding the real records around it.
func TestTailSkipsJunkLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	body := strings.Join([]string{
		`{"ts":"2026-03-01T12:00:00Z","event":"ModelRegistered","actor":"local","subject_type":"model","subject":"m-1","model_id":"m-1"}`,
		``,
		`this is not json at all`,
		`{"ts":"2026-03-01T12:00:01Z"}`, // valid JSON, no event
		`   `,
		`{"ts":"2026-03-01T12:00:02Z","event":"ModelActivated","actor":"local","subject_type":"model","subject":"m-1","model_id":"m-1"}`,
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	recs, err := audit.Tail(path, 0, audit.Filter{})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if got := events(recs); len(got) != 2 ||
		got[0] != audit.EventModelActivated || got[1] != audit.EventModelRegistered {
		t.Fatalf("got %v, want the two real records newest-first", got)
	}
}

func TestTailCapAndDefault(t *testing.T) {
	dir := t.TempDir()
	l := audit.New(dir, nil)
	// More than DefaultTail so the default is observable, and enough to see
	// an explicit small n bite.
	total := audit.DefaultTail + 25
	for i := range total {
		l.Log(audit.EventModelRegistered, audit.ActorLocal, fmt.Sprintf("m-%03d", i), "")
	}

	if recs, err := l.Tail(0, audit.Filter{}); err != nil || len(recs) != audit.DefaultTail {
		t.Fatalf("n=0 returned %d records (err %v), want DefaultTail=%d", len(recs), err, audit.DefaultTail)
	}
	if recs, err := l.Tail(-5, audit.Filter{}); err != nil || len(recs) != audit.DefaultTail {
		t.Fatalf("n<0 returned %d records (err %v), want DefaultTail", len(recs), err)
	}
	recs, err := l.Tail(7, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 7 {
		t.Fatalf("n=7 returned %d records", len(recs))
	}
	// n is honoured against the newest end of the log.
	if recs[0].Subject != fmt.Sprintf("m-%03d", total-1) {
		t.Fatalf("newest record is %q, want m-%03d", recs[0].Subject, total-1)
	}
	// An n above MaxTail is clamped, not honoured.
	if recs, err := l.Tail(audit.MaxTail+500, audit.Filter{}); err != nil || len(recs) != total {
		t.Fatalf("large n returned %d records (err %v), want all %d", len(recs), err, total)
	}
}

// The clamp is a real ceiling: with more than MaxTail records on disk, Tail
// never returns more than MaxTail.
func TestTailNeverExceedsMaxTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	var buf strings.Builder
	for i := range audit.MaxTail + 50 {
		fmt.Fprintf(&buf,
			`{"ts":"2026-03-01T12:00:00Z","event":"ModelRegistered","actor":"local","subject_type":"model","subject":"m-%d","model_id":"m-%d"}`+"\n",
			i, i)
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	recs, err := audit.Tail(path, audit.MaxTail*10, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != audit.MaxTail {
		t.Fatalf("got %d records, want the MaxTail cap of %d", len(recs), audit.MaxTail)
	}
}

// Records must be read correctly when the log is larger than one backwards
// chunk, i.e. when lines straddle chunk boundaries.
func TestTailAcrossChunkBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)

	// Pad Detail so the file comfortably exceeds the 64 KiB chunk size.
	pad := strings.Repeat("x", 512)
	const n = 400
	var buf strings.Builder
	for i := range n {
		rec := audit.Record{
			TS:          time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
			Event:       audit.EventModelRegistered,
			Actor:       audit.ActorLocal,
			SubjectType: audit.SubjectModel,
			Subject:     fmt.Sprintf("m-%04d", i),
			ModelID:     fmt.Sprintf("m-%04d", i),
			Detail:      pad,
		}
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	body := buf.String()
	if len(body) < 64<<10 {
		t.Fatalf("fixture is only %d bytes, too small to cross a chunk boundary", len(body))
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	recs, err := audit.Tail(path, audit.MaxTail, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != n {
		t.Fatalf("got %d records, want all %d", len(recs), n)
	}
	// Newest first, contiguous, no line lost or duplicated at a boundary.
	for i, r := range recs {
		want := fmt.Sprintf("m-%04d", n-1-i)
		if r.Subject != want {
			t.Fatalf("record %d = %q, want %q", i, r.Subject, want)
		}
		if r.Detail != pad {
			t.Fatalf("record %d detail truncated to %d bytes", i, len(r.Detail))
		}
	}
}

// The scan floor bounds the work regardless of file size: lines further back
// than MaxScanBytes are simply not returned.
func TestTailScanFloorBoundsTheRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// One old record, then more than MaxScanBytes of newer ones.
	old := `{"ts":"2026-03-01T12:00:00Z","event":"ModelRegistered","actor":"local","subject_type":"model","subject":"ancient","model_id":"ancient"}`
	if _, err := f.WriteString(old + "\n"); err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("y", 4096)
	written := 0
	for written < audit.MaxScanBytes+(1<<20) {
		line := fmt.Sprintf(
			`{"ts":"2026-03-01T13:00:00Z","event":"ModelActivated","actor":"local","subject_type":"model","subject":"recent","model_id":"recent","detail":"%s"}`+"\n",
			pad)
		n, err := f.WriteString(line)
		if err != nil {
			t.Fatal(err)
		}
		written += n
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Asking for the ancient record by subject finds nothing: it is outside
	// the scan window, and the scan stops rather than reading the whole file.
	recs, err := audit.Tail(path, audit.MaxTail, audit.Filter{Subject: "ancient"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("record older than MaxScanBytes was returned: %+v", recs)
	}
	// Recent records are still readable.
	recs, err = audit.Tail(path, 10, audit.Filter{Subject: "recent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 10 {
		t.Fatalf("got %d recent records, want 10", len(recs))
	}
}

// A file with no trailing newline at all (single torn line) yields nothing but
// must not error.
func TestTailSingleTornLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	if err := os.WriteFile(path, []byte(`{"ts":"2026-03-01T12:00:00Z","ev`), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Tail(path, 0, audit.Filter{})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %+v, want no records", recs)
	}
}

// A file whose only line has no trailing newline but is complete JSON is still
// a record: reaching offset 0 proves the line started at the file's start.
func TestTailFirstLineWithoutTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, audit.FileName)
	line := `{"ts":"2026-03-01T12:00:00Z","event":"ModelActivated","actor":"local","subject_type":"model","subject":"m-1","model_id":"m-1"}`
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Tail(path, 0, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Subject != "m-1" {
		t.Fatalf("got %+v", recs)
	}
}
