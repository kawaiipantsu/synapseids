package audit

// This file is the audit-log read path. The log is append-only forever —
// nothing here (and no route above it) can rewrite or delete a line, because a
// mutable audit trail is worth nothing (PROJECT.md §21). Everything below opens
// the file read-only.
//
// Reads run newest-first: an operator asking "who activated what, when" wants
// the end of the log, not the beginning, and the file grows without bound. Tail
// therefore seeks to EOF and walks backwards in fixed chunks, decoding whole
// lines as it finds newline boundaries, and stops as soon as it has enough
// matching records. Two hard bounds keep it off the slow path (§22):
//
//   - the returned slice is capped at MaxTail records;
//   - the scan never reads further back than MaxScanBytes from EOF, so a
//     multi-gigabyte log costs the same as an 8 MiB one. Records older than
//     that window are simply not visible to the API; the file on disk is still
//     the complete record.
//
// Filter treats subject_type as an opaque string and never validates it against
// the SubjectType constants. That is deliberate: a new subject type added
// elsewhere (human label changes on reviews, issue #42) shows up in Tail and in
// the /api/v1/audit filters the moment it is written, with no change here.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

// Bounds on a Tail scan.
const (
	// DefaultTail is the record count Tail uses when asked for n <= 0.
	DefaultTail = 100
	// MaxTail caps the number of records Tail will return.
	MaxTail = 1000
	// MaxScanBytes caps how far back from EOF Tail reads. Lines earlier than
	// this window are not returned.
	MaxScanBytes = 8 << 20 // 8 MiB
	// chunkBytes is the backwards read granularity.
	chunkBytes = 64 << 10 // 64 KiB
)

// Filter narrows a Tail scan. A zero Filter matches every record. String fields
// are exact matches and an empty string means "any"; SubjectType is compared as
// an opaque string so subject types this package does not know about are
// filterable too.
type Filter struct {
	SubjectType string    // "" matches any subject_type
	Subject     string    // "" matches any subject
	Event       string    // "" matches any event
	From        time.Time // zero means unbounded; inclusive
	To          time.Time // zero means unbounded; inclusive
}

// Match reports whether rec satisfies f. A record whose ts does not parse as
// RFC3339 cannot satisfy a bounded time range, but matches an unbounded one.
func (f Filter) Match(rec Record) bool {
	if f.SubjectType != "" && rec.SubjectType != f.SubjectType {
		return false
	}
	if f.Subject != "" && rec.Subject != f.Subject {
		return false
	}
	if f.Event != "" && rec.Event != f.Event {
		return false
	}
	if f.From.IsZero() && f.To.IsZero() {
		return true
	}
	ts, err := time.Parse(time.RFC3339, rec.TS)
	if err != nil {
		return false
	}
	if !f.From.IsZero() && ts.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && ts.After(f.To) {
		return false
	}
	return true
}

// Tail returns up to n records matching filter, newest first (index 0 is the
// most recent line in the log). n <= 0 means DefaultTail and n is clamped to
// MaxTail.
//
// A missing log file is not an error: it means nothing auditable has happened
// yet, and Tail returns no records and no error. Lines that are not valid JSON
// records are skipped rather than fatal, which is what makes a crash mid-append
// harmless — the torn trailing line is simply not a record.
func (l *Logger) Tail(n int, filter Filter) ([]Record, error) {
	if l == nil {
		return nil, nil
	}
	return Tail(l.path, n, filter)
}

// Tail reads path as an audit log. See (*Logger).Tail; this is the same call
// against an explicit path, for callers that hold the models directory rather
// than the Logger.
func Tail(path string, n int, filter Filter) ([]Record, error) {
	if n <= 0 {
		n = DefaultTail
	}
	if n > MaxTail {
		n = MaxTail
	}

	f, err := os.Open(path) //nolint:gosec // operator-configured audit-log path
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}

	// floor is the earliest offset the scan may touch.
	var floor int64
	if size > MaxScanBytes {
		floor = size - MaxScanBytes
	}

	out := make([]Record, 0, min(n, 64))
	// carry holds the bytes of a line whose start lies in an earlier chunk.
	var carry []byte
	pos := size

	for pos > floor && len(out) < n {
		want := int64(chunkBytes)
		if pos-floor < want {
			want = pos - floor
		}
		pos -= want

		buf := make([]byte, want+int64(len(carry)))
		if _, err := f.ReadAt(buf[:want], pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		copy(buf[want:], carry)

		// Walk complete lines in buf from the back. Whatever precedes the
		// first newline in buf is an incomplete line: it continues into the
		// chunk we have not read yet.
		end := len(buf)
		for len(out) < n {
			i := bytes.LastIndexByte(buf[:end], '\n')
			if i < 0 {
				break
			}
			if rec, ok := decodeLine(buf[i+1 : end]); ok && filter.Match(rec) {
				out = append(out, rec)
			}
			end = i
		}
		carry = append(carry[:0:0], buf[:end]...)
	}

	// Reaching offset 0 means carry is the file's first line, not a fragment
	// truncated by the scan floor, so it is a real record.
	if pos == 0 && len(out) < n {
		if rec, ok := decodeLine(carry); ok && filter.Match(rec) {
			out = append(out, rec)
		}
	}
	return out, nil
}

// decodeLine parses one log line. It reports false for blank lines, for lines
// that are not JSON (a torn write, or anything else that ended up in the file)
// and for JSON objects carrying no event name, so callers can skip them.
func decodeLine(line []byte) (Record, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return Record{}, false
	}
	var rec Record
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
		return Record{}, false
	}
	if rec.Event == "" {
		return Record{}, false
	}
	return rec, true
}
