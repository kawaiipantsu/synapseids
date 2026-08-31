// Package audit writes an append-only record of operator actions that change
// durable state (PROJECT.md §21, §28.14): model registration/activation and
// dataset creation, derivation and deletion. It is deliberately tiny — one JSON
// object per line, appended to a single file — so it adds no dependency and
// never meaningfully blocks the API request that triggers it.
//
// Every line names a subject: a SubjectType ("model", "dataset") plus the
// subject's identifier. ModelID is kept alongside Subject for model lines so
// anything already reading the log by model_id keeps working.
//
// This file is the durable record. The matching ModelRegistered /
// ModelActivated / ModelDeactivated envelopes are also published on the live
// event bus (they are already members of the frozen event-envelope-v1 enum), but
// the bus drops events under backpressure by design, so the log is what an
// operator audits after the fact. The dataset events have no envelope: the
// event-envelope-v1 type enum is frozen and has no Dataset* member, so adding
// one is an event-envelope-v2 decision (ADR 0015). For datasets the audit log is
// therefore the only record.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event names for the model-lifecycle audit log.
const (
	EventModelRegistered  = "ModelRegistered"
	EventModelActivated   = "ModelActivated"
	EventModelDeactivated = "ModelDeactivated"
)

// Event names for the dataset-lifecycle audit log (PROJECT.md §14, §21).
const (
	EventDatasetCreated = "DatasetCreated"
	EventDatasetDerived = "DatasetDerived"
	EventDatasetDeleted = "DatasetDeleted"
)

// Subject types. Every record names what kind of thing it is about, so one log
// can carry model and dataset lifecycle without ambiguity.
const (
	SubjectModel   = "model"
	SubjectDataset = "dataset"
)

// ActorLocal is the only actor value for now: the daemon has no authentication
// yet, so every state change is attributed to the local operator. RBAC is
// tracked as issue #58.
const ActorLocal = "local"

// FileName is the audit log's basename; it lives next to the model bundles, in
// cfg.Models.Directory.
const FileName = "audit.log"

// Record is one audit-log line.
type Record struct {
	TS          string `json:"ts"`           // RFC3339 UTC
	Event       string `json:"event"`        // one of the Event* constants
	Actor       string `json:"actor"`        // ActorLocal for now
	SubjectType string `json:"subject_type"` // SubjectModel | SubjectDataset
	Subject     string `json:"subject"`      // the thing the action concerns
	ModelID     string `json:"model_id"`     // == Subject for SubjectModel, "" otherwise
	Detail      string `json:"detail"`       // free-form context, may be empty
}

// Logf is a structured-log sink; cmd/synapsed passes log.Printf. It receives a
// human-readable mirror of every audit line and any write error.
type Logf func(format string, args ...any)

// Logger appends audit records to a file. The zero value is unusable; call New.
// A nil *Logger is a valid no-op sink so callers need no nil checks.
type Logger struct {
	mu   sync.Mutex
	path string
	logf Logf
}

// New returns a Logger that appends to dir/audit.log, creating dir if needed. A
// failure to prepare the directory is not fatal: New logs it and returns a
// Logger that will retry the open on each Log call.
func New(dir string, logf Logf) *Logger {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logf("audit: cannot create %q: %v", dir, err)
	}
	return &Logger{path: filepath.Join(dir, FileName), logf: logf}
}

// Log appends one model-subject record. It is the original entry point and is
// unchanged for callers: the record it writes names SubjectModel and repeats
// modelID in both Subject and ModelID.
func (l *Logger) Log(event, actor, modelID, detail string) {
	l.LogSubject(event, actor, SubjectModel, modelID, detail)
}

// LogSubject appends one record with the current UTC timestamp and mirrors it to
// the structured log. A write error is logged, never returned: an audit-log
// failure must not fail the operator's request.
func (l *Logger) LogSubject(event, actor, subjectType, subject, detail string) {
	if l == nil {
		return
	}
	rec := Record{
		TS:          time.Now().UTC().Format(time.RFC3339),
		Event:       event,
		Actor:       actor,
		SubjectType: subjectType,
		Subject:     subject,
		Detail:      detail,
	}
	if subjectType == SubjectModel {
		rec.ModelID = subject
	}
	line, err := json.Marshal(rec)
	if err != nil { // cannot happen for these fields, but never panic
		l.logf("audit: marshal %s for %q: %v", event, subject, err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // operator-owned audit trail
	if err != nil {
		l.logf("audit: open %q: %v", l.path, err)
		return
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(append(line, '\n')); err != nil {
		l.logf("audit: append to %q: %v", l.path, err)
		return
	}
	l.logf("audit: %s actor=%s %s=%s %s", event, actor, subjectType, subject, detail)
}

// Path returns the audit log's absolute-or-relative path.
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}
