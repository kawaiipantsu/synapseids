// Package training is the run store behind the live training dashboard
// (PROJECT.md §19.8; issue #35). It is a mirror and a history store, never an
// orchestrator: the Go daemon does not and will not run Python (CLAUDE.md,
// PROJECT.md §5.4), so a training run is a separate process — synapse-trainer —
// that registers itself here over HTTP and then POSTs one progress dict per
// epoch. The daemon keeps the latest state plus a bounded history so the SPA can
// poll GET /api/v1/training/{id} and draw the loss curves, per-class metrics and
// confusion matrix (ADR 0019).
//
// Persistence is one JSON file per run under training.directory, written
// atomically (temp file + rename) and reloaded on start; a corrupt or
// unreadable file is logged and skipped, never fatal — the same posture
// registry.Open and dataset.Open take (PROJECT.md §21). A memory index fronts
// the files. The store is safe for concurrent use: the trainer POSTs progress
// while the SPA polls.
package training

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/audit"
)

// HistoryCap bounds the per-epoch progress slice a Run keeps, in memory and on
// disk. The newest HistoryCap updates are retained; older ones are dropped
// oldest-first. A longer run still reports the correct current epoch and latest
// metrics and its `final` block is unaffected — only the earliest tail of the
// loss curve is truncated. At ~400 bytes per epoch dict this caps a run file at
// well under a megabyte.
const HistoryCap = 1000

// StaleAfter is how long a run may go without a progress update before Get and
// List report it as StatusStale instead of StatusRunning. The trainer process
// has most likely died; a later progress POST (or a terminal update) clears the
// stale state on the next read. This is a read-time view, not a stored
// transition — nothing rewrites the file to say "stale".
const StaleAfter = 15 * time.Minute

// FileSuffix is the per-run file extension under the training directory.
const fileSuffix = ".json"

// Status is where a run sits in its lifecycle.
type Status string

// Run lifecycle states.
const (
	// StatusRunning — registered and receiving progress updates.
	StatusRunning Status = "running"
	// StatusCompleted — the trainer POSTed its terminal {"event":"done"} dict.
	StatusCompleted Status = "completed"
	// StatusFailed — the trainer POSTed /fail, or reported an error.
	StatusFailed Status = "failed"
	// StatusStale — a read-time view of a StatusRunning run with no update for
	// longer than StaleAfter. Never written to disk.
	StatusStale Status = "stale"
)

func validStatus(s Status) bool {
	switch s {
	case StatusRunning, StatusCompleted, StatusFailed:
		return true
	default:
		return false
	}
}

// Meta is what a trainer supplies when it registers a run
// (POST /api/v1/training).
type Meta struct {
	Name           string
	Recipe         json.RawMessage
	EpochsTotal    int
	TrainerVersion string
}

// Run is one training run as the daemon mirrors it. Recipe and Final are
// pass-through JSON: whatever the trainer sent is stored and served verbatim so
// a trainer can add fields §19.8 gains without a daemon change (ADR 0019).
// History holds the per-epoch progress dicts, oldest first, capped at
// HistoryCap.
type Run struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Status         Status            `json:"status"`
	Recipe         json.RawMessage   `json:"recipe,omitempty"`
	StartedAt      string            `json:"started_at"`
	UpdatedAt      string            `json:"updated_at"`
	FinishedAt     string            `json:"finished_at,omitempty"`
	TrainerVersion string            `json:"trainer_version,omitempty"`
	EpochsTotal    int               `json:"epochs_total"`
	Epoch          int               `json:"epoch"`
	History        []json.RawMessage `json:"history"`
	Final          json.RawMessage   `json:"final,omitempty"`
	FailReason     string            `json:"fail_reason,omitempty"`
}

// Terminal reports whether the run has finished (completed or failed). A stale
// run is not terminal — the trainer may still be alive.
func (r Run) Terminal() bool {
	return r.Status == StatusCompleted || r.Status == StatusFailed
}

// Errors returned by the store.
var (
	// ErrNotFound — no run with that id.
	ErrNotFound = errors.New("training: run not found")
	// ErrClosed — the run has already finished; it takes no more updates.
	ErrClosed = errors.New("training: run has already finished")
	// ErrInvalid — the registration metadata is unusable.
	ErrInvalid = errors.New("training: invalid run metadata")
)

// Logf is a structured-log sink; cmd/synapsed passes log.Printf.
type Logf func(format string, args ...any)

// Store is the in-memory index over the per-run JSON files under dir.
type Store struct {
	mu    sync.RWMutex
	dir   string
	aud   *audit.Logger
	logf  Logf
	now   func() time.Time
	order []string        // run IDs, oldest StartedAt first
	byID  map[string]*Run // values are replaced wholesale, never mutated in place
}

// Open returns a Store backed by dir, loading every *.json run file it can
// parse. A missing directory starts empty. aud may be nil (auditing becomes a
// no-op). A corrupt file is logged and skipped so a bad file cannot wedge the
// daemon (PROJECT.md §21).
func Open(dir string, aud *audit.Logger, logf Logf) *Store {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Store{
		dir:  dir,
		aud:  aud,
		logf: logf,
		now:  time.Now,
		byID: map[string]*Run{},
	}
	s.load()
	return s
}

func (s *Store) load() {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*"+fileSuffix))
	if err != nil {
		s.logf("training: cannot scan %q: %v — starting empty", s.dir, err)
		return
	}
	loaded := make([]*Run, 0, len(matches))
	for _, path := range matches {
		raw, err := os.ReadFile(path) //nolint:gosec // path from Glob of the configured dir
		if err != nil {
			s.logf("training: cannot read %q: %v — skipping", path, err)
			continue
		}
		var r Run
		if err := json.Unmarshal(raw, &r); err != nil {
			s.logf("training: %q is corrupt (%v) — skipping", path, err)
			continue
		}
		if r.ID == "" {
			s.logf("training: %q has no id — skipping", path)
			continue
		}
		if !validStatus(r.Status) {
			r.Status = StatusRunning
		}
		if r.History == nil {
			r.History = []json.RawMessage{}
		}
		cp := r
		loaded = append(loaded, &cp)
	}
	sort.Slice(loaded, func(i, j int) bool {
		if loaded[i].StartedAt != loaded[j].StartedAt {
			return loaded[i].StartedAt < loaded[j].StartedAt
		}
		return loaded[i].ID < loaded[j].ID
	})
	for _, r := range loaded {
		s.byID[r.ID] = r
		s.order = append(s.order, r.ID)
	}
	s.logf("training: loaded %d run(s) from %q", len(s.order), s.dir)
}

// Start registers a new run and returns it in StatusRunning.
func (s *Store) Start(meta Meta) (Run, error) {
	if meta.EpochsTotal < 0 {
		return Run{}, fmt.Errorf("%w: epochs_total must be >= 0", ErrInvalid)
	}
	name := meta.Name
	id := genID()
	if name == "" {
		name = id
	}
	ts := s.nowStr()
	r := Run{
		ID:             id,
		Name:           name,
		Status:         StatusRunning,
		Recipe:         cloneRaw(meta.Recipe),
		StartedAt:      ts,
		UpdatedAt:      ts,
		TrainerVersion: meta.TrainerVersion,
		EpochsTotal:    meta.EpochsTotal,
		History:        []json.RawMessage{},
	}

	s.mu.Lock()
	if err := s.persistLocked(&r); err != nil {
		s.mu.Unlock()
		return Run{}, err
	}
	cp := r
	s.byID[r.ID] = &cp
	s.order = append(s.order, r.ID)
	s.mu.Unlock()

	s.audit(audit.EventTrainingStarted, r.ID,
		fmt.Sprintf("name=%s epochs_total=%d trainer_version=%s", r.Name, r.EpochsTotal, r.TrainerVersion))
	return r, nil
}

// AppendProgress records one per-epoch progress dict. It bumps Epoch from the
// dict's "epoch" field when present, appends the dict verbatim to History
// (dropping the oldest once HistoryCap is reached) and stamps UpdatedAt.
// A terminal run is rejected with ErrClosed; an unknown id with ErrNotFound.
func (s *Store) AppendProgress(id string, dict json.RawMessage) error {
	if !json.Valid(dict) {
		return fmt.Errorf("%w: progress body is not valid JSON", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if cur.Terminal() {
		return ErrClosed
	}

	upd := *cur
	upd.History = append(append([]json.RawMessage{}, cur.History...), cloneRaw(dict))
	if len(upd.History) > HistoryCap {
		upd.History = upd.History[len(upd.History)-HistoryCap:]
	}
	if ep := peekInt(dict, "epoch"); ep > 0 {
		upd.Epoch = ep
	}
	upd.UpdatedAt = s.nowStr()

	if err := s.persistLocked(&upd); err != nil {
		return err
	}
	s.byID[id] = &upd
	return nil
}

// Finish marks a run completed and stores its final metrics block (the trainer's
// {"event":"done"} "metrics" object, passed through verbatim).
func (s *Store) Finish(id string, final json.RawMessage) error {
	r, err := s.terminate(id, StatusCompleted, "", final)
	if err != nil {
		return err
	}
	s.audit(audit.EventTrainingCompleted, id,
		fmt.Sprintf("name=%s epochs=%d/%d", r.Name, r.Epoch, r.EpochsTotal))
	return nil
}

// Fail marks a run failed with a reason.
func (s *Store) Fail(id, reason string) error {
	r, err := s.terminate(id, StatusFailed, reason, nil)
	if err != nil {
		return err
	}
	s.audit(audit.EventTrainingFailed, id,
		fmt.Sprintf("name=%s epochs=%d/%d reason=%s", r.Name, r.Epoch, r.EpochsTotal, reason))
	return nil
}

func (s *Store) terminate(id string, st Status, reason string, final json.RawMessage) (Run, error) {
	if final != nil && !json.Valid(final) {
		return Run{}, fmt.Errorf("%w: final body is not valid JSON", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.byID[id]
	if !ok {
		return Run{}, ErrNotFound
	}
	if cur.Terminal() {
		return Run{}, ErrClosed
	}

	upd := *cur
	upd.Status = st
	upd.FailReason = reason
	if final != nil {
		upd.Final = cloneRaw(final)
	}
	ts := s.nowStr()
	upd.UpdatedAt = ts
	upd.FinishedAt = ts

	if err := s.persistLocked(&upd); err != nil {
		return Run{}, err
	}
	s.byID[id] = &upd
	return upd, nil
}

// Get returns the run for id, with the stale view applied.
func (s *Store) Get(id string) (Run, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[id]
	if !ok {
		return Run{}, false
	}
	return s.staleize(*r), true
}

// List returns every run, newest StartedAt first, with the stale view applied.
func (s *Store) List() []Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Run, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		out = append(out, s.staleize(*s.byID[s.order[i]]))
	}
	return out
}

// Dir returns the store's directory.
func (s *Store) Dir() string { return s.dir }

// staleize returns r with Status flipped to StatusStale when it is running and
// its last update is older than StaleAfter.
func (s *Store) staleize(r Run) Run {
	if r.Status != StatusRunning {
		return r
	}
	t, err := time.Parse(time.RFC3339, r.UpdatedAt)
	if err != nil {
		return r
	}
	if s.now().Sub(t) > StaleAfter {
		r.Status = StatusStale
	}
	return r
}

func (s *Store) nowStr() string { return s.now().UTC().Format(time.RFC3339) }

func (s *Store) audit(event, id, detail string) {
	if s.aud == nil {
		return
	}
	s.aud.LogSubject(event, audit.ActorLocal, audit.SubjectTraining, id, detail)
}

// persistLocked writes one run file atomically (temp file + rename). The caller
// holds s.mu.
func (s *Store) persistLocked(r *Run) error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("training: cannot create %q: %w", s.dir, err)
	}
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("training: marshal %s: %w", r.ID, err)
	}
	tmp, err := os.CreateTemp(s.dir, r.ID+".*.tmp")
	if err != nil {
		return fmt.Errorf("training: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("training: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("training: close temp: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(s.dir, r.ID+fileSuffix)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("training: rename: %w", err)
	}
	return nil
}

// genID is a sortable, filesystem-safe, collision-resistant run id:
// "<UTC compact timestamp>-<8 hex random>".
func genID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func cloneRaw(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), b...)
}

// peekInt pulls one integer field out of a JSON object without a full decode,
// tolerating a float encoding ("epoch": 3.0). Returns 0 when absent or not a
// number.
func peekInt(raw json.RawMessage, key string) int {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	var f float64
	if err := json.Unmarshal(v, &f); err != nil {
		return 0
	}
	return int(f)
}
