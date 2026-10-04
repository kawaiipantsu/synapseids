// Package workbench is a durable, bounded queue consumed by an external trainer.
// It stores declarative requests; the daemon never starts Python or shell commands.
package workbench

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$`)

// ValidID excludes traversal and prevents arbitrary filesystem selection.
func ValidID(s string) bool { return safeID.MatchString(s) }

// Corpus describes prepared numeric samples; paths and traffic identities stay local.
type Corpus struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Task        string         `json:"task"`
	Rows        int            `json:"rows"`
	Classes     map[string]int `json:"classes"`
	Groups      int            `json:"groups"`
	Source      string         `json:"source"`
	Limitations string         `json:"limitations"`
	Digest      string         `json:"digest"`
}

// Request is the bounded training recipe, or an explicit labeled PCAP preparation.
type Request struct {
	Kind              string   `json:"kind"`
	Name              string   `json:"name"`
	Task              string   `json:"task"`
	Corpora           []string `json:"corpora"`
	CaptureID         string   `json:"capture_id,omitempty"`
	Label             string   `json:"label,omitempty"`
	Epochs            int      `json:"epochs"`
	Width             int      `json:"width"`
	MaxRows           int      `json:"max_rows"`
	FalsePositiveCost float64  `json:"false_positive_cost"`
	MissedAttackCost  float64  `json:"missed_attack_cost"`
}

// Job tracks the lease and final candidate. Lease is only returned to a claimant.
type Job struct {
	ID        string    `json:"id"`
	Request   Request   `json:"request"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	RunID     string    `json:"run_id,omitempty"`
	ModelID   string    `json:"model_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Lease     string    `json:"lease,omitempty"`
}

// Store owns queue transitions and atomically persists each job.
type Store struct {
	mu        sync.Mutex
	dir       string
	jobs      map[string]Job
	heartbeat time.Time
}

// Open reloads the bounded queue and invalidates leases from an earlier daemon.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, jobs: map[string]Job{}}
	for _, d := range []string{"jobs", "corpora", "uploads"} {
		if e := os.MkdirAll(filepath.Join(dir, d), 0700); e != nil {
			return nil, e
		}
	}
	paths, e := filepath.Glob(filepath.Join(dir, "jobs", "*.json"))
	if e != nil {
		return nil, e
	}
	if len(paths) > 200 {
		return nil, errors.New("too many workbench job files")
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		var j Job
		if json.Unmarshal(b, &j) != nil || !ValidID(j.ID) {
			return nil, errors.New("invalid workbench job file")
		}
		if j.Status == "running" {
			j.Status = "failed"
			j.Message = "Daemon restarted during the worker lease; submit a new job."
			j.Lease = ""
			if e = s.persist(j); e != nil {
				return nil, e
			}
		}
		s.jobs[j.ID] = j
	}
	return s, nil
}

// Dir returns the worker shared-data root.
func (s *Store) Dir() string { return s.dir }

// Corpora lists bounded, prepared corpus manifests.
func (s *Store) Corpora() []Corpus {
	out := []Corpus{}
	paths, _ := filepath.Glob(filepath.Join(s.dir, "corpora", "*.json"))
	if len(paths) > 128 {
		paths = paths[:128]
	}
	for _, p := range paths {
		info, e := os.Stat(p)
		if e != nil || info.Size() > 65536 {
			continue
		}
		b, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		var c Corpus
		if json.Unmarshal(b, &c) != nil || !ValidID(c.ID) || c.ID+".json" != filepath.Base(p) || c.Rows <= 0 || len(c.Classes) > 32 {
			continue
		}
		if _, e = os.Stat(filepath.Join(s.dir, "corpora", c.ID+".jsonl")); e != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}
func token() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

// Enqueue validates every executable choice before persistence.
func (s *Store) Enqueue(r Request) (Job, error) {
	if r.Kind != "train" && r.Kind != "prepare" {
		return Job{}, errors.New("kind must be train or prepare")
	}
	if r.Task != "attack" && r.Task != "application" {
		return Job{}, errors.New("task must be attack or application")
	}
	if len(r.Name) > 100 {
		return Job{}, errors.New("name exceeds 100 characters")
	}
	if r.Epochs == 0 {
		r.Epochs = 30
	}
	if r.Width == 0 {
		r.Width = 128
	}
	if r.MaxRows == 0 {
		r.MaxRows = 50000
	}
	if r.FalsePositiveCost == 0 {
		r.FalsePositiveCost = 2
	}
	if r.MissedAttackCost == 0 {
		r.MissedAttackCost = 2
	}
	if r.Epochs < 1 || r.Epochs > 100 || (r.Width != 64 && r.Width != 128 && r.Width != 256) || r.MaxRows < 100 || r.MaxRows > 100000 || r.FalsePositiveCost < .25 || r.FalsePositiveCost > 10 || r.MissedAttackCost < .25 || r.MissedAttackCost > 10 {
		return Job{}, errors.New("training parameters exceed supported limits")
	}
	if r.Kind == "train" {
		if len(r.Corpora) == 0 || len(r.Corpora) > 16 {
			return Job{}, errors.New("select 1–16 labeled corpora")
		}
		known := map[string]Corpus{}
		for _, c := range s.Corpora() {
			known[c.ID] = c
		}
		seen := map[string]bool{}
		for _, id := range r.Corpora {
			c, ok := known[id]
			if !ok || c.Task != r.Task || seen[id] {
				return Job{}, errors.New("unknown, duplicate or incompatible corpus")
			}
			seen[id] = true
		}
	} else {
		if !ValidID(r.CaptureID) || !ValidID(r.Label) {
			return Job{}, errors.New("invalid capture or label")
		}
		if _, e := os.Stat(filepath.Join(s.dir, "uploads", r.CaptureID+".pcap")); e != nil {
			return Job{}, errors.New("capture not uploaded")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, j := range s.jobs {
		if j.Status == "queued" || j.Status == "running" {
			active++
		}
	}
	if active >= 4 {
		return Job{}, errors.New("queue full (4 pending jobs)")
	}
	if len(s.jobs) >= 200 {
		var oldest Job
		for _, j := range s.jobs {
			if j.Status != "queued" && j.Status != "running" && (oldest.ID == "" || j.UpdatedAt.Before(oldest.UpdatedAt)) {
				oldest = j
			}
		}
		if oldest.ID == "" {
			return Job{}, errors.New("job history full")
		}
		if e := os.Remove(filepath.Join(s.dir, "jobs", oldest.ID+".json")); e != nil {
			return Job{}, e
		}
		delete(s.jobs, oldest.ID)
	}
	j := Job{ID: token(), Request: r, Status: "queued", UpdatedAt: time.Now().UTC()}
	if e := s.persist(j); e != nil {
		return Job{}, e
	}
	s.jobs[j.ID] = j
	return j, nil
}
func (s *Store) persist(j Job) error {
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Join(s.dir, "jobs"), ".job-*")
	if e != nil {
		return e
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, e = f.Write(b); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(s.dir, "jobs", j.ID+".json"))
}
func (s *Store) expireLocked() {
	now := time.Now()
	for id, j := range s.jobs {
		if j.Status == "running" && now.Sub(j.UpdatedAt) > 2*time.Minute {
			j.Status = "failed"
			j.Message = "Worker heartbeat expired; candidate was not activated."
			j.Lease = ""
			if s.persist(j) == nil {
				s.jobs[id] = j
			}
		}
	}
}

// List returns jobs without leases and current worker liveness.
func (s *Store) List() ([]Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	out := []Job{}
	for _, j := range s.jobs {
		j.Lease = ""
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, time.Since(s.heartbeat) < 45*time.Second
}

// Claim keeps a worker heartbeat and leases at most one job globally.
func (s *Store) Claim() (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeat = time.Now()
	s.expireLocked()
	var next Job
	for _, j := range s.jobs {
		if j.Status == "running" {
			return Job{}, false, nil
		}
		if j.Status == "queued" && (next.ID == "" || j.UpdatedAt.Before(next.UpdatedAt)) {
			next = j
		}
	}
	if next.ID == "" {
		return Job{}, false, nil
	}
	next.Status = "running"
	next.Lease = token()
	next.UpdatedAt = time.Now().UTC()
	if e := s.persist(next); e != nil {
		return Job{}, false, e
	}
	s.jobs[next.ID] = next
	return next, true, nil
}

// Update checks the lease on heartbeats and terminal updates, rejecting stale workers.
func (s *Store) Update(id, lease, status, runID, modelID, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Status != "running" || lease == "" || j.Lease != lease {
		return errors.New("job lease is no longer valid")
	}
	if status != "running" && status != "completed" && status != "failed" {
		return errors.New("invalid worker status")
	}
	if len(message) > 500 || len(runID) > 100 || len(modelID) > 100 {
		return errors.New("worker update too large")
	}
	j.Status = status
	j.UpdatedAt = time.Now().UTC()
	s.heartbeat = j.UpdatedAt
	j.RunID = runID
	j.ModelID = modelID
	j.Message = message
	if status != "running" {
		j.Lease = ""
	}
	if e := s.persist(j); e != nil {
		return e
	}
	s.jobs[id] = j
	return nil
}

// Cancel invalidates a queued or running job and its lease.
func (s *Store) Cancel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("unknown job")
	}
	if j.Status != "queued" && j.Status != "running" {
		return errors.New("job already finished")
	}
	j.Status = "cancelled"
	j.Lease = ""
	j.Message = "Cancelled by operator"
	j.UpdatedAt = time.Now().UTC()
	if e := s.persist(j); e != nil {
		return e
	}
	s.jobs[id] = j
	return nil
}
