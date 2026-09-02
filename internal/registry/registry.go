// Package registry is the model registry with lineage (PROJECT.md §15, §19.12).
// It records one Entry per registered model bundle — the §11 descriptor plus
// registry bookkeeping (status, timestamps, artifact size, on-disk location) —
// and tracks the derived-from lineage so the UI can draw the global → location →
// fine-tune tree.
//
// It is not an activation mechanism. Registering a bundle here makes it known and
// inspectable; turning it on is a separate explicit step (inference.Runtime plus
// the /api/v1/models/{id}/activate route). SetStatus records the outcome of that
// step but never runs a model itself (PROJECT.md §28.10).
//
// Persistence is a single JSON file, registry.json, under the model directory,
// rewritten atomically (temp file + rename). It is bounded by the number of
// bundles on disk; a database-backed registry is a separate tracked issue.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/model"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// FileName is the registry's basename, under the configured model directory.
const FileName = "registry.json"

const fileVersion = 1

// Status is where a registered model sits in its lifecycle. It is registry
// bookkeeping, not a live-runtime fact: a model is only actually scoring flows
// when inference.Runtime holds it.
type Status string

// Model lifecycle states.
const (
	// StatusRegistered — known and validated, not activated.
	StatusRegistered Status = "registered"
	// StatusActive — the operator activated this model; it is the intended
	// primary. At most one entry is Active at a time.
	StatusActive Status = "active"
	// StatusDeactivated — was Active, then explicitly turned off.
	StatusDeactivated Status = "deactivated"
)

// validStatus reports whether s is one of the three lifecycle states.
func validStatus(s Status) bool {
	switch s {
	case StatusRegistered, StatusActive, StatusDeactivated:
		return true
	default:
		return false
	}
}

// Ensemble roles a registered model can occupy. They mirror inference.Role; the
// registry keeps its own copies so it takes no dependency on internal/inference.
const (
	rolePrimary = "primary"
	roleAnomaly = "anomaly"
)

// roleForFamily maps a model family to the role it occupies when activated: the
// flow-anomaly-v1 autoencoder is the anomaly role, everything else is primary
// (ADR 0037).
func roleForFamily(family string) string {
	if family == schema.FamilyAnomalyV1 {
		return roleAnomaly
	}
	return rolePrimary
}

// entryRole is e.Role with the empty-value default applied: a registry.json
// written before the Role field existed has no role, and those entries are all
// primaries.
func entryRole(e *Entry) string {
	if e.Role == "" {
		return rolePrimary
	}
	return e.Role
}

// Entry is one registered model: its frozen §11 metadata plus registry
// bookkeeping. Metrics is the bundle's metrics.json carried through verbatim.
type Entry struct {
	ModelID            string              `json:"model_id"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Family             string              `json:"family"`
	FeatureSchema      string              `json:"feature_schema"`
	InputSize          int                 `json:"input_size"`
	OutputSchema       string              `json:"output_schema"`
	OutputSize         int                 `json:"output_size"`
	Architecture       schema.Architecture `json:"architecture"`
	TrainingDatasetIDs []string            `json:"training_dataset_ids"`
	Metrics            json.RawMessage     `json:"metrics,omitempty"`
	ParameterCount     int64               `json:"parameter_count"`
	ArtifactBytes      int64               `json:"artifact_bytes"`
	ContentHash        string              `json:"content_hash"`
	CreatedAt          string              `json:"created_at"`
	TrainerVersion     string              `json:"trainer_version"`
	DerivedFrom        string              `json:"derived_from,omitempty"`
	// Role is the ensemble role this model occupies when activated, mirroring
	// inference.Role: "primary" (the default, and what an absent value means on
	// a registry.json written before this field existed) or "anomaly" for the
	// flow-anomaly-v1 autoencoder family. At most one entry is Active per role
	// (ADR 0037).
	Role         string `json:"role,omitempty"`
	Status       Status `json:"status"`
	RegisteredAt string `json:"registered_at"`
	ActivatedAt  string `json:"activated_at,omitempty"`
	Dir          string `json:"dir"`
}

// TreeNode is one model in the lineage forest returned by Tree: an Entry plus its
// registered children, recursively (PROJECT.md §15, §19.12).
type TreeNode struct {
	Entry    Entry      `json:"entry"`
	Children []TreeNode `json:"children"`
}

// Logf is a structured-log sink; cmd/synapsed passes log.Printf.
type Logf func(format string, args ...any)

// Registry is the in-memory model registry backed by registry.json. It is safe
// for concurrent use: the API reads it while startup registration writes it.
type Registry struct {
	mu    sync.RWMutex
	dir   string
	path  string
	logf  Logf
	order []string          // model IDs in registration order
	byID  map[string]*Entry // stored value is never mutated in place after insert

	// reconciled names the models Open demoted from active to deactivated
	// because activation must not survive a restart. It is set once during
	// load and never changes, so the daemon can audit the demotion it did not
	// ask for (PROJECT.md §21, §28.10).
	reconciled []string
}

// Open returns a Registry backed by dir/registry.json, loading any existing
// file. A missing file starts empty; a corrupt or unreadable file is logged and
// also starts empty rather than failing the daemon — the bundles on disk are the
// source of truth and startup re-registers them (PROJECT.md §21 keeps this
// non-fatal so a bad file cannot wedge the daemon).
func Open(dir string, logf Logf) *Registry {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r := &Registry{
		dir:  dir,
		path: filepath.Join(dir, FileName),
		logf: logf,
		byID: map[string]*Entry{},
	}
	r.load()
	return r
}

func (r *Registry) load() {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.logf("registry: cannot read %q: %v — starting empty", r.path, err)
		}
		return
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		r.logf("registry: %q is corrupt (%v) — starting empty", r.path, err)
		return
	}
	for i := range f.Entries {
		e := f.Entries[i]
		if e.ModelID == "" {
			continue
		}
		if !validStatus(e.Status) {
			e.Status = StatusRegistered
		}
		// Activation does not survive a restart: inference.Runtime starts with
		// only the heuristic and nothing auto-loads a trained model (PROJECT.md
		// §28.10). Reconcile a persisted "active" to "deactivated" so the status
		// always reflects the running Runtime; ActivatedAt is kept so the UI can
		// still offer "re-activate the last active model".
		if e.Status == StatusActive {
			e.Status = StatusDeactivated
			r.reconciled = append(r.reconciled, e.ModelID)
		}
		cp := e
		r.byID[e.ModelID] = &cp
		r.order = append(r.order, e.ModelID)
	}
	r.logf("registry: loaded %d model(s) from %q", len(r.order), r.path)
	if len(r.reconciled) > 0 {
		r.logf("registry: %d model(s) were active before shutdown — marked deactivated; re-activate explicitly to make one live", len(r.reconciled))
		if err := r.persistLocked(); err != nil {
			r.logf("registry: could not persist startup reconciliation: %v", err)
		}
	}
}

type fileFormat struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Register validates b and records it. It returns an error when the bundle fails
// the activation gate, or when its content hash is already registered under a
// different model_id, or when its model_id is already registered with a
// different content hash. Re-registering the identical (id, hash) pair is a
// no-op that refreshes the on-disk location and metrics and returns the existing
// entry — so a daemon restart's startup sweep is idempotent.
func (r *Registry) Register(b *model.Bundle) (Entry, error) {
	if b == nil {
		return Entry{}, errors.New("registry: nil bundle")
	}
	if err := b.Validate(); err != nil {
		return Entry{}, fmt.Errorf("registry: bundle failed validation: %w", err)
	}

	m := b.Meta()
	if m.ModelID == "" {
		return Entry{}, errors.New("registry: bundle metadata has an empty model_id")
	}

	var artifactBytes int64
	if fi, err := os.Stat(b.ONNXPath()); err == nil {
		artifactBytes = fi.Size()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, id := range r.order {
		if e := r.byID[id]; e.ContentHash == b.Hash() && e.ModelID != m.ModelID {
			return Entry{}, fmt.Errorf("registry: content hash %s is already registered as model %q", b.Hash(), e.ModelID)
		}
	}

	if existing, ok := r.byID[m.ModelID]; ok {
		if existing.ContentHash != b.Hash() {
			return Entry{}, fmt.Errorf("registry: model %q is already registered with a different content hash (have %s, got %s)", m.ModelID, existing.ContentHash, b.Hash())
		}
		upd := *existing
		upd.Dir = b.Dir()
		upd.Metrics = cloneRaw(b.Metrics())
		upd.ArtifactBytes = artifactBytes
		upd.DerivedFrom = m.DerivedFrom
		upd.Role = roleForFamily(m.Family)
		r.byID[m.ModelID] = &upd
		if err := r.persistLocked(); err != nil {
			return Entry{}, err
		}
		return upd, nil
	}

	e := Entry{
		ModelID:            m.ModelID,
		Name:               m.Name,
		Version:            m.Version,
		Family:             m.Family,
		FeatureSchema:      m.FeatureSchema,
		InputSize:          m.InputSize,
		OutputSchema:       m.OutputSchema,
		OutputSize:         m.OutputSize,
		Architecture:       m.Architecture,
		TrainingDatasetIDs: m.TrainingDatasetIDs,
		Metrics:            cloneRaw(b.Metrics()),
		ParameterCount:     m.ParameterCount,
		ArtifactBytes:      artifactBytes,
		ContentHash:        b.Hash(),
		CreatedAt:          m.CreatedAt,
		TrainerVersion:     m.TrainerVersion,
		DerivedFrom:        m.DerivedFrom,
		Role:               roleForFamily(m.Family),
		Status:             StatusRegistered,
		RegisteredAt:       time.Now().UTC().Format(time.RFC3339),
		Dir:                b.Dir(),
	}
	r.byID[e.ModelID] = &e
	r.order = append(r.order, e.ModelID)
	if err := r.persistLocked(); err != nil {
		// Roll back the in-memory insert so state matches disk.
		delete(r.byID, e.ModelID)
		r.order = r.order[:len(r.order)-1]
		return Entry{}, err
	}
	return e, nil
}

// SetStatus records a lifecycle transition. Moving to StatusActive stamps
// ActivatedAt and demotes any other Active entry *in the same role* to
// StatusDeactivated, so at most one entry is Active per role — a primary
// classifier and an anomaly model can be Active at the same time (ADR 0037). It
// does not touch inference.Runtime — the caller wires the live model (see the
// activate route and internal/modelrun).
func (r *Registry) SetStatus(id string, st Status) (Entry, error) {
	if !validStatus(st) {
		return Entry{}, fmt.Errorf("registry: invalid status %q", st)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, ok := r.byID[id]
	if !ok {
		return Entry{}, fmt.Errorf("registry: unknown model %q", id)
	}

	// Snapshot for rollback on a persist failure.
	prev := map[string]Entry{}
	set := func(e *Entry, s Status) {
		prev[e.ModelID] = *e
		cp := *e
		cp.Status = s
		if s == StatusActive {
			cp.ActivatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		r.byID[e.ModelID] = &cp
	}

	if st == StatusActive {
		want := entryRole(cur)
		for _, oid := range r.order {
			if oid == id {
				continue
			}
			if e := r.byID[oid]; e.Status == StatusActive && entryRole(e) == want {
				set(e, StatusDeactivated)
			}
		}
	}
	set(cur, st)

	if err := r.persistLocked(); err != nil {
		for oid, e := range prev {
			cp := e
			r.byID[oid] = &cp
		}
		return Entry{}, err
	}
	return *r.byID[id], nil
}

// Get returns the entry for id.
func (r *Registry) Get(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byID[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// List returns every entry, newest registration first.
func (r *Registry) List() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.order))
	for i := len(r.order) - 1; i >= 0; i-- {
		out = append(out, *r.byID[r.order[i]])
	}
	return out
}

// Active returns the entry currently Active in the primary role, if any. It is
// the classifier the read-side (drift baseline, flow explain) means by "the
// active model"; an Active anomaly model is reached via ActiveByRole.
func (r *Registry) Active() (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeByRoleLocked(rolePrimary)
}

// ActiveByRole returns the entry currently Active in the given role ("primary"
// or "anomaly"; an empty string means "primary"). At most one entry is Active
// per role.
func (r *Registry) ActiveByRole(role string) (Entry, bool) {
	if role == "" {
		role = rolePrimary
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeByRoleLocked(role)
}

func (r *Registry) activeByRoleLocked(role string) (Entry, bool) {
	for _, id := range r.order {
		if e := r.byID[id]; e.Status == StatusActive && entryRole(e) == role {
			return *e, true
		}
	}
	return Entry{}, false
}

// Reconciled returns the model IDs that Open demoted from active to deactivated
// while loading, because activation never survives a restart (PROJECT.md
// §28.10). The daemon audits these so the log records the state change: without
// it, the last line about such a model claims it is active when it is not.
// The result is empty for a registry that had no active entry on disk.
func (r *Registry) Reconciled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.reconciled...)
}

// Lineage returns the derived-from chain for id, root first, id last. A
// DerivedFrom that names an unregistered parent, or a cycle, terminates the walk
// at that point (the chain returned is still root-ward-first for whatever is
// registered).
func (r *Registry) Lineage(id string) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var chain []Entry
	seen := map[string]bool{}
	for cur := id; cur != ""; {
		e, ok := r.byID[cur]
		if !ok || seen[cur] {
			break
		}
		seen[cur] = true
		chain = append(chain, *e)
		cur = e.DerivedFrom
	}
	// Reverse to root-first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// Children returns the entries whose DerivedFrom is id, newest registration
// first.
func (r *Registry) Children(id string) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.childrenLocked(id)
}

func (r *Registry) childrenLocked(id string) []Entry {
	var out []Entry
	for i := len(r.order) - 1; i >= 0; i-- {
		if e := r.byID[r.order[i]]; e.DerivedFrom == id {
			out = append(out, *e)
		}
	}
	return out
}

// Tree returns the lineage forest: one TreeNode per root (an entry whose
// DerivedFrom is empty or names an unregistered model), each with its registered
// descendants attached. Roots and children are ordered newest registration
// first. A DerivedFrom cycle is broken so the walk always terminates.
func (r *Registry) Tree() []TreeNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var roots []TreeNode
	for i := len(r.order) - 1; i >= 0; i-- {
		e := r.byID[r.order[i]]
		if e.DerivedFrom == "" {
			roots = append(roots, r.buildNodeLocked(e.ModelID, map[string]bool{}))
			continue
		}
		if _, ok := r.byID[e.DerivedFrom]; !ok {
			roots = append(roots, r.buildNodeLocked(e.ModelID, map[string]bool{}))
		}
	}
	return roots
}

func (r *Registry) buildNodeLocked(id string, seen map[string]bool) TreeNode {
	node := TreeNode{Entry: *r.byID[id]}
	if seen[id] {
		return node
	}
	seen[id] = true
	for _, c := range r.childrenLocked(id) {
		if seen[c.ModelID] {
			continue
		}
		node.Children = append(node.Children, r.buildNodeLocked(c.ModelID, seen))
	}
	return node
}

// Path returns the registry file's path.
func (r *Registry) Path() string { return r.path }

// persistLocked writes registry.json atomically. The caller holds r.mu.
func (r *Registry) persistLocked() error {
	if err := os.MkdirAll(r.dir, 0o750); err != nil {
		return fmt.Errorf("registry: cannot create %q: %w", r.dir, err)
	}
	f := fileFormat{Version: fileVersion, Entries: make([]Entry, 0, len(r.order))}
	for _, id := range r.order {
		f.Entries = append(f.Entries, *r.byID[id])
	}
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(r.dir, FileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("registry: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("registry: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("registry: close temp: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("registry: rename: %w", err)
	}
	return nil
}

func cloneRaw(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), b...)
}
