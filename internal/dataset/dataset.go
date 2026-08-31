// Package dataset materialises stored flow classifications into first-class,
// versioned, immutable datasets (PROJECT.md §14, §19.10; issue #33).
//
// A dataset version is a directory. It holds exactly two files:
//
//	<datasets.directory>/<id>/<version>/dataset.csv    the rows the trainer reads
//	<datasets.directory>/<id>/<version>/manifest.json  every §14 metadata field
//
// The id may contain one "/" (PROJECT.md §14 writes ids like
// "thugs/lab-attacks-2026-08"), so an id maps to one or two path segments; the
// version is always the last segment. Nothing else lives in the tree, so the
// directory layout *is* the index: Open walks it and there is no second
// registry.json-style file that could drift from the manifests. This is the one
// deliberate difference from internal/registry, whose entries describe bundles
// that live elsewhere; see ADR 0015.
//
// dataset.csv is written for the Python trainer verbatim: a header of the 48
// flow-features-v1 column names in frozen schema order plus a trailing "label"
// column, then one row per flow, sorted by flow id. trainer/synapse_trainer's
// dataset.load_csv reads it with no adaptation, and because load_csv also
// accepts a directory containing dataset.csv, a version directory can be handed
// to the trainer as-is.
//
// A written version is never mutated. A change produces a new version that names
// its predecessor in parent_datasets. Delete is the single exception and it is
// audited by the caller.
//
// Honesty about labels: Phase 4 has no human review loop (issue #42), so a
// dataset built today is labelled by the daemon's own model predictions. That is
// recorded literally in labeling_source as "model_prediction:<model ids>" and
// nothing here can write "human_review".
package dataset

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// File names inside a version directory.
const (
	CSVFileName      = "dataset.csv"
	ManifestFileName = "manifest.json"
)

// LabelColumn is the trainer's required label column name; it is appended after
// the 48 frozen feature columns.
const LabelColumn = "label"

// Errors callers match with errors.Is to choose an HTTP status.
var (
	// ErrInvalid is a malformed spec: a bad id or version, a wrong schema pair,
	// an unknown class filter. Maps to 400.
	ErrInvalid = errors.New("dataset: invalid specification")
	// ErrExists is a duplicate (id, version). Maps to 409.
	ErrExists = errors.New("dataset: version already exists")
	// ErrNotFound is an unknown (id, version). Maps to 404.
	ErrNotFound = errors.New("dataset: not found")
	// ErrUnusable is a selection that produced nothing a trainer could learn
	// from: no rows, one class, or fewer rows than MinRows. Maps to 422.
	ErrUnusable = errors.New("dataset: selection is not usable for training")
)

// TimeRange is the span the selected flows cover, RFC3339 UTC, "" when empty.
type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Manifest is the §14 record of one dataset version. Every field §14 lists is
// present; the trailing block is bookkeeping this implementation adds so a
// dataset can be reproduced and audited.
type Manifest struct {
	ID               string         `json:"id"`
	Version          string         `json:"version"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Location         string         `json:"location"`
	Tags             []string       `json:"tags"`
	CreatedAt        string         `json:"created_at"`
	SourceCaptureIDs []string       `json:"source_capture_ids"`
	TimeRange        TimeRange      `json:"time_range"`
	FeatureSchema    string         `json:"feature_schema"`
	OutputSchema     string         `json:"output_schema"`
	FlowCount        int            `json:"flow_count"`
	LabelCounts      map[string]int `json:"label_counts"`
	LabelingSource   string         `json:"labeling_source"`
	ParentDatasets   []string       `json:"parent_datasets"`
	ContentHash      string         `json:"content_hash"`

	// Bookkeeping (additive to §14).
	Selection    Selection `json:"selection"`
	Warnings     []string  `json:"warnings,omitempty"`
	CSVFile      string    `json:"csv_file"`
	CSVBytes     int64     `json:"csv_bytes"`
	FeatureCount int       `json:"feature_count"`
	Columns      []string  `json:"columns"`
}

// Dataset is a Manifest plus where it lives on disk.
type Dataset struct {
	Manifest
	Dir string `json:"dir"`
}

// Ref is the "<id>@<version>" identifier used in parent_datasets and in the REST
// path (url-escaped).
func (m Manifest) Ref() string { return m.ID + "@" + m.Version }

// ParseRef splits an "<id>@<version>" reference. The id may itself contain "/"
// but never "@", so the last "@" separates the two.
func ParseRef(ref string) (id, version string, err error) {
	i := strings.LastIndex(ref, "@")
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("%w: reference %q must be \"<id>@<version>\"", ErrInvalid, ref)
	}
	return ref[:i], ref[i+1:], nil
}

// Spec is what an operator asks Create for: the §14 metadata plus the selection
// that picks the rows.
type Spec struct {
	ID               string    `json:"id"`
	Version          string    `json:"version"` // "" auto-assigns v1, or v<max+1>
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Location         string    `json:"location"`
	Tags             []string  `json:"tags"`
	SourceCaptureIDs []string  `json:"source_capture_ids"`
	Selection        Selection `json:"selection"`
}

// FlowSource is the read side of storage.Store a build needs: the recent
// classifications to select from and the flow record (with its 48 features)
// behind each one. *storage.Mem and any future storage.Store satisfy it.
type FlowSource interface {
	RecentClassifications(limit int) []storage.Classification
	Flow(id uint64) (storage.FlowRecord, bool)
}

// Logf is a structured-log sink; cmd/synapsed passes log.Printf.
type Logf func(format string, args ...any)

// Manager owns the on-disk dataset tree. It is safe for concurrent use: the API
// lists datasets while another request writes one.
type Manager struct {
	mu   sync.RWMutex
	dir  string
	src  FlowSource
	logf Logf
	byID map[string]*Dataset // keyed by Ref()

	// statsByHash caches Stats bundles keyed by a version's immutable content
	// hash (see stats.go). A version's CSV never changes, so a hit is always
	// valid for the life of the process.
	statsMu     sync.Mutex
	statsByHash map[string]*Stats
}

// Open returns a Manager over dir, scanning it for existing versions. src is the
// flow store Create reads from and may be nil in a read-only context (Create
// then fails cleanly). A missing directory is not an error — it is created on
// the first write. A version directory whose manifest.json is missing or corrupt
// is logged and skipped rather than failing the daemon, matching
// registry.Open's posture (PROJECT.md §21).
func Open(dir string, src FlowSource, logf Logf) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	m := &Manager{dir: dir, src: src, logf: logf, byID: map[string]*Dataset{}}
	m.scan()
	return m
}

// Dir returns the dataset root directory.
func (m *Manager) Dir() string { return m.dir }

// scan walks the tree and loads every manifest.json it can parse.
func (m *Manager) scan() {
	root, err := os.Stat(m.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			m.logf("dataset: cannot read %q: %v — starting empty", m.dir, err)
		}
		return
	}
	if !root.IsDir() {
		m.logf("dataset: %q is not a directory — starting empty", m.dir)
		return
	}

	skipped := 0
	// An id is one or two segments and the version is one more, so a version
	// directory is at depth 2 or 3 and its manifest.json at depth 3 or 4. Bound
	// the walk there so a stray deep tree cannot make startup crawl.
	err = filepath.WalkDir(m.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			m.logf("dataset: skipping %q: %v", path, err)
			return nil //nolint:nilerr // a bad subtree must not abort the scan
		}
		rel, rerr := filepath.Rel(m.dir, path)
		if rerr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = len(strings.Split(filepath.ToSlash(rel), "/"))
		}
		if d.IsDir() {
			// A version directory is the deepest thing that can hold a manifest;
			// nothing legitimate lives below it. Interrupted Create staging
			// directories start with "." and are never datasets.
			if depth >= 4 || (depth > 0 && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != ManifestFileName {
			return nil
		}
		ds, lerr := loadManifest(filepath.Dir(path))
		if lerr != nil {
			m.logf("dataset: ignoring %q: %v", path, lerr)
			skipped++
			return nil
		}
		m.byID[ds.Ref()] = ds
		return nil
	})
	if err != nil {
		m.logf("dataset: walk %q: %v", m.dir, err)
	}
	m.logf("dataset: loaded %d dataset version(s) from %q (%d skipped)", len(m.byID), m.dir, skipped)
}

// loadManifest reads and sanity-checks one version directory.
func loadManifest(dir string) (*Dataset, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFileName)) //nolint:gosec // operator-owned dataset tree
	if err != nil {
		return nil, err
	}
	var man Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return nil, fmt.Errorf("corrupt manifest: %w", err)
	}
	if man.ID == "" || man.Version == "" {
		return nil, errors.New("manifest has no id/version")
	}
	if err := ValidateID(man.ID); err != nil {
		return nil, err
	}
	if err := ValidateVersion(man.Version); err != nil {
		return nil, err
	}
	if man.LabelCounts == nil {
		man.LabelCounts = map[string]int{}
	}
	return &Dataset{Manifest: man, Dir: dir}, nil
}

// Get returns one dataset version.
func (m *Manager) Get(id, version string) (Dataset, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.byID[id+"@"+version]
	if !ok {
		return Dataset{}, false
	}
	return *d, true
}

// List returns every known version, newest created first; equal timestamps fall
// back to id then version so the order is total and stable.
func (m *Manager) List() []Dataset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Dataset, 0, len(m.byID))
	for _, d := range m.byID {
		out = append(out, *d)
	}
	sortDatasets(out)
	return out
}

// sortDatasets orders newest created first. created_at has one-second
// resolution, so two versions cut in the same second tie; the tiebreak is id
// ascending then version *descending*, which keeps Latest correct for the
// common case of v1 and v2 built moments apart.
func sortDatasets(out []Dataset) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return versionAfter(out[i].Version, out[j].Version)
	})
}

// versionAfter reports whether a is the later version of b: numerically when
// both are "v<n>", lexicographically otherwise.
func versionAfter(a, b string) bool {
	na, aok := numericVersion(a)
	nb, bok := numericVersion(b)
	if aok && bok {
		return na > nb
	}
	return a > b
}

// Latest returns the newest version of id.
func (m *Manager) Latest(id string) (Dataset, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var got []Dataset
	for _, d := range m.byID {
		if d.ID == id {
			got = append(got, *d)
		}
	}
	if len(got) == 0 {
		return Dataset{}, false
	}
	sortDatasets(got)
	return got[0], true
}

// Versions returns every version of id, newest first.
func (m *Manager) Versions(id string) []Dataset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Dataset{}
	for _, d := range m.byID {
		if d.ID == id {
			out = append(out, *d)
		}
	}
	sortDatasets(out)
	return out
}

// CSVPath returns the absolute-or-relative path of a version's dataset.csv.
func (m *Manager) CSVPath(id, version string) (string, error) {
	d, ok := m.Get(id, version)
	if !ok {
		return "", fmt.Errorf("%w: %s@%s", ErrNotFound, id, version)
	}
	return filepath.Join(d.Dir, CSVFileName), nil
}

// Create builds a new dataset version from the current contents of the flow
// store and writes it. It refuses to overwrite an existing (id, version).
func (m *Manager) Create(spec Spec) (*Dataset, error) {
	return m.create(spec, nil)
}

// Derive builds a new dataset version that records <fromID>@<fromVersion> as its
// parent. The parent must exist. The rows come from a fresh selection over the
// flow store, not from the parent's CSV: dataset-to-dataset transforms (subset,
// merge with weighting) are the training-recipe work of PROJECT.md §14 and are
// tracked separately. What Derive gives you today is honest lineage for
// "same corpus, different selection" — the common case when an operator tightens
// a filter and re-cuts a dataset.
func (m *Manager) Derive(fromID, fromVersion string, spec Spec) (*Dataset, error) {
	parent, ok := m.Get(fromID, fromVersion)
	if !ok {
		return nil, fmt.Errorf("%w: parent %s@%s", ErrNotFound, fromID, fromVersion)
	}
	parents := append([]string{parent.Ref()}, parent.ParentDatasets...)
	return m.create(spec, parents)
}

// Delete removes a version directory. Immutability protects a version's
// *contents*, not its existence: an operator who built a dataset from the wrong
// window must be able to remove it, and refusing would leave the only escape
// hatch outside the product. The caller audits it (the API does).
// Deleting a dataset that a registered model was trained on breaks that model's
// provenance; the manifest's content_hash lives on in the model's metadata, so
// the loss is recoverable only by rebuilding — the UI warns before deleting.
func (m *Manager) Delete(id, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ref := id + "@" + version
	d, ok := m.byID[ref]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	// Re-derive the path from the validated id/version rather than trusting the
	// stored Dir, so a hand-edited manifest cannot point Delete at another tree.
	dir, err := m.versionDirLocked(id, version)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("dataset: remove %q: %w", dir, err)
	}
	delete(m.byID, ref)
	// Prune the id directory when its last version is gone. os.Remove only
	// succeeds on an empty directory, which is exactly the condition we want.
	_ = os.Remove(filepath.Dir(dir))
	if i := strings.Index(id, "/"); i > 0 {
		_ = os.Remove(filepath.Join(m.dir, filepath.FromSlash(id[:i])))
	}
	m.logf("dataset: deleted %s (%s)", ref, d.ContentHash)
	return nil
}

// versionDirLocked maps a validated (id, version) to its directory under the
// root. The caller holds m.mu.
func (m *Manager) versionDirLocked(id, version string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	if err := ValidateVersion(version); err != nil {
		return "", err
	}
	parts := append(strings.Split(id, "/"), version)
	return filepath.Join(append([]string{m.dir}, parts...)...), nil
}

// nextVersionLocked picks "v<n+1>" from the highest existing numeric v-version
// of id, or "v1" when id is new. The caller holds m.mu.
func (m *Manager) nextVersionLocked(id string) string {
	best := 0
	for _, d := range m.byID {
		if d.ID != id {
			continue
		}
		if n, ok := numericVersion(d.Version); ok && n > best {
			best = n
		}
	}
	return fmt.Sprintf("v%d", best+1)
}

func numericVersion(v string) (int, bool) {
	if len(v) < 2 || v[0] != 'v' {
		return 0, false
	}
	n := 0
	for _, c := range v[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// create is the shared body of Create and Derive.
func (m *Manager) create(spec Spec, parents []string) (*Dataset, error) {
	if err := ValidateID(spec.ID); err != nil {
		return nil, err
	}
	if spec.Version != "" {
		if err := ValidateVersion(spec.Version); err != nil {
			return nil, err
		}
	}
	if err := spec.Selection.validate(); err != nil {
		return nil, err
	}
	if m.src == nil {
		return nil, fmt.Errorf("%w: no flow store is wired", ErrInvalid)
	}

	built, err := build(m.src, spec.Selection)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	version := spec.Version
	if version == "" {
		version = m.nextVersionLocked(spec.ID)
	}
	ref := spec.ID + "@" + version
	if _, ok := m.byID[ref]; ok {
		return nil, fmt.Errorf("%w: %s is immutable — create a new version", ErrExists, ref)
	}
	dir, err := m.versionDirLocked(spec.ID, version)
	if err != nil {
		return nil, err
	}
	// A directory on disk that the in-memory index does not know about (a
	// manifest we failed to parse at Open) still counts as taken: never clobber
	// operator data.
	if _, statErr := os.Stat(dir); statErr == nil {
		return nil, fmt.Errorf("%w: %q already exists on disk", ErrExists, dir)
	}

	man := Manifest{
		ID:               spec.ID,
		Version:          version,
		Name:             orDefault(strings.TrimSpace(spec.Name), spec.ID),
		Description:      spec.Description,
		Location:         spec.Location,
		Tags:             nonNil(spec.Tags),
		CreatedAt:        nowRFC3339(),
		SourceCaptureIDs: nonNil(spec.SourceCaptureIDs),
		TimeRange:        built.timeRange,
		FeatureSchema:    schema.FlowFeaturesV1().Schema,
		OutputSchema:     schema.TrafficClassesV1().Schema,
		FlowCount:        built.rows,
		LabelCounts:      built.labelCounts,
		LabelingSource:   built.labelingSource,
		ParentDatasets:   nonNil(parents),
		ContentHash:      built.contentHash,
		Selection:        spec.Selection,
		Warnings:         built.warnings,
		CSVFile:          CSVFileName,
		CSVBytes:         int64(len(built.csv)),
		FeatureCount:     schema.FlowFeaturesV1().InputSize,
		Columns:          built.columns,
	}

	if err := writeVersionDir(m.dir, dir, man, built.csv); err != nil {
		return nil, err
	}
	ds := &Dataset{Manifest: man, Dir: dir}
	m.byID[ref] = ds
	m.logf("dataset: created %s — %d flows, %s, labeling_source=%s", ref, man.FlowCount, man.ContentHash, man.LabelingSource)
	for _, w := range man.Warnings {
		m.logf("dataset: %s: %s", ref, w)
	}
	cp := *ds
	return &cp, nil
}

// writeVersionDir stages the two files in a temp directory under the dataset
// root and renames it into place, so a reader never sees a half-written version
// and a failure leaves no partial directory behind. Rename is the same atomicity
// primitive registry.persistLocked uses; here the unit is a directory because a
// version is two files that must appear together.
func writeVersionDir(root, dir string, man Manifest, csv []byte) error {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return fmt.Errorf("dataset: cannot create %q: %w", root, err)
	}
	staging, err := os.MkdirTemp(root, ".staging-*")
	if err != nil {
		return fmt.Errorf("dataset: staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	if err := os.WriteFile(filepath.Join(staging, CSVFileName), csv, 0o640); err != nil {
		return fmt.Errorf("dataset: write %s: %w", CSVFileName, err)
	}
	blob, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return fmt.Errorf("dataset: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(staging, ManifestFileName), append(blob, '\n'), 0o640); err != nil {
		return fmt.Errorf("dataset: write %s: %w", ManifestFileName, err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return fmt.Errorf("dataset: cannot create %q: %w", filepath.Dir(dir), err)
	}
	if err := os.Rename(staging, dir); err != nil {
		return fmt.Errorf("dataset: publish %q: %w", dir, err)
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
