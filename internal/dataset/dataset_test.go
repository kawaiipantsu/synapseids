package dataset_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func quiet(string, ...any) {}

var baseTS = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// putFlow stores one flow plus its verdict. Feature values are a deterministic
// function of the flow id and the column index, so every row is distinct and a
// rebuild is byte-identical.
func putFlow(st *storage.Mem, id uint64, class string, opts ...func(*storage.Classification)) {
	var fv features.Vector
	fv.FlowID = id
	fv.Schema = schema.FlowFeaturesV1().Schema
	for i := range fv.Values {
		fv.Values[i] = float64(id)*0.5 + float64(i)/8
	}
	c := storage.Classification{
		FlowID:        id,
		TS:            baseTS.Add(time.Duration(id) * time.Second),
		Sensor:        "local",
		Proto:         "TCP",
		InitiatorIP:   "10.0.0.5",
		InitiatorPort: 40000 + uint16(id%1000), //nolint:gosec // test data, id is small
		ResponderIP:   "10.0.0.9",
		ResponderPort: 80,
		Result: inference.Result{
			FlowID:  id,
			Class:   class,
			Score:   0.9,
			ClassID: 0,
			Models: []inference.ModelOutput{
				{ModelID: "heuristic-v1", Role: inference.RolePrimary, Class: class, Score: 0.9},
			},
		},
	}
	for _, o := range opts {
		o(&c)
	}
	st.PutFlow(storage.FlowRecord{
		ID: id, Proto: c.Proto,
		InitiatorIP: c.InitiatorIP, InitiatorPort: c.InitiatorPort,
		ResponderIP: c.ResponderIP, ResponderPort: c.ResponderPort,
		FirstSeen: c.TS, LastSeen: c.TS,
		Features: fv,
	})
	st.PutClassification(c)
}

// twoClassStore holds n flows alternating normal/scan — enough rows and enough
// classes to pass the build guard rails.
func twoClassStore(t *testing.T, n int) *storage.Mem {
	t.Helper()
	st := storage.NewMem(1000, 1000)
	for i := 1; i <= n; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		putFlow(st, uint64(i), class) //nolint:gosec // loop bound is small and positive
	}
	return st
}

func mustCreate(t *testing.T, m *dataset.Manager, spec dataset.Spec) *dataset.Dataset {
	t.Helper()
	d, err := m.Create(spec)
	if err != nil {
		t.Fatalf("Create(%s): %v", spec.ID, err)
	}
	return d
}

func spec(id string) dataset.Spec {
	return dataset.Spec{
		ID:               id,
		Version:          "v1",
		Name:             "Lab attacks, August 2026",
		Description:      "Replayed lab corpus.",
		Location:         "thugs-lab",
		Tags:             []string{"lab", "phase4"},
		SourceCaptureIDs: []string{"replay:portscan.pcap"},
	}
}

// ---- manifest ------------------------------------------------------------

func TestCreateWritesEveryManifestField(t *testing.T) {
	root := t.TempDir()
	m := dataset.Open(root, twoClassStore(t, 40), quiet)

	d := mustCreate(t, m, spec("thugs/lab-attacks-2026-08"))

	if d.ID != "thugs/lab-attacks-2026-08" || d.Version != "v1" {
		t.Fatalf("id/version = %s@%s", d.ID, d.Version)
	}
	if d.Name != "Lab attacks, August 2026" || d.Description == "" || d.Location != "thugs-lab" {
		t.Errorf("metadata not carried through: %+v", d.Manifest)
	}
	if len(d.Tags) != 2 || d.Tags[0] != "lab" {
		t.Errorf("tags = %v", d.Tags)
	}
	if len(d.SourceCaptureIDs) != 1 {
		t.Errorf("source_capture_ids = %v", d.SourceCaptureIDs)
	}
	if _, err := time.Parse(time.RFC3339, d.CreatedAt); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", d.CreatedAt, err)
	}
	if !strings.HasSuffix(d.CreatedAt, "Z") {
		t.Errorf("created_at %q is not UTC", d.CreatedAt)
	}
	if d.TimeRange.From == "" || d.TimeRange.To == "" || d.TimeRange.From > d.TimeRange.To {
		t.Errorf("time_range = %+v", d.TimeRange)
	}
	if d.FeatureSchema != "flow-features-v1" || d.OutputSchema != "traffic-classes-v1" {
		t.Errorf("schemas = %s / %s", d.FeatureSchema, d.OutputSchema)
	}
	if d.FlowCount != 40 {
		t.Errorf("flow_count = %d, want 40", d.FlowCount)
	}
	if d.LabelCounts["normal"] != 20 || d.LabelCounts["scan"] != 20 {
		t.Errorf("label_counts = %v", d.LabelCounts)
	}
	if d.LabelingSource != "model_prediction:heuristic-v1" {
		t.Errorf("labeling_source = %q", d.LabelingSource)
	}
	if d.ParentDatasets == nil || len(d.ParentDatasets) != 0 {
		t.Errorf("parent_datasets = %v, want an empty (non-null) list", d.ParentDatasets)
	}
	if !strings.HasPrefix(d.ContentHash, "sha256:") || len(d.ContentHash) != len("sha256:")+64 {
		t.Errorf("content_hash = %q", d.ContentHash)
	}
	if strings.ToLower(d.ContentHash) != d.ContentHash {
		t.Errorf("content_hash %q is not lowercase hex", d.ContentHash)
	}

	// The two files exist where the layout says they do.
	dir := filepath.Join(root, "thugs", "lab-attacks-2026-08", "v1")
	for _, f := range []string{dataset.CSVFileName, dataset.ManifestFileName} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}

	// manifest.json on disk round-trips to the same thing.
	raw, err := os.ReadFile(filepath.Join(dir, dataset.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk dataset.Manifest
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	if onDisk.ContentHash != d.ContentHash || onDisk.FlowCount != d.FlowCount {
		t.Errorf("manifest.json disagrees with the returned manifest")
	}

	// Every §14 field is present as a JSON key, even when empty.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"id", "name", "description", "location", "tags", "created_at",
		"source_capture_ids", "time_range", "feature_schema", "output_schema",
		"flow_count", "label_counts", "labeling_source", "parent_datasets", "content_hash",
	} {
		if _, ok := keys[k]; !ok {
			t.Errorf("manifest.json is missing the §14 field %q", k)
		}
	}
}

func TestLabelCountsMatchTheCSV(t *testing.T) {
	root := t.TempDir()
	st := storage.NewMem(1000, 1000)
	// 30 normal, 8 scan, 4 brute_force.
	id := uint64(0)
	for _, p := range []struct {
		class string
		n     int
	}{{"normal", 30}, {"scan", 8}, {"brute_force", 4}} {
		for i := 0; i < p.n; i++ {
			id++
			putFlow(st, id, p.class)
		}
	}
	d := mustCreate(t, dataset.Open(root, st, quiet), spec("hq/mixed"))

	want := map[string]int{"normal": 30, "scan": 8, "brute_force": 4}
	for k, v := range want {
		if d.LabelCounts[k] != v {
			t.Errorf("label_counts[%q] = %d, want %d", k, d.LabelCounts[k], v)
		}
	}
	if len(d.LabelCounts) != len(want) {
		t.Errorf("label_counts has %d entries, want %d: %v", len(d.LabelCounts), len(want), d.LabelCounts)
	}
	if d.FlowCount != 42 {
		t.Errorf("flow_count = %d, want 42", d.FlowCount)
	}

	// The counts really do describe the file.
	got := map[string]int{}
	for _, line := range csvRows(t, filepath.Join(d.Dir, dataset.CSVFileName)) {
		f := strings.Split(line, ",")
		got[f[len(f)-1]]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("csv has %d %q rows, manifest says %d", got[k], k, v)
		}
	}
}

// TestSelectionJSONOmitsUnsetTimes: an unbounded selection must not record a
// zero time as if it were a real bound.
func TestSelectionJSONOmitsUnsetTimes(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)

	d := mustCreate(t, m, spec("json/unbounded"))
	raw := readFile(t, filepath.Join(d.Dir, dataset.ManifestFileName))
	if strings.Contains(raw, "0001-01-01") {
		t.Fatalf("manifest records a zero time as a selection bound:\n%s", raw)
	}
	var man map[string]any
	if err := json.Unmarshal([]byte(raw), &man); err != nil {
		t.Fatal(err)
	}
	sel, _ := man["selection"].(map[string]any)
	if _, ok := sel["from"]; ok {
		t.Errorf("selection.from is present for an unbounded selection: %v", sel)
	}

	// A real bound round-trips.
	s := spec("json/bounded")
	s.Selection = dataset.Selection{From: baseTS}
	d = mustCreate(t, m, s)
	raw = readFile(t, filepath.Join(d.Dir, dataset.ManifestFileName))
	if !strings.Contains(raw, baseTS.Format(time.RFC3339)) {
		t.Fatalf("manifest lost the selection.from bound:\n%s", raw)
	}
	var back dataset.Manifest
	if err := json.Unmarshal([]byte(raw), &back); err != nil {
		t.Fatal(err)
	}
	if !back.Selection.From.Equal(baseTS) {
		t.Errorf("selection.from round-tripped to %v, want %v", back.Selection.From, baseTS)
	}
}

// ---- content hash --------------------------------------------------------

func TestContentHashIsReproducible(t *testing.T) {
	st := twoClassStore(t, 40)

	// Two independent managers over two independent roots, same store.
	a := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("a/one"))
	b := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), dataset.Spec{
		// Different name, description, location, tags, id and version — none of
		// which may influence the hash.
		ID: "b/two", Version: "v7", Name: "something else", Description: "different",
		Location: "elsewhere", Tags: []string{"other"},
	})

	if a.ContentHash != b.ContentHash {
		t.Fatalf("same rows hashed differently:\n a=%s\n b=%s", a.ContentHash, b.ContentHash)
	}

	csvA := readFile(t, filepath.Join(a.Dir, dataset.CSVFileName))
	csvB := readFile(t, filepath.Join(b.Dir, dataset.CSVFileName))
	if csvA != csvB {
		t.Error("the two CSVs differ byte-for-byte but hashed the same")
	}
}

func TestContentHashChangesWithTheRows(t *testing.T) {
	st := twoClassStore(t, 40)
	a := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("a/one"))

	putFlow(st, 41, "scan")
	b := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("a/one"))

	if a.ContentHash == b.ContentHash {
		t.Fatal("adding a row did not change the content hash")
	}
}

func TestContentHashChangesWithTheLabels(t *testing.T) {
	base := twoClassStore(t, 40)
	a := mustCreate(t, dataset.Open(t.TempDir(), base, quiet), spec("a/one"))

	// Same 40 flows, same features, one relabelled.
	relabelled := storage.NewMem(1000, 1000)
	for i := 1; i <= 40; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		if i == 3 {
			class = "brute_force"
		}
		putFlow(relabelled, uint64(i), class) //nolint:gosec // small positive loop bound
	}
	b := mustCreate(t, dataset.Open(t.TempDir(), relabelled, quiet), spec("a/one"))

	if a.ContentHash == b.ContentHash {
		t.Fatal("changing a label did not change the content hash")
	}
}

// ---- immutability --------------------------------------------------------

func TestVersionIsImmutable(t *testing.T) {
	root := t.TempDir()
	m := dataset.Open(root, twoClassStore(t, 40), quiet)
	first := mustCreate(t, m, spec("thugs/lab"))

	_, err := m.Create(spec("thugs/lab"))
	if !errors.Is(err, dataset.ErrExists) {
		t.Fatalf("second write to the same version: err = %v, want ErrExists", err)
	}
	// Nothing was touched.
	got, ok := m.Get("thugs/lab", "v1")
	if !ok || got.ContentHash != first.ContentHash || got.CreatedAt != first.CreatedAt {
		t.Error("the existing version changed after the refused write")
	}

	// A directory that exists on disk but is not in the index is still taken.
	orphan := filepath.Join(root, "orphan", "v1")
	if err := os.MkdirAll(orphan, 0o750); err != nil {
		t.Fatal(err)
	}
	s := spec("orphan")
	if _, err := m.Create(s); !errors.Is(err, dataset.ErrExists) {
		t.Fatalf("writing over an unindexed directory: err = %v, want ErrExists", err)
	}
}

func TestVersionAutoIncrements(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)

	s := spec("hq/base")
	s.Version = ""
	first := mustCreate(t, m, s)
	if first.Version != "v1" {
		t.Fatalf("first auto version = %q, want v1", first.Version)
	}
	second := mustCreate(t, m, s)
	if second.Version != "v2" {
		t.Fatalf("second auto version = %q, want v2", second.Version)
	}
	if latest, ok := m.Latest("hq/base"); !ok || latest.Version != "v2" {
		t.Fatalf("Latest = %q, want v2", latest.Version)
	}
	if got := m.Versions("hq/base"); len(got) != 2 {
		t.Fatalf("Versions returned %d, want 2", len(got))
	}
}

// ---- derive --------------------------------------------------------------

func TestDeriveRecordsTheParent(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)
	parent := mustCreate(t, m, spec("thugs/lab"))

	childSpec := spec("thugs/lab")
	childSpec.Version = "v2"
	child, err := m.Derive("thugs/lab", "v1", childSpec)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(child.ParentDatasets) != 1 || child.ParentDatasets[0] != parent.Ref() {
		t.Fatalf("parent_datasets = %v, want [%s]", child.ParentDatasets, parent.Ref())
	}

	// A grandchild carries the whole chain, nearest ancestor first.
	gSpec := spec("thugs/lab")
	gSpec.Version = "v3"
	grand, err := m.Derive("thugs/lab", "v2", gSpec)
	if err != nil {
		t.Fatalf("Derive grandchild: %v", err)
	}
	want := []string{"thugs/lab@v2", "thugs/lab@v1"}
	if len(grand.ParentDatasets) != 2 || grand.ParentDatasets[0] != want[0] || grand.ParentDatasets[1] != want[1] {
		t.Fatalf("parent_datasets = %v, want %v", grand.ParentDatasets, want)
	}

	if _, err := m.Derive("thugs/lab", "v99", childSpec); !errors.Is(err, dataset.ErrNotFound) {
		t.Fatalf("Derive from an unknown parent: err = %v, want ErrNotFound", err)
	}
}

// ---- persistence ---------------------------------------------------------

func TestReopenFindsEveryVersion(t *testing.T) {
	root := t.TempDir()
	st := twoClassStore(t, 40)
	m := dataset.Open(root, st, quiet)
	mustCreate(t, m, spec("thugs/lab"))
	mustCreate(t, m, spec("global"))

	reopened := dataset.Open(root, st, quiet)
	if got := len(reopened.List()); got != 2 {
		t.Fatalf("reopened List has %d entries, want 2", got)
	}
	if _, ok := reopened.Get("thugs/lab", "v1"); !ok {
		t.Error("namespaced id did not survive a reopen")
	}
	if _, ok := reopened.Get("global", "v1"); !ok {
		t.Error("single-segment id did not survive a reopen")
	}
}

func TestOpenToleratesAMissingDirectory(t *testing.T) {
	m := dataset.Open(filepath.Join(t.TempDir(), "does", "not", "exist"), nil, quiet)
	if got := m.List(); len(got) != 0 {
		t.Fatalf("List = %v, want empty", got)
	}
	if _, ok := m.Get("a", "v1"); ok {
		t.Error("Get found something in an empty manager")
	}
}

func TestOpenToleratesACorruptManifest(t *testing.T) {
	root := t.TempDir()
	st := twoClassStore(t, 40)
	good := mustCreate(t, dataset.Open(root, st, quiet), spec("good/one"))

	bad := filepath.Join(root, "bad", "v1")
	if err := os.MkdirAll(bad, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, dataset.ManifestFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A manifest that parses but names an id that could never be written.
	evil := filepath.Join(root, "evil", "v1")
	if err := os.MkdirAll(evil, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evil, dataset.ManifestFileName), []byte(`{"id":"../../etc","version":"v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	logged := 0
	m := dataset.Open(root, st, func(string, ...any) { logged++ })
	if got := m.List(); len(got) != 1 || got[0].ContentHash != good.ContentHash {
		t.Fatalf("List = %d entries, want just the good one", len(got))
	}
	if logged == 0 {
		t.Error("a corrupt manifest was skipped silently")
	}
}

// ---- ids -----------------------------------------------------------------

func TestValidateIDRejectsTraversalAndJunk(t *testing.T) {
	bad := []string{
		"", "..", "../etc", "a/../../etc", "/abs", "abs/", "/", "a//b",
		"a/b/c", "Uppercase", "a/Uppercase", "sp ace", "tab\t", "new\nline",
		"has@at", "has:colon", "back\\slash", "nul\x00byte", ".hidden", "trailing-",
		"-leading", "a/.", "a/..", strings.Repeat("x", 200), strings.Repeat("x", 65),
		"caf\u00e9", "\u202eevil", // non-ASCII and a right-to-left override
	}
	for _, id := range bad {
		if err := dataset.ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q) = nil, want an error", id)
		} else if !errors.Is(err, dataset.ErrInvalid) {
			t.Errorf("ValidateID(%q) error does not wrap ErrInvalid: %v", id, err)
		}
	}

	good := []string{
		"global", "thugs/lab-attacks-2026-08", "hq-copenhagen/baseline-2026-08",
		"a", "a/b", "a.b", "a_b-c/d.e_f-2026", "x1/y2",
	}
	for _, id := range good {
		if err := dataset.ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", id, err)
		}
	}
}

func TestValidateVersionRejectsSeparators(t *testing.T) {
	for _, v := range []string{"", "a/b", "..", "v1@2", "V1", "v 1", strings.Repeat("v", 70), "/", "."} {
		if err := dataset.ValidateVersion(v); err == nil {
			t.Errorf("ValidateVersion(%q) = nil, want an error", v)
		}
	}
	for _, v := range []string{"v1", "v2026-08-31", "2026.08.31", "v1_rc2"} {
		if err := dataset.ValidateVersion(v); err != nil {
			t.Errorf("ValidateVersion(%q) = %v, want nil", v, err)
		}
	}
}

func TestCreateRejectsATraversalID(t *testing.T) {
	root := t.TempDir()
	m := dataset.Open(root, twoClassStore(t, 40), quiet)

	for _, id := range []string{"../escape", "a/../../escape", "/etc/passwd"} {
		s := spec(id)
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Errorf("Create(%q): err = %v, want ErrInvalid", id, err)
		}
	}
	// Nothing escaped the root.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a rejected id still created %d entries under the root", len(entries))
	}
}

func TestParseRef(t *testing.T) {
	id, v, err := dataset.ParseRef("thugs/lab-attacks-2026-08@v1")
	if err != nil || id != "thugs/lab-attacks-2026-08" || v != "v1" {
		t.Fatalf("ParseRef = %q, %q, %v", id, v, err)
	}
	for _, bad := range []string{"", "noat", "@v1", "id@", "@"} {
		if _, _, err := dataset.ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) = nil error, want one", bad)
		}
	}
}

// ---- selection guard rails ----------------------------------------------

func TestSelectionRejections(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)

	t.Run("no rows", func(t *testing.T) {
		s := spec("x/none")
		s.Selection = dataset.Selection{InitiatorIP: "203.0.113.7"}
		_, err := m.Create(s)
		if !errors.Is(err, dataset.ErrUnusable) {
			t.Fatalf("err = %v, want ErrUnusable", err)
		}
		if !strings.Contains(err.Error(), "matched no classifications") {
			t.Errorf("error does not say the selection was empty: %v", err)
		}
	})

	t.Run("single class", func(t *testing.T) {
		s := spec("x/one-class")
		s.Selection = dataset.Selection{Class: "normal"}
		_, err := m.Create(s)
		if !errors.Is(err, dataset.ErrUnusable) {
			t.Fatalf("err = %v, want ErrUnusable", err)
		}
		if !strings.Contains(err.Error(), "one class") {
			t.Errorf("error does not explain the single-class problem: %v", err)
		}
	})

	t.Run("below the row floor", func(t *testing.T) {
		s := spec("x/tiny")
		s.Selection = dataset.Selection{Limit: 4}
		_, err := m.Create(s)
		if !errors.Is(err, dataset.ErrUnusable) {
			t.Fatalf("err = %v, want ErrUnusable", err)
		}
		if !strings.Contains(err.Error(), "row floor") {
			t.Errorf("error does not mention the floor: %v", err)
		}
	})

	t.Run("negative limit", func(t *testing.T) {
		s := spec("x/neg")
		s.Selection = dataset.Selection{Limit: -1}
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("min_confidence out of range", func(t *testing.T) {
		s := spec("x/conf")
		s.Selection = dataset.Selection{MinConfidence: 1.5}
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("unknown class", func(t *testing.T) {
		s := spec("x/badclass")
		s.Selection = dataset.Selection{Class: "definitely-not-a-class"}
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("unknown proto", func(t *testing.T) {
		s := spec("x/badproto")
		s.Selection = dataset.Selection{Proto: "sctp"}
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("inverted time range", func(t *testing.T) {
		s := spec("x/badtime")
		s.Selection = dataset.Selection{From: baseTS.Add(time.Hour), To: baseTS}
		if _, err := m.Create(s); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("no flow store wired", func(t *testing.T) {
		nm := dataset.Open(t.TempDir(), nil, quiet)
		if _, err := nm.Create(spec("x/nostore")); !errors.Is(err, dataset.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})
}

// TestRowFloorBoundary pins the exact edge: MinRows rows build, MinRows-1 does
// not. Off-by-one here would either block a legitimate small dataset or let an
// unusable one through.
func TestRowFloorBoundary(t *testing.T) {
	exact := dataset.Open(t.TempDir(), twoClassStore(t, dataset.MinRows), quiet)
	d := mustCreate(t, exact, spec("floor/exact"))
	if d.FlowCount != dataset.MinRows {
		t.Fatalf("flow_count = %d, want exactly MinRows (%d)", d.FlowCount, dataset.MinRows)
	}

	under := dataset.Open(t.TempDir(), twoClassStore(t, dataset.MinRows-1), quiet)
	if _, err := under.Create(spec("floor/under")); !errors.Is(err, dataset.ErrUnusable) {
		t.Fatalf("MinRows-1 rows: err = %v, want ErrUnusable", err)
	}
}

func TestSelectionFilters(t *testing.T) {
	st := storage.NewMem(1000, 1000)
	for i := 1; i <= 40; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		id := uint64(i) //nolint:gosec // small positive loop bound
		putFlow(st, id, class, func(c *storage.Classification) {
			if i > 20 {
				c.Proto = "UDP"
				c.InitiatorIP = "192.168.1.1"
			}
		})
	}
	m := dataset.Open(t.TempDir(), st, quiet)

	s := spec("f/proto")
	s.Selection = dataset.Selection{Proto: "udp"} // case-insensitive
	d := mustCreate(t, m, s)
	if d.FlowCount != 20 {
		t.Errorf("proto filter kept %d rows, want 20", d.FlowCount)
	}

	s = spec("f/time")
	s.Version = "v1"
	s.Selection = dataset.Selection{From: baseTS.Add(11 * time.Second)}
	d = mustCreate(t, m, s)
	if d.FlowCount != 30 {
		t.Errorf("time filter kept %d rows, want 30", d.FlowCount)
	}

	s = spec("f/ip")
	s.Selection = dataset.Selection{InitiatorIP: "192.168.1.1"}
	d = mustCreate(t, m, s)
	if d.FlowCount != 20 {
		t.Errorf("initiator_ip filter kept %d rows, want 20", d.FlowCount)
	}

	s = spec("f/model")
	s.Selection = dataset.Selection{Model: "heuristic-v1"}
	if d = mustCreate(t, m, s); d.FlowCount != 40 {
		t.Errorf("model filter kept %d rows, want 40", d.FlowCount)
	}
	s = spec("f/nomodel")
	s.Selection = dataset.Selection{Model: "no-such-model"}
	if _, err := m.Create(s); !errors.Is(err, dataset.ErrUnusable) {
		t.Errorf("an unmatched model filter should be unusable, got %v", err)
	}
}

func TestOneRowPerFlowNewestVerdictWins(t *testing.T) {
	st := twoClassStore(t, 40)
	// Flow 1 is reclassified: the newer verdict must be the one that lands.
	putFlow(st, 1, "brute_force")

	d := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("x/dedupe"))
	if d.FlowCount != 40 {
		t.Fatalf("flow_count = %d, want 40 (one row per flow)", d.FlowCount)
	}
	if d.LabelCounts["brute_force"] != 1 || d.LabelCounts["normal"] != 19 {
		t.Errorf("label_counts = %v, want the newest verdict for flow 1", d.LabelCounts)
	}
}

// ---- warnings ------------------------------------------------------------

func TestImbalanceWarning(t *testing.T) {
	st := storage.NewMem(1000, 1000)
	for i := 1; i <= 99; i++ {
		putFlow(st, uint64(i), "normal") //nolint:gosec // small positive loop bound
	}
	putFlow(st, 100, "scan")

	d := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("x/skewed"))
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "class imbalance") && strings.Contains(w, "normal") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no class-imbalance warning in %v", d.Warnings)
	}
	// A 7-class schema with 2 populated classes always warns about the gap too.
	gap := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "have no rows") {
			gap = true
		}
	}
	if !gap {
		t.Errorf("no absent-class warning in %v", d.Warnings)
	}
}

func TestDuplicateRowWarning(t *testing.T) {
	st := storage.NewMem(1000, 1000)
	var fv features.Vector
	fv.Schema = schema.FlowFeaturesV1().Schema
	for i := 1; i <= 40; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		id := uint64(i) //nolint:gosec // small positive loop bound
		fv.FlowID = id
		// Every flow of a class gets an identical feature vector.
		for j := range fv.Values {
			fv.Values[j] = float64(i % 2)
		}
		st.PutFlow(storage.FlowRecord{ID: id, Proto: "TCP", Features: fv})
		st.PutClassification(storage.Classification{
			FlowID: id, TS: baseTS, Proto: "TCP",
			Result: inference.Result{FlowID: id, Class: class, Score: 0.9,
				Models: []inference.ModelOutput{{ModelID: "heuristic-v1", Class: class}}},
		})
	}
	d := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("x/dupes"))
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "duplicate an earlier row") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no duplicate-row warning in %v", d.Warnings)
	}
}

func TestEvictedFlowIsSkippedAndReported(t *testing.T) {
	// A store whose classification ring is far larger than its flow ring: the
	// oldest verdicts outlive their flow records, exactly as they do in a
	// long-running daemon.
	st := storage.NewMem(30, 1000)
	for i := 1; i <= 40; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		putFlow(st, uint64(i), class) //nolint:gosec // small positive loop bound
	}
	d := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("x/evicted"))
	if d.FlowCount != 30 {
		t.Fatalf("flow_count = %d, want 30 (10 verdicts lost their flow record)", d.FlowCount)
	}
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "already been evicted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no eviction warning in %v", d.Warnings)
	}
}

// ---- labeling source -----------------------------------------------------

func TestLabelingSourceNamesTheModels(t *testing.T) {
	st := storage.NewMem(1000, 1000)
	for i := 1; i <= 40; i++ {
		class := "normal"
		if i%2 == 0 {
			class = "scan"
		}
		id := uint64(i) //nolint:gosec // small positive loop bound
		putFlow(st, id, class, func(c *storage.Classification) {
			c.Result.Models = append(c.Result.Models,
				inference.ModelOutput{ModelID: "flow-classifier-v1", Class: class})
		})
	}
	d := mustCreate(t, dataset.Open(t.TempDir(), st, quiet), spec("x/labels"))

	// Sorted, joined, and unmistakably not a human.
	if d.LabelingSource != "model_prediction:flow-classifier-v1+heuristic-v1" {
		t.Fatalf("labeling_source = %q", d.LabelingSource)
	}
	if strings.Contains(d.LabelingSource, "human") {
		t.Error("a Phase-4 dataset must never claim human review (issue #42)")
	}
}

// ---- delete --------------------------------------------------------------

func TestDeleteRemovesTheVersionAndPrunesEmptyParents(t *testing.T) {
	root := t.TempDir()
	m := dataset.Open(root, twoClassStore(t, 40), quiet)
	mustCreate(t, m, spec("thugs/lab"))

	if err := m.Delete("thugs/lab", "v1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := m.Get("thugs/lab", "v1"); ok {
		t.Error("Get still finds the deleted version")
	}
	if _, err := os.Stat(filepath.Join(root, "thugs")); !os.IsNotExist(err) {
		t.Errorf("the empty namespace directory was not pruned: %v", err)
	}
	if err := m.Delete("thugs/lab", "v1"); !errors.Is(err, dataset.ErrNotFound) {
		t.Errorf("second Delete: err = %v, want ErrNotFound", err)
	}
	if err := m.Delete("nope", "v1"); !errors.Is(err, dataset.ErrNotFound) {
		t.Errorf("Delete of an unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteKeepsSiblingVersions(t *testing.T) {
	root := t.TempDir()
	m := dataset.Open(root, twoClassStore(t, 40), quiet)
	s := spec("thugs/lab")
	mustCreate(t, m, s)
	s.Version = "v2"
	mustCreate(t, m, s)

	if err := m.Delete("thugs/lab", "v1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("thugs/lab", "v2"); !ok {
		t.Fatal("deleting v1 removed v2")
	}
	if _, err := os.Stat(filepath.Join(root, "thugs", "lab", "v2")); err != nil {
		t.Errorf("v2 is gone from disk: %v", err)
	}
}

// ---- ordering ------------------------------------------------------------

func TestListIsNewestFirstAndTotal(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)
	// Created within the same RFC3339 second, so the id/version tiebreak decides.
	for _, id := range []string{"c/three", "a/one", "b/two"} {
		mustCreate(t, m, spec(id))
	}
	got := m.List()
	if len(got) != 3 {
		t.Fatalf("List = %d entries, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].CreatedAt < got[i].CreatedAt {
			t.Fatalf("List is not newest-first: %v", got)
		}
	}
	// Two calls agree — no map-iteration nondeterminism leaks out.
	again := m.List()
	for i := range got {
		if got[i].Ref() != again[i].Ref() {
			t.Fatalf("List is not stable: %v then %v", got, again)
		}
	}
}

// ---- concurrency ---------------------------------------------------------

// TestConcurrentCreateAndList exercises the RWMutex under -race: the API lists
// datasets while another request writes one.
func TestConcurrentCreateAndList(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := m.Create(spec("conc/" + strconv.Itoa(n))); err != nil {
				errs <- err
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = m.List()
				_, _ = m.Get("conc/0", "v1")
				_, _ = m.Latest("conc/1")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Create: %v", err)
	}
	if got := len(m.List()); got != 8 {
		t.Fatalf("List = %d, want 8", got)
	}
}

// TestConcurrentCreateSameVersion: two goroutines racing for the same
// (id, version) — exactly one may win, immutability holds under concurrency.
func TestConcurrentCreateSameVersion(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)

	var wg sync.WaitGroup
	var okCount, existsCount atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := m.Create(spec("race/one")); {
			case err == nil:
				okCount.Add(1)
			case errors.Is(err, dataset.ErrExists):
				existsCount.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != 1 || existsCount.Load() != 5 {
		t.Fatalf("ok=%d exists=%d, want 1 and 5", okCount.Load(), existsCount.Load())
	}
}

// ---- helpers -------------------------------------------------------------

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// csvRows returns the data lines of a dataset CSV (header dropped).
func csvRows(t *testing.T, path string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(readFile(t, path), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("%s has no data rows", path)
	}
	return lines[1:]
}
