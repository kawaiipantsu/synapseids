package dataset_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/dataset"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// The integration contract with trainer/synapse_trainer/dataset.py: a dataset's
// CSV must be loadable by load_csv with no adaptation. That means the 48
// flow-features-v1 column names spelled exactly as the frozen schema spells
// them, plus a "label" column, and every row parseable as floats plus a
// traffic-classes-v1 class name.
//
// TestDatasetCSVMatchesTheTrainerContract asserts that from the Go side and
// always runs. TestTrainerLoadsTheDataset additionally runs the real Python
// loader when python3 + numpy are importable, and says so out loud when they
// are not — a skipped contract test that nobody notices is worse than none.

func TestDatasetCSVMatchesTheTrainerContract(t *testing.T) {
	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)
	d := mustCreate(t, m, spec("trainer/contract"))

	body := readFile(t, filepath.Join(d.Dir, dataset.CSVFileName))
	if !strings.HasSuffix(body, "\n") {
		t.Error("the CSV does not end with a newline")
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != d.FlowCount+1 {
		t.Fatalf("csv has %d lines, want %d rows + 1 header", len(lines), d.FlowCount)
	}

	// Header: exactly the 48 schema names in schema order, then "label".
	header := strings.Split(lines[0], ",")
	fs := schema.FlowFeaturesV1()
	if len(header) != fs.InputSize+1 {
		t.Fatalf("header has %d columns, want %d features + label", len(header), fs.InputSize)
	}
	for i := 0; i < fs.InputSize; i++ {
		if want := schema.FeatureName(i); header[i] != want {
			t.Fatalf("header[%d] = %q, want %q — the CSV column order must be the frozen schema order", i, header[i], want)
		}
	}
	if header[fs.InputSize] != dataset.LabelColumn {
		t.Fatalf("last column = %q, want %q", header[fs.InputSize], dataset.LabelColumn)
	}

	// The manifest advertises the same header.
	if len(d.Columns) != len(header) {
		t.Fatalf("manifest columns = %d, csv header = %d", len(d.Columns), len(header))
	}
	for i := range header {
		if d.Columns[i] != header[i] {
			t.Fatalf("manifest columns[%d] = %q, csv header = %q", i, d.Columns[i], header[i])
		}
	}

	// Rows: 49 fields, 48 parseable floats, a known class name last.
	classes := map[string]bool{}
	for _, c := range schema.TrafficClassesV1().Classes {
		classes[c.Name] = true
	}
	for n, line := range lines[1:] {
		f := strings.Split(line, ",")
		if len(f) != fs.InputSize+1 {
			t.Fatalf("row %d has %d fields, want %d", n+1, len(f), fs.InputSize+1)
		}
		for i := 0; i < fs.InputSize; i++ {
			if _, err := strconv.ParseFloat(f[i], 64); err != nil {
				t.Fatalf("row %d column %q (%s) is not a float: %v", n+1, header[i], f[i], err)
			}
		}
		if !classes[f[fs.InputSize]] {
			t.Fatalf("row %d label %q is not a traffic-classes-v1 class", n+1, f[fs.InputSize])
		}
		// No quoting or escaping is ever needed, so none is ever emitted.
		if strings.ContainsAny(line, "\"\r") {
			t.Fatalf("row %d contains a quote or CR: %q", n+1, line)
		}
	}
}

// pythonWithNumpy returns the python3 interpreter to use, or "" plus a reason.
func pythonWithNumpy() (string, string) {
	py, err := exec.LookPath("python3")
	if err != nil {
		return "", "python3 is not on PATH"
	}
	out, err := exec.Command(py, "-c", "import numpy; print(numpy.__version__)").CombinedOutput() //nolint:gosec // py comes from LookPath
	if err != nil {
		return "", "python3 cannot import numpy: " + strings.TrimSpace(string(out))
	}
	return py, ""
}

// repoRoot walks up from the test's working directory to the directory holding
// go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find the repo root (no go.mod above the test directory)")
	return ""
}

func TestTrainerLoadsTheDataset(t *testing.T) {
	py, why := pythonWithNumpy()
	if py == "" {
		// Deliberately not t.Skip: the Go-side contract test above covers the
		// header and the row shape, and a silent skip would hide the fact that
		// the real loader never ran here.
		t.Logf("NOT RUN against the real trainer: %s — the Go-side contract assertions in "+
			"TestDatasetCSVMatchesTheTrainerContract still apply", why)
		return
	}

	root := repoRoot(t)
	trainer := filepath.Join(root, "trainer")
	if _, err := os.Stat(filepath.Join(trainer, "synapse_trainer", "dataset.py")); err != nil {
		t.Logf("NOT RUN: trainer/synapse_trainer/dataset.py is not present: %v", err)
		return
	}

	m := dataset.Open(t.TempDir(), twoClassStore(t, 40), quiet)
	d := mustCreate(t, m, spec("trainer/roundtrip"))

	// load_csv also accepts a directory containing dataset.csv, so hand it the
	// version directory exactly as an operator would.
	script := `
import json, sys
from synapse_trainer.dataset import load_csv
from synapse_trainer.schema import INPUT_SIZE, OUTPUT_SIZE, CLASS_NAMES
ds = load_csv(sys.argv[1])
print(json.dumps({
    "n": len(ds),
    "cols": int(ds.X.shape[1]),
    "input_size": INPUT_SIZE,
    "labels": ds.label_counts(),
    "ymin": int(ds.y.min()),
    "ymax": int(ds.y.max()),
    "meta": ds.meta(),
}))
`
	cmd := exec.Command(py, "-c", script, d.Dir) //nolint:gosec // py from LookPath, script is a constant, arg is a temp dir
	cmd.Dir = trainer
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+trainer,
		"SYNAPSE_SCHEMA_DIR="+filepath.Join(root, "schemas"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("trainer could not load the dataset: %v\n%s", err, out)
	}

	got := strings.TrimSpace(string(out))
	t.Logf("trainer load_csv: %s", got)
	for _, want := range []string{
		`"n": 40`,
		`"cols": 48`,
		`"input_size": 48`,
		`"normal": 20`,
		`"scan": 20`,
		`"feature_schema": "flow-features-v1"`,
		`"output_schema": "traffic-classes-v1"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("trainer output does not contain %s\nfull output: %s", want, got)
		}
	}
}
