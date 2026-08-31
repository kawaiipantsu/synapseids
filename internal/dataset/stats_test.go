package dataset

import (
	"bytes"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var statsBaseTS = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

func meanStd(xs []float64) (mean, std float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		d := x - mean
		std += d * d
	}
	return mean, math.Sqrt(std / float64(len(xs)))
}

func storageResult(id uint64, class string) inference.Result {
	return inference.Result{
		FlowID: id, Class: class, Score: 0.9,
		Models: []inference.ModelOutput{{ModelID: "heuristic-v1", Class: class, Score: 0.9}},
	}
}

// makeStatsCSV renders rows+labels in the frozen dataset.csv layout.
func makeStatsCSV(rows [][nFeat]float64, labels []string) []byte {
	var b bytes.Buffer
	b.WriteString(strings.Join(Columns(), ","))
	b.WriteByte('\n')
	for i, r := range rows {
		for j, v := range r {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		}
		b.WriteByte(',')
		b.WriteString(labels[i])
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// blobSignalDims is how many leading features carry the class separation. They
// end up mutually correlated, so together they form one dominant principal
// component that stands clear of the noise-dimension eigenvalues.
const blobSignalDims = 8

// twoBlobs builds nPerClass rows per class of two Gaussian blobs separated by
// ±sep on the first blobSignalDims features; every other feature is independent
// unit noise, and feature 47 is held at exactly zero (a degenerate column).
func twoBlobs(nPerClass int, sep float64) (rows [][nFeat]float64, labels []string) {
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic test fixture
	add := func(off float64, label string) {
		for i := 0; i < nPerClass; i++ {
			var r [nFeat]float64
			for j := 0; j < nFeat-1; j++ {
				r[j] = rng.NormFloat64()
			}
			for j := 0; j < blobSignalDims; j++ {
				r[j] += off
			}
			r[nFeat-1] = 0
			rows = append(rows, r)
			labels = append(labels, label)
		}
	}
	add(+sep, "scan")
	add(-sep, "normal")
	return rows, labels
}

func TestStatsSchemaIndices(t *testing.T) {
	want := map[int]string{
		idxSourcePort:  "source_port",
		idxDestPort:    "destination_port",
		idxProtocolTCP: "protocol_tcp",
		idxProtocolUDP: "protocol_udp",
		idxProtocolICM: "protocol_icmp",
	}
	for i, name := range want {
		if got := schema.FeatureName(i); got != name {
			t.Fatalf("flow-features-v1 index %d = %q, want %q — Stats reads it by index", i, got, name)
		}
	}
	if nFeat != 48 {
		t.Fatalf("nFeat = %d, want 48", nFeat)
	}
}

func TestStatsHistogramCountsSumToRows(t *testing.T) {
	rows, labels := twoBlobs(60, 8)
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{})
	if st.RowCount != 120 {
		t.Fatalf("RowCount = %d, want 120", st.RowCount)
	}
	for _, fs := range st.FeatureStats {
		if fs.Degenerate {
			if fs.BinCounts != nil || fs.BinEdges != nil {
				t.Errorf("%s degenerate but has a histogram", fs.Name)
			}
			continue
		}
		sum := 0
		for _, c := range fs.BinCounts {
			sum += c
		}
		if sum != st.RowCount {
			t.Errorf("%s: histogram counts sum to %d, want %d", fs.Name, sum, st.RowCount)
		}
		if len(fs.BinEdges) != StatsHistogramBins+1 || len(fs.BinCounts) != StatsHistogramBins {
			t.Errorf("%s: bins %d edges %d", fs.Name, len(fs.BinCounts), len(fs.BinEdges))
		}
	}
}

func TestStatsDegenerateAllZeroFeature(t *testing.T) {
	rows, labels := twoBlobs(30, 5)
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{})

	last := st.FeatureStats[nFeat-1] // snapshot_index, held at 0
	if !last.Degenerate || last.Min != 0 || last.Max != 0 {
		t.Fatalf("all-zero feature not reported degenerate: %+v", last)
	}
	// A degenerate column must correlate 0 with everything, including itself.
	n := st.Correlation.Size
	for j := 0; j < n; j++ {
		if v := st.Correlation.Matrix[(nFeat-1)*n+j]; v != 0 {
			t.Fatalf("degenerate feature correlation[%d] = %v, want 0", j, v)
		}
	}
}

func TestStatsCorrelation(t *testing.T) {
	rows, labels := twoBlobs(80, 8)
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{})
	n := st.Correlation.Size
	at := func(i, j int) float64 { return float64(st.Correlation.Matrix[i*n+j]) }

	if math.Abs(at(0, 0)-1) > 1e-6 {
		t.Errorf("corr(f0,f0) = %v, want 1", at(0, 0))
	}
	// f0 and f1 are both driven by the class offset → strongly positive.
	if at(0, 1) < 0.8 {
		t.Errorf("corr(f0,f1) = %v, want > 0.8 (both carry the class separation)", at(0, 1))
	}
	// f10 and f20 are independent unit noise → near zero.
	if math.Abs(at(10, 20)) > 0.25 {
		t.Errorf("corr(f10,f20) = %v, want ~0", at(10, 20))
	}
	// symmetric
	if at(3, 7) != at(7, 3) {
		t.Errorf("correlation not symmetric: %v vs %v", at(3, 7), at(7, 3))
	}
}

func TestStatsPCASeparatesBlobs(t *testing.T) {
	rows, labels := twoBlobs(75, 8)
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{})
	pca := st.PCA

	if pca.Components != 3 || len(pca.Loadings) != 3 || len(pca.Loadings[0]) != nFeat {
		t.Fatalf("PCA shape wrong: comps=%d loadings=%d", pca.Components, len(pca.Loadings))
	}
	if len(pca.ExplainedVariance) != 3 {
		t.Fatalf("explained variance len %d", len(pca.ExplainedVariance))
	}
	ev := pca.ExplainedVariance
	if !(ev[0] >= ev[1] && ev[1] >= ev[2]) {
		t.Errorf("explained variance not sorted descending: %v", ev)
	}
	if ev[0] <= 0 || ev[0] > 1 || ev[0]+ev[1]+ev[2] > 1.0000001 {
		t.Errorf("explained variance out of range: %v", ev)
	}
	// The dominant component carries the class separation: its share must beat
	// the 1/47 a pure-noise feature would contribute.
	if ev[0] < 4.0/47 {
		t.Errorf("PC1 explained variance %.4f is not above the noise floor", ev[0])
	}

	var scan, norm []float64
	for _, p := range pca.Projection {
		if p.Label == "scan" {
			scan = append(scan, p.PC1)
		} else {
			norm = append(norm, p.PC1)
		}
	}
	ms, ss := meanStd(scan)
	mn, sn := meanStd(norm)
	gap := math.Abs(ms - mn)
	if gap < 1.0 {
		t.Fatalf("PC1 does not separate the blobs: gap=%.3f (scan %.3f±%.3f, normal %.3f±%.3f)", gap, ms, ss, mn, sn)
	}
	if ss > gap/3 || sn > gap/3 {
		t.Errorf("PC1 within-class spread too wide vs the gap: gap=%.3f ss=%.3f sn=%.3f", gap, ss, sn)
	}
}

func TestStatsDeterministic(t *testing.T) {
	rows, labels := twoBlobs(50, 7)
	csv := makeStatsCSV(rows, labels)

	tbl1, _ := parseStatsCSV(csv)
	tbl2, _ := parseStatsCSV(csv)
	b1, err := computeStats(tbl1, Manifest{}).StatsJSON()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := computeStats(tbl2, Manifest{}).StatsJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("two runs over identical bytes produced different stats (%d vs %d bytes)", len(b1), len(b2))
	}
}

func TestStatsSingleRowNoPanic(t *testing.T) {
	var r [nFeat]float64
	for j := range r {
		r[j] = float64(j)
	}
	tbl, err := parseStatsCSV(makeStatsCSV([][nFeat]float64{r}, []string{"normal"}))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{}) // must not panic
	if st.RowCount != 1 {
		t.Fatalf("RowCount = %d", st.RowCount)
	}
	for _, fs := range st.FeatureStats {
		if !fs.Degenerate {
			t.Errorf("%s: a single row must be degenerate", fs.Name)
		}
	}
	for _, v := range st.Correlation.Matrix {
		if v != 0 {
			t.Fatalf("single-row correlation should be all zero, got %v", v)
		}
	}
	if st.PCA.EigenvaluesTotal != 0 {
		t.Errorf("single-row trace = %v, want 0", st.PCA.EigenvaluesTotal)
	}
	for _, ev := range st.PCA.ExplainedVariance {
		if ev != 0 {
			t.Errorf("single-row explained variance = %v, want 0", ev)
		}
	}
}

func TestStatsOutliers(t *testing.T) {
	rows, labels := twoBlobs(60, 4)
	// Plant one obvious outlier: feature 20 (unit noise) far outside its range.
	rows[10][20] = 40
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{})
	if st.Outliers.Count == 0 {
		t.Fatal("planted outlier not detected")
	}
	if len(st.Outliers.Rows) > st.Outliers.Cap {
		t.Fatalf("outlier list %d exceeds cap %d", len(st.Outliers.Rows), st.Outliers.Cap)
	}
	top := st.Outliers.Rows[0]
	if top.Row != 10 {
		t.Errorf("worst outlier row = %d, want 10", top.Row)
	}
	if len(top.Features) == 0 || top.Features[0].Index != 20 {
		t.Errorf("outlier's top feature = %+v, want index 20", top.Features)
	}
	if top.MaxZ <= StatsOutlierZ {
		t.Errorf("outlier MaxZ = %v, want > %v", top.MaxZ, StatsOutlierZ)
	}
}

func TestStatsLabelDistribution(t *testing.T) {
	rows, labels := twoBlobs(30, 5) // 30 scan + 30 normal
	tbl, err := parseStatsCSV(makeStatsCSV(rows, labels))
	if err != nil {
		t.Fatal(err)
	}
	st := computeStats(tbl, Manifest{LabelCounts: map[string]int{"scan": 30, "normal": 30}})
	ld := st.LabelDistribution
	if ld.Total != 60 || ld.ManifestMismatch {
		t.Fatalf("label distribution total=%d mismatch=%v", ld.Total, ld.ManifestMismatch)
	}
	idx := map[string]int{}
	for i, c := range ld.Classes {
		idx[c] = i
	}
	if ld.Counts[idx["scan"]] != 30 || ld.Counts[idx["normal"]] != 30 {
		t.Fatalf("counts = %v", ld.Counts)
	}
	if math.Abs(ld.Fractions[idx["scan"]]-0.5) > 1e-9 {
		t.Fatalf("scan fraction = %v", ld.Fractions[idx["scan"]])
	}
}

// TestStatsManagerCachesByHash exercises the full Manager.Stats path and its
// content-hash cache.
func TestStatsManagerCachesByHash(t *testing.T) {
	st := storage.NewMem(1000, 1000)
	rows, labels := twoBlobs(40, 6)
	for i := range rows {
		id := uint64(i + 1)
		var fv features.Vector
		fv.FlowID = id
		fv.Schema = schema.FlowFeaturesV1().Schema
		fv.Values = rows[i]
		st.PutFlow(storage.FlowRecord{ID: id, Proto: "TCP", InitiatorIP: "10.0.0.1", ResponderIP: "10.0.0.2", Features: fv})
		st.PutClassification(storage.Classification{
			FlowID: id, TS: statsBaseTS.Add(time.Duration(i) * time.Second),
			Proto: "TCP", InitiatorIP: "10.0.0.1", ResponderIP: "10.0.0.2",
			Result: storageResult(id, labels[i]),
		})
	}
	m := Open(t.TempDir(), st, func(string, ...any) {})
	d, err := m.Create(Spec{ID: "lab/explore", Version: "v1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s1, err := m.Stats(d.ID, d.Version)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	s2, err := m.Stats(d.ID, d.Version)
	if err != nil {
		t.Fatalf("Stats (2nd): %v", err)
	}
	if s1 != s2 {
		t.Fatal("second Stats call did not return the cached pointer")
	}
	if s1.Ref != d.Ref() || s1.ContentHash != d.ContentHash {
		t.Fatalf("Stats identity wrong: %s / %s", s1.Ref, s1.ContentHash)
	}
	if s1.RowCount != len(rows) {
		t.Fatalf("RowCount = %d, want %d", s1.RowCount, len(rows))
	}
	b1, _ := s1.StatsJSON()
	b2, _ := s2.StatsJSON()
	if !bytes.Equal(b1, b2) {
		t.Fatal("cached Stats marshalled to different bytes")
	}

	if _, err := m.Stats("lab/explore", "v9"); err == nil {
		t.Fatal("Stats of an unknown version should error")
	}
}
