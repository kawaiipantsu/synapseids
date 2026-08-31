// Package dataset — dataset-explorer statistics (PROJECT.md §19.11; issues #37, #67).
//
// Stats reads a *materialised* dataset.csv from disk and derives everything the
// ML ▸ Dataset Explorer draws: per-feature distributions and histograms, the
// label distribution, the 48×48 Pearson correlation matrix, protocol/port
// splits, a bounded outlier list, and the top-3 PCA projection of the
// standardised feature matrix.
//
// A written dataset version is immutable (see dataset.go), so the CSV bytes for
// a given content hash never change: Stats caches the whole bundle by content
// hash and a repeated call is a map lookup. All maths is stdlib `math` only —
// the covariance matrix is 48×48, small enough that a cyclic Jacobi
// symmetric-eigen solver is exact to ~1e-10 and dependency-free (ADR 0020).
// UMAP is deliberately not attempted; PCA covers the #67 "feature-space view".
package dataset

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/kawaiipantsu/synapseids/internal/features"
	"github.com/kawaiipantsu/synapseids/internal/schema"
)

// nFeat is the frozen flow-features-v1 width (48), aliased for brevity.
const nFeat = features.Size

// Tunables. All fixed so the same CSV bytes always produce identical stats.
const (
	// StatsHistogramBins is the fixed bucket count per feature histogram.
	StatsHistogramBins = 24
	// StatsPCAComponents is how many principal components Stats returns.
	StatsPCAComponents = 3
	// statsJacobiMaxSweeps caps the cyclic Jacobi solver. A 48×48 symmetric
	// matrix converges in well under ten sweeps; the cap only bounds a
	// pathological input and keeps the result deterministic.
	statsJacobiMaxSweeps = 100
	// statsJacobiOffThreshold stops the solver once the sum of squared
	// off-diagonal entries falls below this.
	statsJacobiOffThreshold = 1e-12
	// StatsOutlierZ is the max-per-feature |z-score| above which a row is an
	// outlier (see OutlierReport.Rule).
	StatsOutlierZ = 6.0
	// StatsOutlierCap bounds the outlier list.
	StatsOutlierCap = 100
	// statsOutlierTopFeatures is how many offending features each outlier lists.
	statsOutlierTopFeatures = 3
	// StatsProjectionCap bounds pca.projection. A larger dataset is sampled with
	// a fixed stride and projection_sampled is set.
	StatsProjectionCap = 5000
	// statsTopPorts bounds the port-distribution lists.
	statsTopPorts = 20

	// Frozen flow-features-v1 indices Stats reads directly for the
	// protocol/port views. Guarded by TestStatsSchemaIndices.
	idxSourcePort  = 21
	idxDestPort    = 22
	idxProtocolTCP = 23
	idxProtocolUDP = 24
	idxProtocolICM = 25

	// tiny guards a divide-by-a-near-zero-variance.
	statsTiny = 1e-12
)

// FeatureStats is one feature's distribution over the dataset's rows.
type FeatureStats struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Unit  string `json:"unit"`
	Norm  string `json:"norm"`

	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	Stddev float64 `json:"stddev"`
	P25    float64 `json:"p25"`
	P50    float64 `json:"p50"`
	P75    float64 `json:"p75"`

	// Degenerate is true when every row holds the same value (min == max),
	// including the all-zero case. The histogram is then empty.
	Degenerate bool `json:"degenerate"`
	// LogScale is true when the histogram edges are log1p-spaced (the schema
	// norm hint is "log1p" and all values are >= 0).
	LogScale bool `json:"log_scale"`
	// BinEdges has StatsHistogramBins+1 entries; BinCounts has
	// StatsHistogramBins. Both are nil for a degenerate feature.
	BinEdges  []float64 `json:"bin_edges"`
	BinCounts []int     `json:"bin_counts"`
}

// LabelDistribution counts rows per traffic-classes-v1 class, in schema order.
type LabelDistribution struct {
	Classes   []string  `json:"classes"`
	Counts    []int     `json:"counts"`
	Fractions []float64 `json:"fractions"`
	Total     int       `json:"total"`
	// Unknown holds labels found in the CSV that are not traffic-classes-v1
	// classes (should never happen for a dataset this daemon wrote).
	Unknown map[string]int `json:"unknown,omitempty"`
	// ManifestMismatch is true when the per-class counts computed from the CSV
	// disagree with the manifest's label_counts.
	ManifestMismatch bool `json:"manifest_mismatch"`
}

// CorrelationMatrix is the 48×48 Pearson matrix, row-major flattened:
// Matrix[i*Size+j] is corr(feature i, feature j). A zero-variance feature
// correlates 0 with everything and 0 on its own diagonal; every non-finite
// value is clamped to 0.
type CorrelationMatrix struct {
	Names  []string  `json:"names"`
	Size   int       `json:"size"`
	Matrix []float32 `json:"matrix"`
}

// PortCount is one (port, row-count) pair.
type PortCount struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

// PortStats is the destination/source port distribution, derived from the
// source_port / destination_port features (the only port signal in
// flow-features-v1).
type PortStats struct {
	TopDestination      []PortCount `json:"top_destination"`
	TopSource           []PortCount `json:"top_source"`
	DistinctDestination int         `json:"distinct_destination"`
	DistinctSource      int         `json:"distinct_source"`
}

// ProtocolStats is the protocol split from the protocol_tcp/udp/icmp flags.
// Other counts rows with none of the three flags set.
type ProtocolStats struct {
	TCP   int `json:"tcp"`
	UDP   int `json:"udp"`
	ICMP  int `json:"icmp"`
	Other int `json:"other"`
}

// OutlierFeature is one feature's contribution to a row being an outlier.
type OutlierFeature struct {
	Index int     `json:"index"`
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Z     float64 `json:"z"`
}

// Outlier is one flagged row. Row is its 0-based index into dataset.csv
// (excluding the header); the CSV is ordered by flow id, which the CSV does not
// carry as a column, so the index is the stable handle.
type Outlier struct {
	Row      int              `json:"row"`
	Label    string           `json:"label"`
	MaxZ     float64          `json:"max_z"`
	Features []OutlierFeature `json:"features"`
}

// OutlierReport is the bounded outlier list plus the rule that produced it.
type OutlierReport struct {
	Rule      string    `json:"rule"`
	Threshold float64   `json:"threshold"`
	Count     int       `json:"count"`
	Cap       int       `json:"cap"`
	Rows      []Outlier `json:"rows"`
}

// PCAPoint is one row projected onto the first StatsPCAComponents components.
type PCAPoint struct {
	PC1   float64 `json:"pc1"`
	PC2   float64 `json:"pc2"`
	PC3   float64 `json:"pc3"`
	Label string  `json:"label"`
	// Row is the 0-based dataset.csv row index (no flow-id column exists).
	Row int `json:"row"`
}

// PCAResult is the top-3 principal components of the standardised 48-feature
// matrix, computed from the correlation matrix by cyclic Jacobi rotation.
type PCAResult struct {
	Components int `json:"components"`
	// Loadings[k] is the k-th eigenvector in standardised space, length 48, in
	// flow-features-v1 order. Its sign is fixed so its largest-magnitude
	// component is positive (eigenvectors are otherwise sign-ambiguous).
	Loadings [][]float64 `json:"loadings"`
	// ExplainedVariance[k] is eigenvalue_k / trace, i.e. the share of total
	// standardised variance on component k.
	ExplainedVariance []float64 `json:"explained_variance"`
	// EigenvaluesTotal is the matrix trace: the count of non-degenerate
	// features, and the sum of all 48 eigenvalues.
	EigenvaluesTotal float64 `json:"eigenvalues_total"`
	// JacobiSweeps is how many sweeps the solver ran (bounded, for the record).
	JacobiSweeps int `json:"jacobi_sweeps"`

	Projection        []PCAPoint `json:"projection"`
	ProjectionSampled bool       `json:"projection_sampled"`
	ProjectionCap     int        `json:"projection_cap"`
}

// Stats is the whole explorer bundle for one dataset version.
type Stats struct {
	Ref           string `json:"ref"`
	ContentHash   string `json:"content_hash"`
	FeatureSchema string `json:"feature_schema"`
	OutputSchema  string `json:"output_schema"`
	RowCount      int    `json:"row_count"`
	FeatureCount  int    `json:"feature_count"`

	FeatureStats      []FeatureStats    `json:"feature_stats"`
	LabelDistribution LabelDistribution `json:"label_distribution"`
	Correlation       CorrelationMatrix `json:"correlation"`
	Ports             PortStats         `json:"ports"`
	Protocols         ProtocolStats     `json:"protocols"`
	Outliers          OutlierReport     `json:"outliers"`
	PCA               PCAResult         `json:"pca"`
}

// Stats returns the explorer bundle for one dataset version, computing it from
// the on-disk dataset.csv on the first call and serving a cached copy (keyed by
// the immutable content hash) thereafter. It returns ErrNotFound for an unknown
// version and ErrInvalid if the CSV on disk is unreadable or malformed.
func (m *Manager) Stats(id, version string) (*Stats, error) {
	d, ok := m.Get(id, version)
	if !ok {
		return nil, fmt.Errorf("%w: %s@%s", ErrNotFound, id, version)
	}

	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.statsByHash == nil {
		m.statsByHash = map[string]*Stats{}
	}
	if cached, hit := m.statsByHash[d.ContentHash]; hit {
		return cached, nil
	}

	csvPath := filepath.Join(d.Dir, CSVFileName)
	raw, err := os.ReadFile(csvPath) //nolint:gosec // operator-owned dataset tree, path from validated id/version
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrInvalid, csvPath, err)
	}
	table, err := parseStatsCSV(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, CSVFileName, err)
	}

	st := computeStats(table, d.Manifest)
	st.Ref = d.Ref()
	st.ContentHash = d.ContentHash
	m.statsByHash[d.ContentHash] = st
	return st, nil
}

// statsTable is the parsed CSV: one values row per flow plus its label.
type statsTable struct {
	values [][]float64 // [rows][48]
	labels []string    // [rows]
}

// parseStatsCSV reads the frozen dataset.csv layout: a header of the 48
// flow-features-v1 names then "label", then one row per flow. Non-finite cells
// become the schema default_missing, matching how the CSV was written.
func parseStatsCSV(raw []byte) (*statsTable, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = nFeat + 1
	r.ReuseRecord = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("no header row: %w", err)
	}
	if len(header) != nFeat+1 {
		return nil, fmt.Errorf("header has %d columns, want %d", len(header), nFeat+1)
	}

	miss := schema.FlowFeaturesV1().DefaultMissing
	tbl := &statsTable{}
	for {
		rec, rerr := r.Read()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, rerr
		}
		row := make([]float64, nFeat)
		for i := 0; i < nFeat; i++ {
			v, perr := strconv.ParseFloat(rec[i], 64)
			if perr != nil || !finite(v) {
				v = miss
			}
			row[i] = v
		}
		tbl.values = append(tbl.values, row)
		tbl.labels = append(tbl.labels, rec[nFeat])
	}
	if len(tbl.values) == 0 {
		return nil, fmt.Errorf("no data rows")
	}
	return tbl, nil
}

// computeStats does every derivation over the parsed table.
func computeStats(t *statsTable, man Manifest) *Stats {
	rows := len(t.values)
	feats := schema.FlowFeaturesV1().Features

	means, stddevs := columnMoments(t.values)
	st := &Stats{
		FeatureSchema: schema.FlowFeaturesV1().Schema,
		OutputSchema:  schema.TrafficClassesV1().Schema,
		RowCount:      rows,
		FeatureCount:  nFeat,
		FeatureStats:  make([]FeatureStats, nFeat),
	}

	for j := range feats {
		st.FeatureStats[j] = featureStats(t.values, j, feats[j], means[j], stddevs[j])
	}
	st.LabelDistribution = labelDistribution(t.labels, man.LabelCounts)
	st.Correlation = correlation(t.values, means)
	st.Ports = portStats(t.values)
	st.Protocols = protocolStats(t.values)

	// PCA of the standardised matrix == eigen of the correlation matrix. Reuse
	// the matrix we just built rather than recomputing the covariances.
	corr := square(st.Correlation.Matrix, nFeat)
	eigVals, eigVecs, sweeps := jacobiEigenSym(corr)
	st.PCA = pcaResult(t, means, stddevs, eigVals, eigVecs, sweeps)
	st.Outliers = outlierReport(t.values, t.labels, means, stddevs, feats)
	return st
}

// columnMoments returns the per-column mean and population stddev in one pass
// each. A zero-variance column reports stddev 0.
func columnMoments(rows [][]float64) (mean, stddev []float64) {
	n := float64(len(rows))
	mean = make([]float64, nFeat)
	stddev = make([]float64, nFeat)
	for _, r := range rows {
		for j, v := range r {
			mean[j] += v
		}
	}
	for j := range mean {
		mean[j] /= n
	}
	for _, r := range rows {
		for j, v := range r {
			d := v - mean[j]
			stddev[j] += d * d
		}
	}
	for j := range stddev {
		stddev[j] = math.Sqrt(stddev[j] / n)
	}
	return mean, stddev
}

// featureStats builds one feature's distribution and histogram.
func featureStats(rows [][]float64, j int, f schema.Feature, mean, stddev float64) FeatureStats {
	col := make([]float64, len(rows))
	for i, r := range rows {
		col[i] = r[j]
	}
	sorted := append([]float64(nil), col...)
	sort.Float64s(sorted)

	fs := FeatureStats{
		Index:  j,
		Name:   f.Name,
		Unit:   f.Unit,
		Norm:   f.Norm,
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Mean:   mean,
		Stddev: stddev,
		P25:    quantile(sorted, 0.25),
		P50:    quantile(sorted, 0.50),
		P75:    quantile(sorted, 0.75),
	}
	if fs.Max-fs.Min <= statsTiny {
		fs.Degenerate = true
		return fs
	}
	fs.LogScale = f.Norm == "log1p" && fs.Min >= 0
	fs.BinEdges = histogramEdges(fs.Min, fs.Max, fs.LogScale)
	fs.BinCounts = histogramCounts(col, fs.BinEdges)
	return fs
}

// histogramEdges returns StatsHistogramBins+1 edges, linearly spaced or, for a
// non-negative log1p feature, spaced evenly in log1p space.
func histogramEdges(min, max float64, logScale bool) []float64 {
	edges := make([]float64, StatsHistogramBins+1)
	if logScale {
		lo, hi := math.Log1p(min), math.Log1p(max)
		for i := range edges {
			edges[i] = math.Expm1(lo + (hi-lo)*float64(i)/float64(StatsHistogramBins))
		}
	} else {
		for i := range edges {
			edges[i] = min + (max-min)*float64(i)/float64(StatsHistogramBins)
		}
	}
	edges[0], edges[StatsHistogramBins] = min, max
	return edges
}

// histogramCounts bins col into the half-open buckets [edges[i], edges[i+1]),
// with the final bucket closed so the maximum lands in it.
func histogramCounts(col, edges []float64) []int {
	counts := make([]int, StatsHistogramBins)
	for _, v := range col {
		b := sort.SearchFloat64s(edges, v) - 1
		if b < 0 {
			b = 0
		}
		if b >= StatsHistogramBins {
			b = StatsHistogramBins - 1
		}
		counts[b]++
	}
	return counts
}

// labelDistribution counts rows per traffic-classes-v1 class and cross-checks
// the manifest.
func labelDistribution(labels []string, manifest map[string]int) LabelDistribution {
	classes := schema.TrafficClassesV1().Classes
	order := make([]string, len(classes))
	idx := make(map[string]int, len(classes))
	for i, c := range classes {
		order[i] = c.Name
		idx[c.Name] = i
	}
	ld := LabelDistribution{
		Classes:   order,
		Counts:    make([]int, len(order)),
		Fractions: make([]float64, len(order)),
		Total:     len(labels),
	}
	for _, l := range labels {
		if i, ok := idx[l]; ok {
			ld.Counts[i]++
			continue
		}
		if ld.Unknown == nil {
			ld.Unknown = map[string]int{}
		}
		ld.Unknown[l]++
	}
	if ld.Total > 0 {
		for i, c := range ld.Counts {
			ld.Fractions[i] = float64(c) / float64(ld.Total)
		}
	}
	for i, name := range order {
		if manifest[name] != ld.Counts[i] {
			ld.ManifestMismatch = true
			break
		}
	}
	return ld
}

// correlation builds the 48×48 Pearson matrix, flattened row-major. Means are
// passed in; one pass accumulates the covariances.
func correlation(rows [][]float64, mean []float64) CorrelationMatrix {
	n := nFeat
	cov := make([]float64, n*n)
	dev := make([]float64, n)
	for _, r := range rows {
		for j := 0; j < n; j++ {
			dev[j] = r[j] - mean[j]
		}
		for i := 0; i < n; i++ {
			di := dev[i]
			if di == 0 {
				continue
			}
			base := i * n
			for j := i; j < n; j++ {
				cov[base+j] += di * dev[j]
			}
		}
	}

	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = schema.FeatureName(i)
	}
	m := CorrelationMatrix{Names: names, Size: n, Matrix: make([]float32, n*n)}
	for i := 0; i < n; i++ {
		vi := cov[i*n+i]
		for j := i; j < n; j++ {
			vj := cov[j*n+j]
			var c float64
			switch {
			case i == j:
				if vi > statsTiny {
					c = 1
				}
			case vi > statsTiny && vj > statsTiny:
				c = cov[i*n+j] / math.Sqrt(vi*vj)
			}
			c = clamp(c, -1, 1)
			if !finite(c) {
				c = 0
			}
			m.Matrix[i*n+j] = float32(c)
			m.Matrix[j*n+i] = float32(c)
		}
	}
	return m
}

// portStats builds the destination/source port distributions from the two port
// features. Ports are rounded to the nearest integer.
func portStats(rows [][]float64) PortStats {
	dst := map[int]int{}
	src := map[int]int{}
	for _, r := range rows {
		dst[int(math.Round(r[idxDestPort]))]++
		src[int(math.Round(r[idxSourcePort]))]++
	}
	return PortStats{
		TopDestination:      topPorts(dst),
		TopSource:           topPorts(src),
		DistinctDestination: len(dst),
		DistinctSource:      len(src),
	}
}

// topPorts returns the statsTopPorts most common ports, count descending then
// port ascending so the order is total.
func topPorts(m map[int]int) []PortCount {
	out := make([]PortCount, 0, len(m))
	for p, c := range m {
		out = append(out, PortCount{Port: p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > statsTopPorts {
		out = out[:statsTopPorts]
	}
	return out
}

// protocolStats counts the protocol flags. A flag is "set" when it rounds to 1.
func protocolStats(rows [][]float64) ProtocolStats {
	var ps ProtocolStats
	for _, r := range rows {
		switch {
		case r[idxProtocolTCP] >= 0.5:
			ps.TCP++
		case r[idxProtocolUDP] >= 0.5:
			ps.UDP++
		case r[idxProtocolICM] >= 0.5:
			ps.ICMP++
		default:
			ps.Other++
		}
	}
	return ps
}

// outlierReport flags rows whose largest per-feature |z-score| exceeds
// StatsOutlierZ, bounded at StatsOutlierCap and ordered by that score.
func outlierReport(rows [][]float64, labels []string, mean, stddev []float64, feats []schema.Feature) OutlierReport {
	rep := OutlierReport{
		Rule: fmt.Sprintf("row's max |z-score| over the %d features exceeds the threshold; "+
			"z = (value - column mean) / column population stddev, zero-variance columns skipped", nFeat),
		Threshold: StatsOutlierZ,
		Cap:       StatsOutlierCap,
	}
	var found []Outlier
	for ri, r := range rows {
		var maxZ float64
		hits := make([]OutlierFeature, 0, nFeat)
		for j, v := range r {
			if stddev[j] <= statsTiny {
				continue
			}
			z := (v - mean[j]) / stddev[j]
			az := math.Abs(z)
			if az > maxZ {
				maxZ = az
			}
			if az > StatsOutlierZ {
				hits = append(hits, OutlierFeature{Index: j, Name: feats[j].Name, Value: v, Z: z})
			}
		}
		if maxZ <= StatsOutlierZ {
			continue
		}
		sort.Slice(hits, func(a, b int) bool { return math.Abs(hits[a].Z) > math.Abs(hits[b].Z) })
		if len(hits) > statsOutlierTopFeatures {
			hits = hits[:statsOutlierTopFeatures]
		}
		found = append(found, Outlier{Row: ri, Label: labels[ri], MaxZ: maxZ, Features: hits})
	}
	sort.SliceStable(found, func(a, b int) bool {
		if found[a].MaxZ != found[b].MaxZ {
			return found[a].MaxZ > found[b].MaxZ
		}
		return found[a].Row < found[b].Row
	})
	rep.Count = len(found)
	if len(found) > StatsOutlierCap {
		found = found[:StatsOutlierCap]
	}
	rep.Rows = found
	return rep
}

// pcaResult sorts the eigenpairs, fixes each eigenvector's sign, and projects
// every row (or a fixed-stride sample) onto the top components.
func pcaResult(t *statsTable, mean, stddev []float64, eigVals []float64, eigVecs [][]float64, sweeps int) PCAResult {
	n := nFeat
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return eigVals[order[a]] > eigVals[order[b]] })

	trace := 0.0
	for _, v := range eigVals {
		if v > 0 {
			trace += v
		}
	}

	k := StatsPCAComponents
	res := PCAResult{
		Components:        k,
		Loadings:          make([][]float64, k),
		ExplainedVariance: make([]float64, k),
		EigenvaluesTotal:  trace,
		JacobiSweeps:      sweeps,
		ProjectionCap:     StatsProjectionCap,
	}
	comps := make([][]float64, k) // comps[c] is the c-th eigenvector, length n
	for c := 0; c < k; c++ {
		col := order[c]
		vec := make([]float64, n)
		for row := 0; row < n; row++ {
			vec[row] = eigVecs[row][col]
		}
		fixSign(vec)
		comps[c] = vec
		res.Loadings[c] = vec
		if trace > statsTiny {
			res.ExplainedVariance[c] = math.Max(eigVals[col], 0) / trace
		}
	}

	rows := len(t.values)
	step := 1
	if rows > StatsProjectionCap {
		step = (rows + StatsProjectionCap - 1) / StatsProjectionCap
		res.ProjectionSampled = true
	}
	z := make([]float64, n)
	for ri := 0; ri < rows; ri += step {
		r := t.values[ri]
		for j := 0; j < n; j++ {
			if stddev[j] > statsTiny {
				z[j] = (r[j] - mean[j]) / stddev[j]
			} else {
				z[j] = 0
			}
		}
		res.Projection = append(res.Projection, PCAPoint{
			PC1:   dot(z, comps[0]),
			PC2:   dot(z, comps[1]),
			PC3:   dot(z, comps[2]),
			Label: t.labels[ri],
			Row:   ri,
		})
	}
	return res
}

// jacobiEigenSym diagonalises a symmetric n×n matrix by cyclic Jacobi rotation.
// It returns the eigenvalues and V, where V[r][c] is component r of eigenvector
// c. Deterministic: fixed sweep order, a fixed sweep cap and a fixed
// off-diagonal threshold. For a 48×48 matrix this agrees with a LAPACK
// symmetric solver to ~1e-10 (ADR 0020).
func jacobiEigenSym(in [][]float64) (eig []float64, vec [][]float64, sweeps int) {
	n := len(in)
	a := make([][]float64, n)
	v := make([][]float64, n)
	for i := 0; i < n; i++ {
		a[i] = append([]float64(nil), in[i]...)
		v[i] = make([]float64, n)
		v[i][i] = 1
	}

	for sweeps = 0; sweeps < statsJacobiMaxSweeps; sweeps++ {
		off := 0.0
		for p := 0; p < n-1; p++ {
			for q := p + 1; q < n; q++ {
				off += a[p][q] * a[p][q]
			}
		}
		if off <= statsJacobiOffThreshold {
			break
		}
		for p := 0; p < n-1; p++ {
			for q := p + 1; q < n; q++ {
				if math.Abs(a[p][q]) <= 1e-300 {
					continue
				}
				// For the Givens factor J = [[c, s], [-s, c]] that jacobiRotate
				// applies as A' = JᵀAJ, the angle that zeroes A'_pq satisfies
				// tan(2θ) = 2·A_pq / (A_qq - A_pp).
				phi := 0.5 * math.Atan2(2*a[p][q], a[q][q]-a[p][p])
				jacobiRotate(a, v, p, q, math.Cos(phi), math.Sin(phi))
			}
		}
	}

	eig = make([]float64, n)
	for i := 0; i < n; i++ {
		eig[i] = a[i][i]
	}
	return eig, v, sweeps
}

// jacobiRotate applies one Givens rotation of the (p,q) plane to a (both sides)
// and accumulates it into v.
func jacobiRotate(a, v [][]float64, p, q int, c, s float64) {
	n := len(a)
	for k := 0; k < n; k++ {
		akp, akq := a[k][p], a[k][q]
		a[k][p] = c*akp - s*akq
		a[k][q] = s*akp + c*akq
	}
	for k := 0; k < n; k++ {
		apk, aqk := a[p][k], a[q][k]
		a[p][k] = c*apk - s*aqk
		a[q][k] = s*apk + c*aqk
	}
	for k := 0; k < n; k++ {
		vkp, vkq := v[k][p], v[k][q]
		v[k][p] = c*vkp - s*vkq
		v[k][q] = s*vkp + c*vkq
	}
}

// fixSign negates vec in place if its largest-magnitude component is negative,
// so a sign-ambiguous eigenvector has one deterministic orientation.
func fixSign(vec []float64) {
	mi, mv := 0, 0.0
	for i, v := range vec {
		if math.Abs(v) > mv {
			mi, mv = i, math.Abs(v)
		}
	}
	if vec[mi] < 0 {
		for i := range vec {
			vec[i] = -vec[i]
		}
	}
}

// --- small numeric helpers ------------------------------------------------

func square(flat []float32, n int) [][]float64 {
	m := make([][]float64, n)
	for i := 0; i < n; i++ {
		m[i] = make([]float64, n)
		for j := 0; j < n; j++ {
			m[i][j] = float64(flat[i*n+j])
		}
	}
	return m
}

func quantile(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	pos := q * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// StatsJSON marshals a Stats bundle the way the API serves it (indented). It is
// here so a test can assert byte-for-byte determinism without importing the api
// package.
func (s *Stats) StatsJSON() ([]byte, error) { return json.MarshalIndent(s, "", "  ") }
