package insight

// Tests for the bounded traffic matrix (issue #68). The properties that matter
// are: direction is preserved, the cap evicts and counts, the ordering is a total
// order (so repeated reads are byte-identical), and the fold stays cheap.

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// pairOf finds one cell in a materialised matrix.
func pairOf(t *testing.T, m Matrix, initiator, responder string) MatrixPair {
	t.Helper()
	for _, p := range m.Pairs {
		if p.Initiator == initiator && p.Responder == responder {
			return p
		}
	}
	t.Fatalf("pair %s→%s missing from matrix %+v", initiator, responder, m.Pairs)
	return MatrixPair{}
}

func hasPair(m Matrix, initiator, responder string) bool {
	for _, p := range m.Pairs {
		if p.Initiator == initiator && p.Responder == responder {
			return true
		}
	}
	return false
}

func TestMatrixAccumulatesPerPair(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck // always nil

	// A→B three times, plus one B→A. The reverse direction is a different pair.
	for i := 0; i < 3; i++ {
		fr, cl := rec(uint64(i+1), "10.0.0.1", 40000+uint16(i), "10.0.0.2", 3306,
			"tcp", base.Add(time.Duration(i)*time.Second), 100, 200, "brute_force", 3, false)
		feed(ix, fr, cl)
	}
	fr, cl := rec(99, "10.0.0.2", 51000, "10.0.0.1", 80, "tcp",
		base.Add(10*time.Second), 7, 11, "normal", 0, true)
	feed(ix, fr, cl)
	ix.Sync()

	m := ix.Matrix(0, MatrixSortFlows)
	if m.TrackedPairs != 2 || len(m.Pairs) != 2 {
		t.Fatalf("tracked %d pairs, returned %d, want 2 and 2", m.TrackedPairs, len(m.Pairs))
	}
	if m.Source != "incremental" {
		t.Errorf("Source = %q, want incremental", m.Source)
	}
	if m.Partial || m.Truncated {
		t.Errorf("an unevicted, unlimited matrix must be neither partial nor truncated: %+v", m)
	}

	fwd := pairOf(t, m, "10.0.0.1", "10.0.0.2")
	if fwd.Flows != 3 {
		t.Errorf("A→B flows = %d, want 3", fwd.Flows)
	}
	if fwd.Bytes != 3*300 || fwd.BytesFwd != 300 || fwd.BytesBwd != 600 {
		t.Errorf("A→B bytes = %d (fwd %d, bwd %d), want 900 (300, 600)",
			fwd.Bytes, fwd.BytesFwd, fwd.BytesBwd)
	}
	if fwd.Packets != 3*5 {
		t.Errorf("A→B packets = %d, want 15", fwd.Packets)
	}
	if fwd.Classifications != 3 || fwd.DominantClass != "brute_force" {
		t.Errorf("A→B verdicts = %d dominant %q, want 3 brute_force",
			fwd.Classifications, fwd.DominantClass)
	}
	if fwd.ThreatClass != "brute_force" || fwd.ThreatCount != 3 {
		t.Errorf("A→B threat = %q×%d, want brute_force×3", fwd.ThreatClass, fwd.ThreatCount)
	}
	if !fwd.FirstSeen.Equal(base.Add(-time.Second)) || !fwd.LastSeen.Equal(base.Add(2*time.Second)) {
		t.Errorf("A→B window = %s..%s", fwd.FirstSeen, fwd.LastSeen)
	}

	// The reverse pair is tracked separately and keeps its own direction.
	bwd := pairOf(t, m, "10.0.0.2", "10.0.0.1")
	if bwd.Flows != 1 || bwd.BytesFwd != 7 || bwd.BytesBwd != 11 {
		t.Errorf("B→A = %+v, want 1 flow 7/11 bytes", bwd)
	}
	if bwd.Disagreements != 1 {
		t.Errorf("B→A disagreements = %d, want 1", bwd.Disagreements)
	}
	// "normal" is the only class here, so it is dominant but not a threat.
	if bwd.DominantClass != "normal" || bwd.ThreatClass != "" || bwd.ThreatCount != 0 {
		t.Errorf("B→A dominant %q threat %q×%d, want normal, none",
			bwd.DominantClass, bwd.ThreatClass, bwd.ThreatCount)
	}

	if m.TotalFlows != 4 || m.TotalBytes != 900+18 {
		t.Errorf("totals = %d flows / %d bytes, want 4 / 918", m.TotalFlows, m.TotalBytes)
	}
	if m.MaxFlows != 3 || m.MaxBytes != 900 {
		t.Errorf("heat scale = %d/%d, want 3/900", m.MaxFlows, m.MaxBytes)
	}
}

// A pair carrying mostly benign traffic with a few attack verdicts must still
// report the attack class — that is the cell an operator is looking for.
func TestMatrixThreatClassSurvivesABenignMajority(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	for i := 0; i < 40; i++ {
		fr, cl := rec(uint64(i+1), "10.0.0.7", 1234, "10.0.0.8", 443, "tcp",
			base.Add(time.Duration(i)*time.Second), 10, 10, "normal", 0, false)
		feed(ix, fr, cl)
	}
	for i := 0; i < 2; i++ {
		fr, cl := rec(uint64(100+i), "10.0.0.7", 1234, "10.0.0.8", 443, "tcp",
			base.Add(time.Duration(i)*time.Second), 10, 10, "scan", 1, false)
		feed(ix, fr, cl)
	}
	ix.Sync()

	p := pairOf(t, ix.Matrix(0, MatrixSortFlows), "10.0.0.7", "10.0.0.8")
	if p.DominantClass != "normal" {
		t.Errorf("DominantClass = %q, want normal", p.DominantClass)
	}
	if p.ThreatClass != "scan" || p.ThreatCount != 2 {
		t.Errorf("ThreatClass = %q×%d, want scan×2", p.ThreatClass, p.ThreatCount)
	}
	// The class list is ordered by count, so the mix bar reads correctly.
	if len(p.Classes) != 2 || p.Classes[0].Class != "normal" || p.Classes[1].Class != "scan" {
		t.Errorf("Classes = %+v, want normal then scan", p.Classes)
	}
}

// Snapshot records carry cumulative counters, so they must not add to volume —
// the same rule host profiles follow (ADR 0016).
func TestMatrixSnapshotsDoNotDoubleCountVolume(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	fr, cl := rec(1, "10.1.0.1", 1000, "10.1.0.2", 22, "tcp", base, 500, 900, "normal", 0, false)
	fr.CloseReason = "snapshot"
	feed(ix, fr, cl)
	fr.CloseReason = "fin_rst"
	fr.FwdBytes, fr.BwdBytes = 800, 1200
	feed(ix, fr, cl)
	ix.Sync()

	p := pairOf(t, ix.Matrix(0, MatrixSortFlows), "10.1.0.1", "10.1.0.2")
	if p.Flows != 1 {
		t.Errorf("Flows = %d, want 1 (the snapshot must not count as a flow)", p.Flows)
	}
	if p.Bytes != 2000 {
		t.Errorf("Bytes = %d, want 2000 (terminal counters only)", p.Bytes)
	}
	// Verdicts come from every record, snapshots included.
	if p.Classifications != 2 {
		t.Errorf("Classifications = %d, want 2", p.Classifications)
	}
}

// The cap must bite, count what it dropped, keep the heavy hitters and say the
// result is partial.
func TestMatrixCapEvictsLightPairsAndCounts(t *testing.T) {
	const maxPairs = 16
	ix := New(Options{MaxPairs: maxPairs, QueueSize: 1 << 16})
	defer ix.Close() //nolint:errcheck

	// One heavy conversation: 200 flows on a single pair.
	for i := 0; i < 200; i++ {
		fr, cl := rec(uint64(i+1), "10.9.9.9", 40000, "10.9.9.1", 3306, "tcp",
			base.Add(time.Duration(i)*time.Millisecond), 50, 50, "brute_force", 3, false)
		feed(ix, fr, cl)
	}
	// A wide sweep: 500 one-flow pairs, the long tail the cap exists to shed.
	for i := 0; i < 500; i++ {
		fr, cl := rec(uint64(1000+i), "10.9.9.9", 40001, fmt.Sprintf("10.8.%d.%d", i/250, i%250),
			80, "tcp", base.Add(time.Duration(i)*time.Millisecond), 1, 1, "scan", 1, false)
		feed(ix, fr, cl)
	}
	ix.Sync()

	st := ix.Stats()
	if st.Pairs > maxPairs {
		t.Errorf("Pairs = %d, exceeds the cap of %d", st.Pairs, maxPairs)
	}
	if st.PairCap != maxPairs {
		t.Errorf("PairCap = %d, want %d", st.PairCap, maxPairs)
	}
	if st.PairsEvicted == 0 {
		t.Fatal("PairsEvicted = 0, but 501 distinct pairs were offered to a 16-pair table")
	}

	m := ix.Matrix(0, MatrixSortFlows)
	if !m.Partial {
		t.Error("Partial = false after the cap evicted; a partial matrix must say so")
	}
	if m.PairsEvicted != st.PairsEvicted {
		t.Errorf("Matrix.PairsEvicted = %d, Stats = %d", m.PairsEvicted, st.PairsEvicted)
	}
	// The heavy pair is what a matrix exists to show; it must survive the sweep.
	if !hasPair(m, "10.9.9.9", "10.9.9.1") {
		t.Error("the 200-flow pair was evicted in favour of one-flow scan noise")
	}
	if len(m.Pairs) == 0 || m.Pairs[0].Initiator != "10.9.9.9" || m.Pairs[0].Responder != "10.9.9.1" {
		t.Errorf("heaviest pair is not first: %+v", m.Pairs)
	}
	if m.Pairs[0].Flows != 200 {
		t.Errorf("the retained heavy pair lost counts: flows = %d, want 200", m.Pairs[0].Flows)
	}
}

// Ordering must be a total order: every sort mode ends in the same tie-break, so
// two reads of unchanged state are identical, and limit= marks itself truncated.
func TestMatrixOrderingIsStableAndTruncationIsFlagged(t *testing.T) {
	ix := New(Options{QueueSize: 1 << 16})
	defer ix.Close() //nolint:errcheck

	// Deliberate ties: 12 pairs, 3 flows each, identical byte counts and times.
	for i := 0; i < 12; i++ {
		for f := 0; f < 3; f++ {
			fr, cl := rec(uint64(i*10+f+1), fmt.Sprintf("10.20.0.%d", i), 1234,
				fmt.Sprintf("10.21.0.%d", i), 443, "tcp", base, 10, 10, "normal", 0, false)
			feed(ix, fr, cl)
		}
	}
	// One outlier that is heavy in bytes but light in flows, to separate the
	// two orderings.
	fr, cl := rec(9001, "10.20.9.9", 1234, "10.21.9.9", 443, "tcp", base, 1<<20, 1<<20, "normal", 0, false)
	feed(ix, fr, cl)
	ix.Sync()

	for _, ord := range []MatrixSort{MatrixSortFlows, MatrixSortBytes, MatrixSortLastSeen} {
		a := ix.Matrix(0, ord)
		b := ix.Matrix(0, ord)
		if len(a.Pairs) != len(b.Pairs) {
			t.Fatalf("%s: pair count changed between reads", ord)
		}
		for i := range a.Pairs {
			if !reflect.DeepEqual(a.Pairs[i], b.Pairs[i]) {
				t.Errorf("%s: read is not stable at index %d: %+v vs %+v",
					ord, i, a.Pairs[i], b.Pairs[i])
			}
		}
	}

	// flows= puts a 3-flow pair first; bytes= puts the 2 MiB single flow first.
	byFlows := ix.Matrix(0, MatrixSortFlows)
	if byFlows.Pairs[0].Flows != 3 {
		t.Errorf("sort=flows head has %d flows, want 3", byFlows.Pairs[0].Flows)
	}
	byBytes := ix.Matrix(0, MatrixSortBytes)
	if byBytes.Pairs[0].Initiator != "10.20.9.9" {
		t.Errorf("sort=bytes head = %s, want the 2 MiB pair", byBytes.Pairs[0].Initiator)
	}

	// limit= truncates but does not make the matrix partial: a limited view of a
	// complete table is still complete data.
	lim := ix.Matrix(5, MatrixSortFlows)
	if len(lim.Pairs) != 5 || !lim.Truncated {
		t.Errorf("limit=5 gave %d pairs, truncated=%v", len(lim.Pairs), lim.Truncated)
	}
	if lim.Partial {
		t.Error("Partial = true from limit alone; limit is Truncated, not Partial")
	}
	if lim.TrackedPairs != 13 || lim.ReturnedPairs != 5 {
		t.Errorf("tracked %d returned %d, want 13 and 5", lim.TrackedPairs, lim.ReturnedPairs)
	}
	// Totals span every tracked pair, so a client can size what it is not seeing.
	if lim.TotalFlows != 37 {
		t.Errorf("TotalFlows = %d, want 37 across all 13 pairs", lim.TotalFlows)
	}
}

// The axes must describe exactly the returned pairs, ordered by their own volume,
// so the grid has no all-zero row or column.
func TestMatrixAxesCoverReturnedPairsOnly(t *testing.T) {
	ix := New(Options{QueueSize: 1 << 16})
	defer ix.Close() //nolint:errcheck

	// hot initiator talks to two responders; a cold pair sits below the limit.
	for i := 0; i < 5; i++ {
		fr, cl := rec(uint64(i+1), "10.30.0.1", 1234, "10.30.0.2", 80, "tcp", base, 10, 10, "normal", 0, false)
		feed(ix, fr, cl)
	}
	for i := 0; i < 3; i++ {
		fr, cl := rec(uint64(20+i), "10.30.0.1", 1234, "10.30.0.3", 80, "tcp", base, 10, 10, "normal", 0, false)
		feed(ix, fr, cl)
	}
	fr, cl := rec(90, "10.30.0.9", 1234, "10.30.0.8", 80, "tcp", base, 1, 1, "normal", 0, false)
	feed(ix, fr, cl)
	ix.Sync()

	m := ix.Matrix(2, MatrixSortFlows)
	if len(m.Initiators) != 1 || m.Initiators[0].IP != "10.30.0.1" {
		t.Fatalf("Initiators = %+v, want just the hot initiator", m.Initiators)
	}
	if m.Initiators[0].Flows != 8 || m.Initiators[0].Pairs != 2 {
		t.Errorf("initiator axis = %+v, want 8 flows over 2 pairs", m.Initiators[0])
	}
	if len(m.Responders) != 2 {
		t.Fatalf("Responders = %+v, want 2", m.Responders)
	}
	// Responder axis is ordered by its own volume: .2 (5 flows) before .3 (3).
	if m.Responders[0].IP != "10.30.0.2" || m.Responders[1].IP != "10.30.0.3" {
		t.Errorf("responder axis order = %+v", m.Responders)
	}
	// The cold pair's endpoints are excluded because its pair was not returned.
	for _, a := range append(append([]MatrixAxis{}, m.Initiators...), m.Responders...) {
		if a.IP == "10.30.0.9" || a.IP == "10.30.0.8" {
			t.Errorf("axis contains %s, whose pair was not returned", a.IP)
		}
	}
}

// The on-demand accumulator is what answers a filtered /api/v1/matrix. It must
// apply the identical rules and report its own honesty flags.
func TestMatrixAccumulatorFiltersAndReportsScan(t *testing.T) {
	rows := make([]storage.FlowRecord, 0, 8)
	verdict := map[uint64]storage.Classification{}
	for i := 0; i < 8; i++ {
		class, id := "normal", 0
		if i%2 == 1 {
			class, id = "scan", 1
		}
		fr, cl := rec(uint64(i+1), fmt.Sprintf("10.40.0.%d", i%2), 1234,
			"10.40.9.9", 80, "tcp", base.Add(time.Duration(i)*time.Second), 10, 10, class, id, false)
		rows = append(rows, fr)
		verdict[fr.ID] = cl
	}

	// Unfiltered: both initiators, 8 flows.
	all := NewMatrixAccumulator(0)
	for i := range rows {
		c := verdict[rows[i].ID]
		all.Add(&rows[i], &c)
	}
	full := all.Matrix(0, MatrixSortFlows, false)
	if full.Source != "scan" || full.Scanned != 8 {
		t.Errorf("source %q scanned %d, want scan/8", full.Source, full.Scanned)
	}
	if full.TotalFlows != 8 || len(full.Pairs) != 2 {
		t.Errorf("unfiltered = %d flows over %d pairs, want 8 over 2", full.TotalFlows, len(full.Pairs))
	}

	// class=scan narrows it to the four odd-indexed rows, all from 10.40.0.1.
	only := NewMatrixAccumulator(0)
	for i := range rows {
		c := verdict[rows[i].ID]
		if c.Result.Class != "scan" {
			continue
		}
		only.Add(&rows[i], &c)
	}
	narrowed := only.Matrix(0, MatrixSortFlows, false)
	if len(narrowed.Pairs) != 1 {
		t.Fatalf("class=scan matrix has %d pairs, want 1: %+v", len(narrowed.Pairs), narrowed.Pairs)
	}
	if narrowed.Pairs[0].Initiator != "10.40.0.1" || narrowed.Pairs[0].Flows != 4 {
		t.Errorf("class=scan pair = %+v, want 10.40.0.1 with 4 flows", narrowed.Pairs[0])
	}
	if narrowed.Partial {
		t.Error("Partial = true on a complete scan")
	}
	// A caller whose row scan hit its own cap says so, and the flag survives.
	if !only.Matrix(0, MatrixSortFlows, true).Partial {
		t.Error("a caller-declared partial window was not propagated")
	}

	// A record with no verdict still counts as traffic, just with no class mix.
	unclassified := NewMatrixAccumulator(0)
	unclassified.Add(&rows[0], nil)
	m := unclassified.Matrix(0, MatrixSortFlows, false)
	if len(m.Pairs) != 1 || m.Pairs[0].Flows != 1 || m.Pairs[0].Classifications != 0 {
		t.Errorf("unclassified row = %+v", m.Pairs)
	}
	if len(m.Pairs[0].Classes) != 0 || m.Pairs[0].DominantClass != "" {
		t.Errorf("unclassified row invented a class: %+v", m.Pairs[0])
	}
}

// A record missing either address cannot be a pair and must be skipped rather
// than creating an ""-keyed cell (packet-derived input, §28.11).
func TestMatrixSkipsIncompleteTuples(t *testing.T) {
	a := NewMatrixAccumulator(0)
	fr, cl := rec(1, "", 0, "10.0.0.2", 80, "tcp", base, 1, 1, "normal", 0, false)
	a.Add(&fr, &cl)
	fr2, cl2 := rec(2, "10.0.0.1", 0, "", 80, "tcp", base, 1, 1, "normal", 0, false)
	a.Add(&fr2, &cl2)
	a.Add(nil, nil)

	m := a.Matrix(0, MatrixSortFlows, false)
	if len(m.Pairs) != 0 || len(m.Initiators) != 0 || len(m.Responders) != 0 {
		t.Errorf("incomplete tuples produced cells: %+v", m)
	}
}

func TestMatrixNilSafety(t *testing.T) {
	var ix *Index
	m := ix.Matrix(10, MatrixSortFlows)
	if m.Pairs == nil || len(m.Pairs) != 0 {
		t.Errorf("nil Index matrix pairs = %+v, want an empty non-nil slice", m.Pairs)
	}
	if m.Initiators == nil || m.Responders == nil {
		t.Error("nil Index matrix axes must be empty slices, not null")
	}
	if m.PairCap != DefaultMaxPairs || m.TrackedPairs != 0 || m.Partial {
		t.Errorf("nil Index matrix = %+v", m)
	}

	var acc *MatrixAccumulator
	acc.Add(nil, nil)
	if got := acc.Matrix(5, MatrixSortBytes, false); len(got.Pairs) != 0 {
		t.Errorf("nil accumulator matrix = %+v", got)
	}
}

func TestParseMatrixSort(t *testing.T) {
	for in, want := range map[string]MatrixSort{
		"":          MatrixSortFlows,
		"flows":     MatrixSortFlows,
		"bytes":     MatrixSortBytes,
		"last_seen": MatrixSortLastSeen,
	} {
		if got, ok := ParseMatrixSort(in); !ok || got != want {
			t.Errorf("ParseMatrixSort(%q) = %q,%v, want %q,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"packets", "Flows", "first_seen", "0"} {
		if _, ok := ParseMatrixSort(bad); ok {
			t.Errorf("ParseMatrixSort(%q) accepted", bad)
		}
	}
	// The schema must have told us which class is benign; ThreatClass depends on
	// it, and a silent -1 would make every class a threat.
	if normalClassID != 0 {
		t.Errorf("normalClassID = %d, want the traffic-classes-v1 index of \"normal\"", normalClassID)
	}
}

// The matrix must not be the thing that introduces a race between the packet
// path and the API. Run under -race.
func TestMatrixConcurrentIngestAndRead(t *testing.T) {
	ix := New(Options{MaxHosts: 64, MaxKeys: 16, MaxPairs: 32, QueueSize: 256})
	defer ix.Close() //nolint:errcheck

	const writers, reads, perWriter = 4, 1500, 2500
	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				fr, cl := rec(uint64(w*perWriter+i),
					fmt.Sprintf("10.50.%d.%d", w, i%97), uint16(1024+i%1000),
					fmt.Sprintf("10.51.%d.%d", i%5, i%11), uint16(i%2048),
					[]string{"tcp", "udp", "icmp"}[i%3],
					base.Add(time.Duration(i)*time.Millisecond),
					uint64(i), uint64(i*2),
					[]string{"normal", "scan", "brute_force"}[i%3], []int{0, 1, 3}[i%3],
					i%13 == 0)
				ix.Observe(&fr, &cl)
			}
		}(w)
	}
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < reads; i++ {
				_ = ix.Matrix(25, MatrixSortFlows)
				_ = ix.Matrix(0, MatrixSortBytes)
				_ = ix.Stats()
			}
		}()
	}
	wg.Wait()
	ix.Sync()

	st := ix.Stats()
	if st.Pairs > 32 {
		t.Errorf("Pairs = %d, exceeds the cap under concurrency", st.Pairs)
	}
	m := ix.Matrix(0, MatrixSortFlows)
	if len(m.Pairs) != st.Pairs {
		t.Errorf("matrix returned %d pairs, Stats says %d tracked", len(m.Pairs), st.Pairs)
	}
	if st.PairsEvicted > 0 && !m.Partial {
		t.Error("pairs were evicted but the matrix does not report itself partial")
	}
}

// The fold must stay allocation-free per record: it runs on the aggregator, which
// trails the packet path and must not become the bottleneck (PROJECT.md §22).
func TestMatrixObserveDoesNotAllocate(t *testing.T) {
	tbl := newPairTable(DefaultMaxPairs)
	fr, cl := rec(1, "10.0.0.1", 1234, "10.0.0.2", 443, "tcp", base, 100, 200, "normal", 0, false)
	ob := observationOf(&fr, &cl)
	tbl.observe(ob) // create the cell outside the measurement
	if got := testing.AllocsPerRun(1000, func() { tbl.observe(ob) }); got != 0 {
		t.Errorf("pairTable.observe allocates %.1f times per call, want 0", got)
	}
}

// BenchmarkPairObserve is the steady-state per-record cost of the matrix fold on
// an existing cell: the number ADR 0026 quotes.
func BenchmarkPairObserve(b *testing.B) {
	tbl := newPairTable(DefaultMaxPairs)
	obs := make([]observation, 256)
	for i := range obs {
		fr, cl := rec(uint64(i), fmt.Sprintf("10.60.0.%d", i%64), 1234,
			fmt.Sprintf("10.61.0.%d", i%32), uint16(i%512), "tcp",
			base.Add(time.Duration(i)*time.Millisecond), 100, 200, "normal", 0, i%9 == 0)
		obs[i] = observationOf(&fr, &cl)
		tbl.observe(obs[i]) // warm the cells so this measures the hit path
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.observe(obs[i%len(obs)])
	}
}

// BenchmarkPairObserveWithEviction is the pessimal case: every record is a new
// pair, so the table prunes every max/2 inserts. It is what a /16 sweep costs.
func BenchmarkPairObserveWithEviction(b *testing.B) {
	tbl := newPairTable(1024)
	obs := make([]observation, 4096)
	for i := range obs {
		fr, cl := rec(uint64(i), "10.62.0.1", 1234,
			fmt.Sprintf("10.63.%d.%d", i/256, i%256), 80, "tcp",
			base.Add(time.Duration(i)*time.Millisecond), 100, 200, "scan", 1, false)
		obs[i] = observationOf(&fr, &cl)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.observe(obs[i%len(obs)])
	}
}

// BenchmarkMatrixRead is the API-side materialisation, which holds the read lock.
func BenchmarkMatrixRead(b *testing.B) {
	ix := New(Options{QueueSize: 1 << 20})
	defer ix.Close() //nolint:errcheck
	for i := 0; i < 4000; i++ {
		fr, cl := rec(uint64(i), fmt.Sprintf("10.64.%d.%d", i/256, i%256), 1234,
			fmt.Sprintf("10.65.0.%d", i%32), 443, "tcp",
			base.Add(time.Duration(i)*time.Millisecond), 100, 200, "normal", 0, false)
		ix.Observe(&fr, &cl)
	}
	ix.Sync()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ix.Matrix(200, MatrixSortFlows)
	}
}
