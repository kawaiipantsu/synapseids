package insight

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var base = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// rec builds one classified flow record for the aggregator.
func rec(id uint64, initiator string, iport uint16, responder string, rport uint16,
	proto string, at time.Time, fwdB, bwdB uint64, class string, classID int, disagree bool,
) (storage.FlowRecord, storage.Classification) {
	fr := storage.FlowRecord{
		ID: id, Proto: proto,
		InitiatorIP: initiator, InitiatorPort: iport,
		ResponderIP: responder, ResponderPort: rport,
		FirstSeen: at.Add(-time.Second), LastSeen: at,
		FwdPackets: 3, BwdPackets: 2, FwdBytes: fwdB, BwdBytes: bwdB,
		CloseReason: "fin_rst",
	}
	cl := storage.Classification{
		FlowID: id, TS: at, Proto: proto,
		InitiatorIP: initiator, InitiatorPort: iport,
		ResponderIP: responder, ResponderPort: rport,
		Result: inference.Result{
			FlowID: id, Class: class, ClassID: classID, Score: 0.9, Disagreement: disagree,
		},
	}
	return fr, cl
}

func feed(ix *Index, fr storage.FlowRecord, cl storage.Classification) {
	ix.Observe(&fr, &cl)
}

// withAnomaly attaches an anomaly verdict to a classification.
func withAnomaly(cl storage.Classification, score float64, exceeds bool) storage.Classification {
	cl.Result.Anomaly = &inference.AnomalyResult{
		Available: true, ModelID: "ae-test", Score: score, ReconError: score, Exceeds: exceeds,
	}
	return cl
}

func TestTimelineAndProfileFoldAnomalyScores(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	// Three flows for one host at the same second, two of them scored by an
	// anomaly model (one over threshold).
	fr1, cl1 := rec(1, "10.0.0.5", 40001, "10.0.0.9", 443, "tcp", base, 100, 200, "normal", 0, false)
	feed(ix, fr1, withAnomaly(cl1, 0.2, false))
	fr2, cl2 := rec(2, "10.0.0.5", 40002, "10.0.0.9", 443, "tcp", base, 100, 200, "normal", 0, false)
	feed(ix, fr2, withAnomaly(cl2, 0.8, true))
	fr3, cl3 := rec(3, "10.0.0.5", 40003, "10.0.0.9", 443, "tcp", base, 100, 200, "normal", 0, false)
	feed(ix, fr3, cl3) // no anomaly model scored this one
	ix.Sync()

	ser := ix.Timeline(1, time.Time{}, time.Time{})
	if !ser.AnomalyAvailable {
		t.Fatal("Timeline.AnomalyAvailable = false with anomaly-scored flows")
	}
	var n uint32
	var sawExceeds uint32
	var maxSeen float64
	for _, b := range ser.Buckets {
		n += b.AnomalyN
		sawExceeds += b.AnomalyExceeds
		if b.AnomalyMax > maxSeen {
			maxSeen = b.AnomalyMax
		}
	}
	if n != 2 || sawExceeds != 1 || maxSeen != 0.8 {
		t.Fatalf("bucket anomaly totals: n=%d exceeds=%d max=%v", n, sawExceeds, maxSeen)
	}

	p, ok := ix.Host("10.0.0.5")
	if !ok {
		t.Fatal("host not found")
	}
	if !p.AnomalyAvailable || p.AnomalyFlows != 2 || p.AnomalyExceeded != 1 {
		t.Fatalf("profile anomaly = %+v", p)
	}
	if got := p.AnomalyMean; got < 0.49 || got > 0.51 { // (0.2 + 0.8) / 2
		t.Fatalf("AnomalyMean = %v, want ~0.5", got)
	}
	if p.AnomalyMax != 0.8 {
		t.Fatalf("AnomalyMax = %v, want 0.8", p.AnomalyMax)
	}
}

func TestProfileAccumulates(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck // always nil

	// 10.0.0.5 initiates three flows to two peers, and answers one.
	for i := 0; i < 3; i++ {
		fr, cl := rec(uint64(i+1), "10.0.0.5", 40000+uint16(i), "10.0.0.9", 443,
			"tcp", base.Add(time.Duration(i)*time.Second), 100, 200, "normal", 0, false)
		feed(ix, fr, cl)
	}
	fr, cl := rec(4, "10.0.0.5", 51000, "10.0.0.10", 80, "tcp", base.Add(3*time.Second),
		10, 20, "web_attack", 5, true)
	feed(ix, fr, cl)
	fr, cl = rec(5, "10.0.0.99", 33333, "10.0.0.5", 22, "tcp", base.Add(4*time.Second),
		7, 11, "brute_force", 3, false)
	feed(ix, fr, cl)
	ix.Sync()

	p, ok := ix.Host("10.0.0.5")
	if !ok {
		t.Fatal("10.0.0.5 not tracked")
	}
	if p.Flows != 5 {
		t.Errorf("Flows = %d, want 5", p.Flows)
	}
	if p.FlowsInitiated != 4 || p.FlowsResponded != 1 {
		t.Errorf("initiated/responded = %d/%d, want 4/1", p.FlowsInitiated, p.FlowsResponded)
	}
	// As initiator: out = fwd, in = bwd (3×100+10 out, 3×200+20 in).
	// As responder on flow 5: out = bwd (11), in = fwd (7).
	if want := uint64(3*100 + 10 + 11); p.BytesOut != want {
		t.Errorf("BytesOut = %d, want %d", p.BytesOut, want)
	}
	if want := uint64(3*200 + 20 + 7); p.BytesIn != want {
		t.Errorf("BytesIn = %d, want %d", p.BytesIn, want)
	}
	if !p.FirstSeen.Equal(base.Add(-time.Second)) {
		t.Errorf("FirstSeen = %v, want %v", p.FirstSeen, base.Add(-time.Second))
	}
	if !p.LastSeen.Equal(base.Add(4 * time.Second)) {
		t.Errorf("LastSeen = %v", p.LastSeen)
	}
	if p.Disagreements != 1 {
		t.Errorf("Disagreements = %d, want 1", p.Disagreements)
	}
	if p.Classifications != 5 {
		t.Errorf("Classifications = %d, want 5", p.Classifications)
	}

	// Class mix.
	got := map[string]uint64{}
	for _, c := range p.Classes {
		got[c.Class] = c.Count
	}
	for class, want := range map[string]uint64{"normal": 3, "web_attack": 1, "brute_force": 1} {
		if got[class] != want {
			t.Errorf("class %s = %d, want %d", class, got[class], want)
		}
	}

	// Top ports: the conversation's service port. 443 three times, then 80, 22.
	if len(p.TopPorts) != 3 || p.TopPorts[0].Port != 443 || p.TopPorts[0].Flows != 3 {
		t.Errorf("TopPorts = %+v", p.TopPorts)
	}
	// Top peers.
	if len(p.TopPeers) != 3 || p.TopPeers[0].IP != "10.0.0.9" || p.TopPeers[0].Flows != 3 {
		t.Errorf("TopPeers = %+v", p.TopPeers)
	}
	if len(p.Protocols) != 1 || p.Protocols[0].Proto != "tcp" || p.Protocols[0].Flows != 5 {
		t.Errorf("Protocols = %+v", p.Protocols)
	}
	if len(p.RecentFlows) != 5 || p.RecentFlows[0].FlowID != 5 {
		t.Errorf("RecentFlows = %+v", p.RecentFlows)
	}
	// Phase 7 fields must stay off rather than be faked.
	if p.BaselineAvailable || p.AnomalyAvailable {
		t.Error("baseline/anomaly must be reported unavailable in Phase 5")
	}

	// The peer side is tracked too, with the directions mirrored.
	q, ok := ix.Host("10.0.0.9")
	if !ok {
		t.Fatal("peer 10.0.0.9 not tracked")
	}
	if q.FlowsResponded != 3 || q.BytesIn != 300 || q.BytesOut != 600 {
		t.Errorf("peer profile = %+v", q)
	}
}

// A periodic mid-flow snapshot carries cumulative counters, so it must not add
// to the flow count or the byte totals — but its verdict still counts, matching
// /api/v1/classifications.
func TestSnapshotRecordsDoNotDoubleCountVolume(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	fr, cl := rec(1, "10.0.0.1", 1234, "10.0.0.2", 80, "tcp", base, 500, 900, "normal", 0, false)
	fr.CloseReason = "snapshot"
	fr.FwdBytes, fr.BwdBytes = 200, 300
	feed(ix, fr, cl)

	fr2, cl2 := rec(1, "10.0.0.1", 1234, "10.0.0.2", 80, "tcp", base.Add(time.Minute), 500, 900, "normal", 0, false)
	feed(ix, fr2, cl2)
	ix.Sync()

	p, _ := ix.Host("10.0.0.1")
	if p.Flows != 1 {
		t.Errorf("Flows = %d, want 1 (snapshot must not add a flow)", p.Flows)
	}
	if p.BytesOut != 500 || p.BytesIn != 900 {
		t.Errorf("bytes = out %d / in %d, want 500/900", p.BytesOut, p.BytesIn)
	}
	if p.Classifications != 2 {
		t.Errorf("Classifications = %d, want 2 (a snapshot verdict is a verdict)", p.Classifications)
	}
}

func TestHostCapEvictsLeastRecentlyActive(t *testing.T) {
	const cap = 40
	ix := New(Options{MaxHosts: cap})
	defer ix.Close() //nolint:errcheck

	// 400 distinct initiators, increasing timestamps, all talking to one server.
	for i := 0; i < 400; i++ {
		fr, cl := rec(uint64(i+1), fmt.Sprintf("10.1.%d.%d", i/256, i%256), 5000, "10.9.9.9", 443,
			"tcp", base.Add(time.Duration(i)*time.Second), 10, 10, "normal", 0, false)
		feed(ix, fr, cl)
	}
	ix.Sync()

	st := ix.Stats()
	if st.Hosts > cap {
		t.Errorf("Hosts = %d, exceeds cap %d", st.Hosts, cap)
	}
	if st.HostsEvicted == 0 {
		t.Error("HostsEvicted = 0, want the eviction counter to move")
	}
	if st.HostCap != cap {
		t.Errorf("HostCap = %d, want %d", st.HostCap, cap)
	}
	// The newest initiator must have survived; the very first must not have.
	if _, ok := ix.Host("10.1.1.143"); !ok { // i == 399
		t.Error("most recently active host was evicted")
	}
	if _, ok := ix.Host("10.1.0.0"); ok { // i == 0
		t.Error("least recently active host survived 400 inserts into a 40-host cap")
	}
	// The busy server is touched by every flow, so it must never be evicted.
	if _, ok := ix.Host("10.9.9.9"); !ok {
		t.Error("continuously active host was evicted")
	}
}

func TestTopNBoundedAndOrdered(t *testing.T) {
	const keys = 16
	ix := New(Options{MaxKeys: keys})
	defer ix.Close() //nolint:errcheck

	// A scan: 2000 distinct one-hit ports, plus one heavy hitter on 443.
	var id uint64
	for port := 1; port <= 2000; port++ {
		id++
		fr, cl := rec(id, "10.0.0.7", 40000, "10.0.0.8", uint16(port), "tcp",
			base.Add(time.Duration(id)*time.Millisecond), 1, 1, "scan", 1, false)
		feed(ix, fr, cl)
	}
	for i := 0; i < 50; i++ {
		id++
		fr, cl := rec(id, "10.0.0.7", 40000, "10.0.0.8", 443, "tcp",
			base.Add(time.Duration(id)*time.Millisecond), 1, 1, "normal", 0, false)
		feed(ix, fr, cl)
	}
	ix.Sync()

	p, _ := ix.Host("10.0.0.7")
	if len(p.TopPorts) > 16 {
		t.Errorf("TopPorts len = %d, want <= 16", len(p.TopPorts))
	}
	// The heavy hitter must survive the pruning and lead the list.
	if len(p.TopPorts) == 0 || p.TopPorts[0].Port != 443 {
		t.Errorf("TopPorts[0] = %+v, want port 443 to lead", p.TopPorts)
	}
	// 50, not 51: the single early scan hit on 443 was pruned away with the rest
	// of the one-hit tail before the heavy traffic arrived. That is the
	// documented approximation — top-N counts are exact for keys that stay
	// resident, lossy for a long tail.
	if p.TopPorts[0].Flows != 50 {
		t.Errorf("port 443 flows = %d, want 50", p.TopPorts[0].Flows)
	}
	for i := 1; i < len(p.TopPorts); i++ {
		if p.TopPorts[i-1].Flows < p.TopPorts[i].Flows {
			t.Errorf("TopPorts not count-descending at %d: %+v", i, p.TopPorts)
		}
	}
	if ix.Stats().KeysPruned == 0 {
		t.Error("KeysPruned = 0, want the top-N pruning to be counted")
	}
	// The exact counters are never pruned, only the top-N key sets.
	if p.Flows != 2050 {
		t.Errorf("Flows = %d, want 2050 — pruning must not lose the totals", p.Flows)
	}
	// The recent-flow ring stays bounded too.
	if len(p.RecentFlows) > DefaultRecentFlows {
		t.Errorf("RecentFlows len = %d, want <= %d", len(p.RecentFlows), DefaultRecentFlows)
	}
}

func TestTimelineBucketingAcrossBoundary(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	// Second 0: two normal. Second 1: one scan (disagreeing). Second 2: nothing.
	// Second 3: one normal. Then an out-of-order sample back in second 0.
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	samples := []struct {
		off      time.Duration
		class    string
		id       int
		disagree bool
	}{
		{0, "normal", 0, false},
		{500 * time.Millisecond, "normal", 0, false},
		{1 * time.Second, "scan", 1, true},
		{3 * time.Second, "normal", 0, false},
		{100 * time.Millisecond, "scan", 1, false}, // out of order, back into second 0
	}
	for i, s := range samples {
		fr, cl := rec(uint64(i+1), "10.0.0.1", 1000, "10.0.0.2", 80, "tcp",
			at.Add(s.off), 1, 1, s.class, s.id, s.disagree)
		feed(ix, fr, cl)
	}
	ix.Sync()

	ser := ix.Timeline(1, at, at.Add(3*time.Second))
	if ser.BucketSec != 1 {
		t.Fatalf("BucketSec = %d", ser.BucketSec)
	}
	if len(ser.Buckets) != 4 {
		t.Fatalf("got %d buckets, want 4 (dense over the range): %+v", len(ser.Buckets), ser.Buckets)
	}
	want := []struct {
		total    uint32
		normal   uint32
		scan     uint32
		disagree uint32
	}{
		{3, 2, 1, 0}, // the late sample landed back in second 0
		{1, 0, 1, 1},
		{0, 0, 0, 0}, // gap is emitted as an explicit zero bucket
		{1, 1, 0, 0},
	}
	for i, b := range ser.Buckets {
		if !b.TS.Equal(at.Add(time.Duration(i) * time.Second)) {
			t.Errorf("bucket %d ts = %v, want %v", i, b.TS, at.Add(time.Duration(i)*time.Second))
		}
		if b.Total != want[i].total || b.ByClass["normal"] != want[i].normal ||
			b.ByClass["scan"] != want[i].scan || b.Disagreements != want[i].disagree {
			t.Errorf("bucket %d = total %d by_class %v disagree %d, want %+v",
				i, b.Total, b.ByClass, b.Disagreements, want[i])
		}
	}
	if ser.AnomalyAvailable {
		t.Error("AnomalyAvailable must be false until Phase 7")
	}

	// A 10s bucket folds all of it into one slice.
	ten := ix.Timeline(10, time.Time{}, time.Time{})
	if len(ten.Buckets) != 1 || ten.Buckets[0].Total != 5 {
		t.Errorf("10s series = %+v", ten.Buckets)
	}
	if ix.Stats().TimelineLate != 0 {
		t.Errorf("TimelineLate = %d, want 0 — a same-window reorder is not late", ix.Stats().TimelineLate)
	}
}

// A sample older than the ring's whole window cannot be represented; it must be
// counted, not silently folded into the wrong bucket.
func TestTimelineTooOldIsCounted(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	fr, cl := rec(1, "10.0.0.1", 1, "10.0.0.2", 80, "tcp", base, 1, 1, "normal", 0, false)
	feed(ix, fr, cl)
	fr, cl = rec(2, "10.0.0.1", 1, "10.0.0.2", 80, "tcp", base.Add(-48*time.Hour), 1, 1, "normal", 0, false)
	feed(ix, fr, cl)
	ix.Sync()

	if ix.Stats().TimelineLate == 0 {
		t.Error("TimelineLate = 0, want a sample older than every ring window to be counted")
	}
	ser := ix.Timeline(1, time.Time{}, time.Time{})
	var total uint32
	for _, b := range ser.Buckets {
		total += b.Total
	}
	if total != 1 {
		t.Errorf("1s series total = %d, want 1", total)
	}
}

func TestHostsSortAndFilter(t *testing.T) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck

	// 10.0.0.1: many small flows, oldest. 10.0.0.2: few big flows, newest.
	for i := 0; i < 10; i++ {
		fr, cl := rec(uint64(i+1), "10.0.0.1", 1000, "192.168.1.1", 80, "tcp",
			base.Add(time.Duration(i)*time.Second), 10, 10, "normal", 0, false)
		feed(ix, fr, cl)
	}
	fr, cl := rec(100, "10.0.0.2", 1000, "192.168.1.1", 80, "tcp",
		base.Add(time.Hour), 1_000_000, 1_000_000, "normal", 0, false)
	feed(ix, fr, cl)
	ix.Sync()

	if got := ix.Hosts("", SortFlows, 1); len(got) != 1 || got[0].IP != "192.168.1.1" {
		t.Errorf("SortFlows top = %+v, want the 11-flow server", got)
	}
	if got := ix.Hosts("10.0.0.", SortFlows, 10); len(got) != 2 || got[0].IP != "10.0.0.1" {
		t.Errorf("SortFlows filtered = %+v", got)
	}
	if got := ix.Hosts("10.0.0.", SortBytes, 10); len(got) != 2 || got[0].IP != "10.0.0.2" {
		t.Errorf("SortBytes = %+v", got)
	}
	if got := ix.Hosts("10.0.0.", SortLastSeen, 10); len(got) != 2 || got[0].IP != "10.0.0.2" {
		t.Errorf("SortLastSeen = %+v", got)
	}
	if got := ix.Hosts("nope", SortFlows, 10); len(got) != 0 {
		t.Errorf("q=nope returned %+v", got)
	}
	// The list view is shallow: no peers, no recent flows.
	list := ix.Hosts("10.0.0.1", SortFlows, 10)
	if len(list) != 1 || list[0].TopPeers != nil || list[0].RecentFlows != nil {
		t.Errorf("list profile should be shallow: %+v", list)
	}
}

// The important one: the packet path and the API must be able to run flat out
// against each other without a data race. Run under -race.
func TestConcurrentIngestAndRead(t *testing.T) {
	ix := New(Options{MaxHosts: 64, MaxKeys: 16, QueueSize: 256})
	defer ix.Close() //nolint:errcheck

	const writers, reads, perWriter = 4, 2000, 3000
	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				fr, cl := rec(uint64(w*perWriter+i),
					fmt.Sprintf("10.2.%d.%d", w, i%251), uint16(1024+i%1000),
					fmt.Sprintf("10.3.%d.%d", i%7, i%13), uint16(i%2048),
					[]string{"tcp", "udp", "icmp"}[i%3],
					base.Add(time.Duration(i)*time.Millisecond),
					uint64(i), uint64(i*2),
					[]string{"normal", "scan", "suspicious"}[i%3], []int{0, 1, 6}[i%3],
					i%17 == 0)
				ix.Observe(&fr, &cl)
			}
		}(w)
	}
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < reads; i++ {
				for _, p := range ix.Hosts("10.2.", SortBytes, 25) {
					_, _ = ix.Host(p.IP)
				}
				_ = ix.Timeline(1, time.Time{}, time.Time{})
				_ = ix.Timeline(60, time.Time{}, time.Time{})
				_ = ix.Stats()
			}
		}()
	}
	wg.Wait()
	ix.Sync()

	st := ix.Stats()
	if st.Hosts > 64 {
		t.Errorf("Hosts = %d, exceeds the cap under concurrency", st.Hosts)
	}
	if st.Observed+st.Dropped != writers*perWriter {
		t.Errorf("observed %d + dropped %d != %d offered", st.Observed, st.Dropped, writers*perWriter)
	}
}

// Observe must be cheap and allocation-free: it runs on the packet-processing
// goroutine (PROJECT.md §22).
func TestObserveDoesNotAllocate(t *testing.T) {
	ix := New(Options{QueueSize: 1 << 16})
	defer ix.Close() //nolint:errcheck

	fr, cl := rec(1, "10.0.0.1", 1234, "10.0.0.2", 443, "tcp", base, 100, 200, "normal", 0, false)
	got := testing.AllocsPerRun(1000, func() { ix.Observe(&fr, &cl) })
	if got != 0 {
		t.Errorf("Observe allocates %.1f times per call, want 0", got)
	}
}

// Close must stop the aggregator; a later Observe is a counted drop, not a panic
// or a send on a closed channel.
func TestCloseIsIdempotentAndObserveStaysSafe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ix := New(Options{QueueSize: 2})
		if err := ix.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := ix.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		fr, cl := rec(1, "10.0.0.1", 1, "10.0.0.2", 2, "tcp", base, 1, 1, "normal", 0, false)
		for i := 0; i < 10; i++ {
			ix.Observe(&fr, &cl)
		}
		ix.Sync() // must return rather than block on a stopped aggregator
		if ix.Stats().Dropped == 0 {
			t.Error("Dropped = 0, want sends past a full queue to be counted")
		}
	})
}

func TestNilIndexIsSafe(t *testing.T) {
	var ix *Index
	fr, cl := rec(1, "10.0.0.1", 1, "10.0.0.2", 2, "tcp", base, 1, 1, "normal", 0, false)
	ix.Observe(&fr, &cl)
	ix.Sync()
	if got := ix.Hosts("", SortFlows, 10); len(got) != 0 {
		t.Errorf("Hosts on a nil Index = %+v", got)
	}
	if _, ok := ix.Host("10.0.0.1"); ok {
		t.Error("Host on a nil Index returned a profile")
	}
	if s := ix.Timeline(1, time.Time{}, time.Time{}); len(s.Buckets) != 0 {
		t.Errorf("Timeline on a nil Index = %+v", s)
	}
	if ix.Stats() != (Stats{}) {
		t.Error("Stats on a nil Index is not zero")
	}
}

func TestParseParams(t *testing.T) {
	for in, want := range map[string]int{"": 1, "1s": 1, "10s": 10, "1m": 60, "60s": 60} {
		if got, ok := ParseBucket(in); !ok || got != want {
			t.Errorf("ParseBucket(%q) = %d,%v, want %d,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"5s", "2m", "1h", "0", "abc", "1S"} {
		if _, ok := ParseBucket(bad); ok {
			t.Errorf("ParseBucket(%q) accepted", bad)
		}
	}
	if !ValidBucketSec(10) || ValidBucketSec(7) {
		t.Error("ValidBucketSec is wrong")
	}
	if got, ok := ParseSort(""); !ok || got != SortLastSeen {
		t.Errorf("ParseSort(\"\") = %q,%v", got, ok)
	}
	if _, ok := ParseSort("name"); ok {
		t.Error("ParseSort accepted an unknown ordering")
	}
	if ClassName(0) != "normal" || ClassName(99) != "" || ClassName(-1) != "" {
		t.Errorf("ClassName is wrong: %q", ClassName(0))
	}
}

func TestBucketSamplesScoped(t *testing.T) {
	var rows []storage.Classification
	for i := 0; i < 6; i++ {
		_, cl := rec(uint64(i), "10.0.0.1", 1, "10.0.0.2", 80, "tcp",
			base.Add(time.Duration(i)*time.Second), 1, 1, "normal", 0, false)
		if i%2 == 1 {
			cl.InitiatorIP = "10.0.0.3"
		}
		rows = append(rows, cl)
	}
	s := BucketSamples(rows, 10, time.Time{}, time.Time{}, func(c storage.Classification) bool {
		return c.InitiatorIP == "10.0.0.1"
	})
	if len(s.Buckets) != 1 || s.Buckets[0].Total != 3 {
		t.Errorf("scoped series = %+v", s.Buckets)
	}
	if s.AnomalyAvailable {
		t.Error("AnomalyAvailable must be false")
	}
	// A range that excludes everything yields an empty, non-nil series.
	empty := BucketSamples(rows, 1, base.Add(time.Hour), base.Add(2*time.Hour), nil)
	if empty.Buckets == nil || len(empty.Buckets) != 0 {
		t.Errorf("out-of-range series = %+v", empty.Buckets)
	}
}

func BenchmarkObserve(b *testing.B) {
	ix := New(Options{QueueSize: 1 << 20})
	defer ix.Close() //nolint:errcheck
	fr, cl := rec(1, "10.0.0.1", 1234, "10.0.0.2", 443, "tcp", base, 100, 200, "normal", 0, false)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ix.Observe(&fr, &cl)
	}
}

// BenchmarkApply measures the aggregator's real per-record fold, which is the
// work Observe hands off.
func BenchmarkApply(b *testing.B) {
	ix := New(Options{})
	defer ix.Close() //nolint:errcheck
	obs := make([]observation, 256)
	for i := range obs {
		fr, cl := rec(uint64(i), fmt.Sprintf("10.4.0.%d", i%64), 1234,
			fmt.Sprintf("10.5.0.%d", i%32), uint16(i%512), "tcp",
			base.Add(time.Duration(i)*time.Millisecond), 100, 200, "normal", 0, i%9 == 0)
		ix.Observe(&fr, &cl)
		obs[i] = observation{
			flowID: fr.ID, terminal: true, proto: fr.Proto,
			initiatorIP: fr.InitiatorIP, initiatorPort: fr.InitiatorPort,
			responderIP: fr.ResponderIP, responderPort: fr.ResponderPort,
			firstSeen: fr.FirstSeen, lastSeen: fr.LastSeen, ts: cl.TS,
			packetsFwd: fr.FwdPackets, packetsBwd: fr.BwdPackets,
			bytesFwd: fr.FwdBytes, bytesBwd: fr.BwdBytes,
			classID: cl.Result.ClassID, disagreement: cl.Result.Disagreement,
		}
	}
	ix.Sync()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.apply(obs[i%len(obs)])
	}
}
