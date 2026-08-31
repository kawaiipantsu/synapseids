package api

// GET /api/v1/matrix (issue #68) and the sensor= / location= scope shared with
// the flow and classification lists (issue #46).
//
// Every read here is preceded by insight.Index.Sync(), which queues a barrier
// behind the observations already sent and returns only once the aggregator has
// drained past it. There is no sleep and no poll: the wait cannot be satisfied
// before the folds it is waiting for have happened.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var mxBase = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

// matrixServer seeds a store and an insight index with a small but realistic
// conversation set, and wires a sensor provider so the location scope resolves.
//
//	10.1.0.5 → 10.1.0.9:3306  ×6  brute_force   sensor "dmz-1"
//	10.1.0.5 → 10.1.0.9:443   ×2  normal        sensor "dmz-1"
//	10.1.0.9 → 10.1.0.5:80    ×1  normal        sensor "dmz-1"  (reverse pair)
//	10.1.0.7 → 10.1.0.9:22    ×3  normal        sensor "wan-1"
//	10.1.0.8 → 10.1.0.9:80    ×1  scan          sensor "local"
//
// That is 13 flows over **4** pairs, not 5: a matrix cell is a host pair, so the
// first two lines are the same cell (8 flows, a mixed class bar) and only the
// third is a distinct, opposite-direction cell.
func matrixServer(t *testing.T) http.Handler {
	t.Helper()
	store := storage.NewMem(500, 500)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })

	var next uint64
	put := func(src string, sport uint16, dst string, dport uint16, at time.Time,
		class string, classID int, sensor string, fwd, bwd uint64,
	) {
		next++
		fr := storage.FlowRecord{
			ID: next, Proto: "tcp",
			InitiatorIP: src, InitiatorPort: sport,
			ResponderIP: dst, ResponderPort: dport,
			FirstSeen: at.Add(-time.Second), LastSeen: at,
			FwdPackets: 4, BwdPackets: 3, FwdBytes: fwd, BwdBytes: bwd,
			CloseReason: "fin_rst",
		}
		cl := storage.Classification{
			FlowID: next, TS: at, Sensor: sensor, Proto: "tcp",
			InitiatorIP: src, InitiatorPort: sport,
			ResponderIP: dst, ResponderPort: dport,
			Result: inference.Result{
				FlowID: next, Class: class, ClassID: classID, Score: 0.9,
				Models: []inference.ModelOutput{{ModelID: "heuristic-v1", Class: class, ClassID: classID, Score: 0.9}},
			},
		}
		store.PutFlow(fr)
		store.PutClassification(cl)
		ix.Observe(&fr, &cl)
	}

	for i := 0; i < 6; i++ {
		put("10.1.0.5", 40000+uint16(i), "10.1.0.9", 3306,
			mxBase.Add(time.Duration(i)*time.Second), "brute_force", 3, "dmz-1", 100, 200)
	}
	for i := 0; i < 2; i++ {
		put("10.1.0.5", 41000+uint16(i), "10.1.0.9", 443,
			mxBase.Add(time.Duration(30+i)*time.Second), "normal", 0, "dmz-1", 5000, 9000)
	}
	put("10.1.0.9", 51000, "10.1.0.5", 80, mxBase.Add(time.Minute), "normal", 0, "dmz-1", 10, 20)
	for i := 0; i < 3; i++ {
		put("10.1.0.7", 42000+uint16(i), "10.1.0.9", 22,
			mxBase.Add(time.Duration(70+i)*time.Second), "normal", 0, "wan-1", 300, 400)
	}
	put("10.1.0.8", 43000, "10.1.0.9", 80, mxBase.Add(2*time.Minute), "scan", 1, "local", 60, 0)

	ix.Sync()

	sp := fakeSensors{rows: []capture.SensorStatus{
		{SensorID: "dmz-1", Location: "dmz", State: capture.StateRunning, Mode: "flow"},
		{SensorID: "wan-1", Location: "wan", State: capture.StateRunning, Mode: "flow"},
		{SensorID: "raw-1", Location: "wan", State: capture.StateRunning, Mode: "raw"},
	}}
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	return New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, ix, nil, sp, nil, nil).Handler()
}

func TestMatrixUnfilteredComesFromTheIncrementalTable(t *testing.T) {
	h := matrixServer(t)
	rr := get(t, h, "/api/v1/matrix?limit=100")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	m := decode[insight.Matrix](t, rr)

	if m.Source != "incremental" {
		t.Errorf("source = %q, want incremental for an unfiltered query", m.Source)
	}
	if m.Scanned != 0 {
		t.Errorf("scanned = %d on the incremental path, want 0", m.Scanned)
	}
	if m.Sort != insight.MatrixSortFlows {
		t.Errorf("sort = %q, want the flows default", m.Sort)
	}
	if m.PairCap != insight.DefaultMaxPairs {
		t.Errorf("pair_cap = %d, want %d", m.PairCap, insight.DefaultMaxPairs)
	}
	if m.Partial || m.Truncated {
		t.Errorf("a small complete matrix must be neither partial nor truncated: %+v", m)
	}
	// Three forward host pairs plus the one reverse pair. The two ports between
	// 10.1.0.5 and 10.1.0.9 share a cell — a matrix is host×host, not port×port.
	if m.TrackedPairs != 4 || len(m.Pairs) != 4 {
		t.Fatalf("tracked %d / returned %d pairs, want 4: %+v", m.TrackedPairs, len(m.Pairs), m.Pairs)
	}
	if m.TotalFlows != 13 {
		t.Errorf("total_flows = %d, want 13", m.TotalFlows)
	}

	// The brute-force conversation is the heaviest by flow count, so it leads and
	// sets the heat scale.
	top := m.Pairs[0]
	if top.Initiator != "10.1.0.5" || top.Responder != "10.1.0.9" {
		t.Fatalf("hottest pair = %s→%s, want 10.1.0.5→10.1.0.9", top.Initiator, top.Responder)
	}
	if top.Flows != 8 {
		t.Errorf("hottest pair flows = %d, want 8 (6 brute_force + 2 normal)", top.Flows)
	}
	if top.ThreatClass != "brute_force" || top.ThreatCount != 6 {
		t.Errorf("hottest pair threat = %q×%d, want brute_force×6", top.ThreatClass, top.ThreatCount)
	}
	if m.MaxFlows != 8 {
		t.Errorf("max_flows = %d, want 8", m.MaxFlows)
	}

	// Direction is preserved: the reverse pair exists separately with 1 flow.
	var reverse *insight.MatrixPair
	for i := range m.Pairs {
		if m.Pairs[i].Initiator == "10.1.0.9" && m.Pairs[i].Responder == "10.1.0.5" {
			reverse = &m.Pairs[i]
		}
	}
	if reverse == nil {
		t.Fatal("the reverse pair 10.1.0.9→10.1.0.5 was merged into the forward one")
	}
	if reverse.Flows != 1 {
		t.Errorf("reverse pair flows = %d, want 1", reverse.Flows)
	}

	// Axes: 10.1.0.9 is a responder on 3 of the 4 pairs and an initiator on 1.
	if len(m.Responders) == 0 || m.Responders[0].IP != "10.1.0.9" || m.Responders[0].Pairs != 3 {
		t.Errorf("responder axis head = %+v, want 10.1.0.9 over 3 pairs", m.Responders)
	}
	if len(m.Initiators) != 4 {
		t.Errorf("initiator axis = %+v, want 4 distinct initiators", m.Initiators)
	}
}

func TestMatrixSortAndLimit(t *testing.T) {
	h := matrixServer(t)

	// sort=bytes promotes the 443 conversation (2 × 14000 B) over the 3306 one
	// (6 × 300 B), which sort=flows ranks first.
	m := decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?sort=bytes"))
	if m.Sort != insight.MatrixSortBytes {
		t.Errorf("sort = %q, want bytes", m.Sort)
	}
	if m.Pairs[0].Bytes != m.MaxBytes {
		t.Errorf("sort=bytes head is not the heaviest: %d vs max %d", m.Pairs[0].Bytes, m.MaxBytes)
	}

	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?sort=last_seen"))
	if len(m.Pairs) < 2 || m.Pairs[0].LastSeen.Before(m.Pairs[1].LastSeen) {
		t.Errorf("sort=last_seen is not newest-first: %+v", m.Pairs)
	}

	// limit truncates and says so, without claiming the data is partial.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?limit=2"))
	if len(m.Pairs) != 2 || !m.Truncated || m.Partial {
		t.Errorf("limit=2 → %d pairs truncated=%v partial=%v", len(m.Pairs), m.Truncated, m.Partial)
	}
	if m.TrackedPairs != 4 || m.ReturnedPairs != 2 {
		t.Errorf("tracked %d returned %d, want 4 and 2", m.TrackedPairs, m.ReturnedPairs)
	}
}

func TestMatrixClassFilterSwitchesToTheScanSource(t *testing.T) {
	h := matrixServer(t)

	m := decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?class=brute_force"))
	if m.Source != "scan" {
		t.Errorf("source = %q, want scan for a filtered query", m.Source)
	}
	if m.Scanned == 0 {
		t.Error("scanned = 0 on the scan path")
	}
	if len(m.Pairs) != 1 {
		t.Fatalf("class=brute_force → %d pairs, want 1: %+v", len(m.Pairs), m.Pairs)
	}
	if m.Pairs[0].Responder != "10.1.0.9" || m.Pairs[0].Flows != 6 {
		t.Errorf("class=brute_force pair = %+v, want 6 flows to 10.1.0.9", m.Pairs[0])
	}
	// Only the filtered endpoints appear on the axes.
	if len(m.Initiators) != 1 || m.Initiators[0].IP != "10.1.0.5" {
		t.Errorf("filtered initiator axis = %+v", m.Initiators)
	}

	// class=scan narrows to a different single pair.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?class=scan"))
	if len(m.Pairs) != 1 || m.Pairs[0].Initiator != "10.1.0.8" {
		t.Errorf("class=scan → %+v, want just 10.1.0.8", m.Pairs)
	}

	// A filter that excludes everything is an empty matrix, not an error.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?class=web_attack"))
	if len(m.Pairs) != 0 || m.Pairs == nil {
		t.Errorf("class=web_attack → %+v, want an empty non-nil pair list", m.Pairs)
	}
}

func TestMatrixTimeRangeAndOtherFilters(t *testing.T) {
	h := matrixServer(t)

	// from/to alone forces the scan source, because the incremental table has no
	// time dimension.
	from := mxBase.Add(50 * time.Second).Format(time.RFC3339)
	to := mxBase.Add(80 * time.Second).Format(time.RFC3339)
	m := decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?from="+from+"&to="+to))
	if m.Source != "scan" {
		t.Errorf("source = %q, want scan when from/to are set", m.Source)
	}
	// That window holds the reverse pair (t+60) and the 22/tcp pairs (t+70..72).
	if m.TotalFlows != 4 {
		t.Errorf("windowed total_flows = %d, want 4: %+v", m.TotalFlows, m.Pairs)
	}

	// min_confidence and model are accepted and applied.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?model=heuristic-v1"))
	if m.TotalFlows != 13 {
		t.Errorf("model=heuristic-v1 total_flows = %d, want all 13", m.TotalFlows)
	}
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?model=nope"))
	if len(m.Pairs) != 0 {
		t.Errorf("model=nope → %+v, want empty", m.Pairs)
	}
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?min_confidence=0.95"))
	if len(m.Pairs) != 0 {
		t.Errorf("min_confidence=0.95 → %+v, want empty (every score is 0.9)", m.Pairs)
	}
	// disagreement=true: nothing in this fixture disagrees.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?disagreement=true"))
	if len(m.Pairs) != 0 {
		t.Errorf("disagreement=true → %+v, want empty", m.Pairs)
	}
}

// The sensor scope: what the topology view clicks through to.
func TestMatrixSensorAndLocationScope(t *testing.T) {
	h := matrixServer(t)

	// sensor=dmz-1 keeps the dmz conversations: 9 flows over 2 cells (the 3306 and
	// 443 traffic share one, the reverse flow is the other).
	m := decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?sensor=dmz-1"))
	if m.Source != "scan" {
		t.Errorf("source = %q, want scan", m.Source)
	}
	if len(m.Pairs) != 2 || m.TotalFlows != 9 {
		t.Errorf("sensor=dmz-1 → %d pairs / %d flows, want 2 / 9: %+v",
			len(m.Pairs), m.TotalFlows, m.Pairs)
	}

	// location=dmz resolves through the connected sensors to the same rows.
	byLoc := decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?location=dmz"))
	if len(byLoc.Pairs) != 2 || byLoc.TotalFlows != 9 {
		t.Errorf("location=dmz → %d pairs / %d flows, want 2 / 9", len(byLoc.Pairs), byLoc.TotalFlows)
	}

	// location=wan covers wan-1 (attributable) and raw-1 (not). Only wan-1's rows
	// exist, so the answer is wan-1's three 22/tcp flows — and that is exactly the
	// half-truth topology's flow_attribution warns about.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?location=wan"))
	if len(m.Pairs) != 1 || m.Pairs[0].Initiator != "10.1.0.7" || m.Pairs[0].Flows != 3 {
		t.Errorf("location=wan → %+v, want 10.1.0.7 with 3 flows", m.Pairs)
	}

	// sensor=local is a legitimate scope: locally-built rows carry that label.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?sensor="+LocalSensorLabel))
	if len(m.Pairs) != 1 || m.Pairs[0].Initiator != "10.1.0.8" {
		t.Errorf("sensor=local → %+v, want the 10.1.0.8 scan", m.Pairs)
	}

	// sensor= and location= together intersect rather than union.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?location=dmz&sensor=wan-1"))
	if len(m.Pairs) != 0 {
		t.Errorf("location=dmz&sensor=wan-1 → %+v, want empty (an empty intersection)", m.Pairs)
	}

	// A sensor nobody ever tagged is an empty matrix, not an error: it may simply
	// have produced nothing yet.
	m = decode[insight.Matrix](t, get(t, h, "/api/v1/matrix?sensor=ghost"))
	if len(m.Pairs) != 0 {
		t.Errorf("sensor=ghost → %+v, want empty", m.Pairs)
	}
}

// An unresolvable location is a 400, so a client cannot mistake "no such
// location" for "that location is quiet".
func TestMatrixErrorCodes(t *testing.T) {
	h := matrixServer(t)

	for _, tc := range []struct {
		url  string
		code int
		why  string
	}{
		{"/api/v1/matrix?sort=packets", http.StatusBadRequest, "unknown sort"},
		{"/api/v1/matrix?sort=Flows", http.StatusBadRequest, "sort is case-sensitive"},
		{"/api/v1/matrix?class=nope", http.StatusBadRequest, "unknown class"},
		{"/api/v1/matrix?min_confidence=abc", http.StatusBadRequest, "unparseable min_confidence"},
		{"/api/v1/matrix?min_confidence=-1", http.StatusBadRequest, "negative min_confidence"},
		{"/api/v1/matrix?from=yesterday", http.StatusBadRequest, "non-RFC3339 from"},
		{"/api/v1/matrix?from=2026-04-01T10:00:00Z&to=2026-04-01T09:00:00Z", http.StatusBadRequest, "to before from"},
		{"/api/v1/matrix?location=atlantis", http.StatusBadRequest, "no sensor reports that location"},
		{"/api/v1/matrix", http.StatusOK, "no params is fine"},
		{"/api/v1/matrix?sort=", http.StatusOK, "an empty sort is the default"},
		{"/api/v1/matrix?limit=0", http.StatusOK, "a bad limit falls back to the default"},
	} {
		rr := get(t, h, tc.url)
		if rr.Code != tc.code {
			t.Errorf("%s (%s) → %d, want %d (%s)", tc.url, tc.why, rr.Code, tc.code, rr.Body.String())
		}
	}
}

// location= must also be rejected when there is no collector at all, rather than
// silently matching nothing.
func TestLocationScopeWithoutCollector(t *testing.T) {
	rr := httptest.NewRecorder()
	sensorHandler(nil).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/api/v1/matrix?location=dmz", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("location= with no collector → %d, want 400", rr.Code)
	}
}

// The same scope vocabulary must work on the flow and classification lists —
// that is what makes clicking a sensor in the topology view mean something.
func TestSensorScopeOnFlowAndClassificationLists(t *testing.T) {
	h := matrixServer(t)

	// Unscoped: every flow.
	all := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/flows?limit=500"))
	if len(all) != 13 {
		t.Fatalf("unscoped /flows returned %d, want 13", len(all))
	}

	scoped := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/flows?limit=500&sensor=dmz-1"))
	if len(scoped) != 9 {
		t.Errorf("/flows?sensor=dmz-1 returned %d, want 9", len(scoped))
	}
	byLoc := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/flows?limit=500&location=wan"))
	if len(byLoc) != 3 {
		t.Errorf("/flows?location=wan returned %d, want 3", len(byLoc))
	}
	if rr := get(t, h, "/api/v1/flows?location=atlantis"); rr.Code != http.StatusBadRequest {
		t.Errorf("/flows?location=atlantis → %d, want 400", rr.Code)
	}
	// /flows takes the scope but not the classification predicates, and it must
	// not validate what it would then ignore: an unknown class= is not its error
	// to report. Pins the boundary between parseSensorScope and parseClassFilters.
	if rr := get(t, h, "/api/v1/flows?class=nope"); rr.Code != http.StatusOK {
		t.Errorf("/flows?class=nope → %d, want 200 (the param is not part of this route)", rr.Code)
	}

	cls := decode[[]storage.Classification](t, get(t, h, "/api/v1/classifications?limit=500&sensor=wan-1"))
	if len(cls) != 3 {
		t.Errorf("/classifications?sensor=wan-1 returned %d, want 3", len(cls))
	}
	for _, c := range cls {
		if c.Sensor != "wan-1" {
			t.Errorf("scoped classification carries sensor %q", c.Sensor)
		}
	}
	clsLoc := decode[[]storage.Classification](t, get(t, h, "/api/v1/classifications?limit=500&location=dmz"))
	if len(clsLoc) != 9 {
		t.Errorf("/classifications?location=dmz returned %d, want 9", len(clsLoc))
	}
	// Scope composes with the existing predicates rather than replacing them.
	both := decode[[]storage.Classification](t,
		get(t, h, "/api/v1/classifications?limit=500&location=dmz&class=brute_force"))
	if len(both) != 6 {
		t.Errorf("location=dmz&class=brute_force returned %d, want 6", len(both))
	}
}

// /api/v1/status must surface the matrix counters, like every other bounded
// structure in the daemon (PROJECT.md §24).
func TestStatusReportsMatrixCounters(t *testing.T) {
	h := matrixServer(t)
	st := decode[map[string]any](t, get(t, h, "/api/v1/status"))
	ins, ok := st["insight"].(map[string]any)
	if !ok {
		t.Fatalf("status has no insight block: %v", st["insight"])
	}
	for _, k := range []string{"pairs", "pair_cap", "pairs_evicted"} {
		if _, ok := ins[k]; !ok {
			t.Errorf("status.insight is missing %q", k)
		}
	}
	if n, _ := ins["pairs"].(float64); int(n) != 4 {
		t.Errorf("status.insight.pairs = %v, want 4", ins["pairs"])
	}
	if n, _ := ins["pair_cap"].(float64); int(n) != insight.DefaultMaxPairs {
		t.Errorf("status.insight.pair_cap = %v, want %d", ins["pair_cap"], insight.DefaultMaxPairs)
	}
}

// A nil insight index must not turn the route into a 500.
func TestMatrixWithoutInsight(t *testing.T) {
	rr := httptest.NewRecorder()
	sensorHandler(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/matrix", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	m := decode[insight.Matrix](t, rr)
	if len(m.Pairs) != 0 || m.Pairs == nil {
		t.Errorf("nil-insight matrix = %+v, want an empty non-nil pair list", m.Pairs)
	}
	if m.Initiators == nil || m.Responders == nil {
		t.Error("axes must serialise as [] rather than null")
	}
}
