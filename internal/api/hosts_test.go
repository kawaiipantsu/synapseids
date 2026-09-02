package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/insight"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

var hostBase = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// investigateServer wires a store and an insight index seeded with the same
// records, which is what the daemon does: the pipeline writes both.
//
//	10.0.0.5  → 10.0.0.9:443  ×3  normal
//	10.0.0.5  → 10.0.0.9:80   ×1  scan, disagreeing, score 0.55
//	10.0.0.6  → 10.0.0.9:443  ×1  normal
func investigateServer(t *testing.T) http.Handler {
	t.Helper()
	store := storage.NewMem(200, 200)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })

	put := func(id uint64, src string, sport uint16, dst string, dport uint16, at time.Time,
		class string, classID int, score float64, disagree bool,
	) {
		fr := storage.FlowRecord{
			ID: id, Proto: "tcp",
			InitiatorIP: src, InitiatorPort: sport,
			ResponderIP: dst, ResponderPort: dport,
			FirstSeen: at.Add(-time.Second), LastSeen: at,
			FwdPackets: 4, BwdPackets: 3, FwdBytes: 400, BwdBytes: 300,
			CloseReason: "fin_rst",
		}
		cl := storage.Classification{
			FlowID: id, TS: at, Proto: "tcp",
			InitiatorIP: src, InitiatorPort: sport,
			ResponderIP: dst, ResponderPort: dport,
			Result: inference.Result{
				FlowID: id, Class: class, ClassID: classID, Score: score, Disagreement: disagree,
				Models: []inference.ModelOutput{{ModelID: "heuristic-v1", Class: class, ClassID: classID, Score: score}},
			},
		}
		store.PutFlow(fr)
		store.PutClassification(cl)
		ix.Observe(&fr, &cl)
	}

	for i := 0; i < 3; i++ {
		put(uint64(i+1), "10.0.0.5", 40000+uint16(i), "10.0.0.9", 443,
			hostBase.Add(time.Duration(i)*time.Second), "normal", 0, 0.95, false)
	}
	put(4, "10.0.0.5", 41000, "10.0.0.9", 80, hostBase.Add(10*time.Second), "scan", 1, 0.55, true)
	put(5, "10.0.0.6", 42000, "10.0.0.9", 443, hostBase.Add(20*time.Second), "normal", 0, 0.90, false)

	ix.Sync()
	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	return New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, ix, nil, nil, nil, nil).Handler()
}

func get(t *testing.T, h http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", url, nil))
	return rr
}

func decode[T any](t *testing.T, rr *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("bad JSON: %v (body %s)", err, rr.Body.String())
	}
	return v
}

func TestHostsList(t *testing.T) {
	h := investigateServer(t)

	rr := get(t, h, "/api/v1/hosts")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	hosts := decode[[]insight.Profile](t, rr)
	if len(hosts) != 3 {
		t.Fatalf("want 3 hosts (10.0.0.5, .6, .9), got %d: %+v", len(hosts), hosts)
	}
	// Default order is newest-active first: 10.0.0.9 and 10.0.0.6 both last saw
	// traffic at +20s; 10.0.0.5 stopped at +10s.
	if hosts[len(hosts)-1].IP != "10.0.0.5" {
		t.Errorf("default sort should put the stalest host last, got %q", hosts[len(hosts)-1].IP)
	}

	// sort=flows puts the server that saw every flow on top.
	hosts = decode[[]insight.Profile](t, get(t, h, "/api/v1/hosts?sort=flows"))
	if hosts[0].IP != "10.0.0.9" || hosts[0].Flows != 5 {
		t.Errorf("sort=flows top = %+v, want 10.0.0.9 with 5 flows", hosts[0])
	}

	// q= substring filter.
	hosts = decode[[]insight.Profile](t, get(t, h, "/api/v1/hosts?q=0.0.5"))
	if len(hosts) != 1 || hosts[0].IP != "10.0.0.5" {
		t.Errorf("q=0.0.5 returned %+v", hosts)
	}

	// limit.
	if got := decode[[]insight.Profile](t, get(t, h, "/api/v1/hosts?limit=1")); len(got) != 1 {
		t.Errorf("limit=1 returned %d rows", len(got))
	}

	// sort= validation.
	if rr := get(t, h, "/api/v1/hosts?sort=bogus"); rr.Code != http.StatusBadRequest {
		t.Errorf("sort=bogus should be 400, got %d", rr.Code)
	}
}

func TestHostProfile(t *testing.T) {
	h := investigateServer(t)

	rr := get(t, h, "/api/v1/hosts/10.0.0.5")
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rr.Code, rr.Body.String())
	}
	p := decode[insight.Profile](t, rr)
	if p.IP != "10.0.0.5" || p.Flows != 4 || p.FlowsInitiated != 4 {
		t.Errorf("profile = %+v", p)
	}
	if p.Disagreements != 1 {
		t.Errorf("Disagreements = %d, want 1", p.Disagreements)
	}
	if !p.FirstSeen.Equal(hostBase.Add(-time.Second)) || !p.LastSeen.Equal(hostBase.Add(10*time.Second)) {
		t.Errorf("first/last seen = %v / %v", p.FirstSeen, p.LastSeen)
	}
	if len(p.TopPeers) != 1 || p.TopPeers[0].IP != "10.0.0.9" {
		t.Errorf("TopPeers = %+v", p.TopPeers)
	}
	if len(p.RecentFlows) != 4 {
		t.Errorf("RecentFlows = %+v", p.RecentFlows)
	}
	if p.BaselineAvailable || p.AnomalyAvailable {
		t.Error("baseline/anomaly must be advertised as unavailable, not faked")
	}
}

func TestHostBadAddressAndUnknown(t *testing.T) {
	h := investigateServer(t)

	for _, bad := range []string{"nope", "10.0.0.256", "example.com", "10.0.0.1%2Ffoo", "%3Cscript%3E"} {
		for _, suffix := range []string{"", "/flows", "/classifications", "/similar"} {
			rr := get(t, h, "/api/v1/hosts/"+bad+suffix)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("GET /api/v1/hosts/%s%s = %d, want 400", bad, suffix, rr.Code)
			}
		}
	}
	// Well-formed but never observed.
	if rr := get(t, h, "/api/v1/hosts/203.0.113.7"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown host = %d, want 404", rr.Code)
	}
	// A valid address with no records is an empty list, not a 404, on the
	// sub-collections.
	if rr := get(t, h, "/api/v1/hosts/203.0.113.7/flows"); rr.Code != http.StatusOK {
		t.Errorf("unknown host flows = %d, want 200 with an empty list", rr.Code)
	}
}

func TestHostSimilar(t *testing.T) {
	h := investigateServer(t)

	type simResp struct {
		IP          string `json:"ip"`
		Fingerprint struct {
			IP        string `json:"ip"`
			FlowCount uint64 `json:"flow_count"`
			Vector    []float64
			Dims      []struct {
				Name  string
				Value float64
			}
		}
		Dims     []string
		MinFlows int `json:"min_flows"`
		Similar  []struct {
			IP        string
			Cosine    float64
			FlowCount uint64 `json:"flow_count"`
		}
		Method string
	}

	rr := get(t, h, "/api/v1/hosts/10.0.0.5/similar?min_flows=1")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	got := decode[simResp](t, rr)
	if got.Fingerprint.IP != "10.0.0.5" || len(got.Fingerprint.Vector) == 0 {
		t.Fatalf("fingerprint = %+v", got.Fingerprint)
	}
	if len(got.Fingerprint.Vector) != len(got.Dims) || len(got.Fingerprint.Dims) != len(got.Dims) {
		t.Fatalf("vector/dims length mismatch: %d/%d/%d", len(got.Fingerprint.Vector), len(got.Fingerprint.Dims), len(got.Dims))
	}
	// The other two tracked hosts (10.0.0.6 = 1 flow, 10.0.0.9 = 5 flows) are
	// neighbours with min_flows=1; the query host is never among them; the list
	// is cosine-descending.
	seen := map[string]bool{}
	for i, s := range got.Similar {
		if s.IP == "10.0.0.5" {
			t.Fatalf("query host listed as its own neighbour: %+v", got.Similar)
		}
		if s.Cosine < -1 || s.Cosine > 1 {
			t.Fatalf("cosine out of range: %v", s.Cosine)
		}
		if i > 0 && s.Cosine > got.Similar[i-1].Cosine {
			t.Fatalf("neighbours not cosine-descending: %+v", got.Similar)
		}
		seen[s.IP] = true
	}
	if !seen["10.0.0.6"] || !seen["10.0.0.9"] {
		t.Fatalf("expected 10.0.0.6 and 10.0.0.9 among neighbours: %+v", got.Similar)
	}
	if got.Method == "" {
		t.Error("response must carry the method disclaimer (not a learned embedding)")
	}

	// The default min_flows (5) filters out the single-flow 10.0.0.6 but keeps
	// the 5-flow 10.0.0.9.
	got2 := decode[simResp](t, get(t, h, "/api/v1/hosts/10.0.0.5/similar"))
	if len(got2.Similar) != 1 || got2.Similar[0].IP != "10.0.0.9" {
		t.Fatalf("default min_flows: want just 10.0.0.9, got %+v", got2.Similar)
	}

	// Bad address → 400; unknown host → 404.
	if rr := get(t, h, "/api/v1/hosts/nope/similar"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad addr = %d, want 400", rr.Code)
	}
	if rr := get(t, h, "/api/v1/hosts/203.0.113.7/similar"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown host = %d, want 404", rr.Code)
	}
}

func TestHostFlowsFilters(t *testing.T) {
	h := investigateServer(t)

	all := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows"))
	if len(all) != 4 {
		t.Fatalf("want 4 flows for 10.0.0.5, got %d", len(all))
	}
	if all[0].ID != 4 {
		t.Errorf("flows must be newest-first, got first ID %d", all[0].ID)
	}

	// Classification predicates are honoured by joining flow → verdict.
	scan := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?class=scan"))
	if len(scan) != 1 || scan[0].ID != 4 {
		t.Errorf("class=scan = %+v, want flow 4 only", scan)
	}
	dis := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?disagreement=true"))
	if len(dis) != 1 || dis[0].ID != 4 {
		t.Errorf("disagreement=true = %+v", dis)
	}
	conf := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?min_confidence=0.9"))
	if len(conf) != 3 {
		t.Errorf("min_confidence=0.9 returned %d flows, want 3", len(conf))
	}
	mdl := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?model=heuristic-v1"))
	if len(mdl) != 4 {
		t.Errorf("model=heuristic-v1 returned %d flows, want 4", len(mdl))
	}
	if got := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?model=nope")); len(got) != 0 {
		t.Errorf("model=nope returned %d flows", len(got))
	}
	if got := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.5/flows?limit=2")); len(got) != 2 {
		t.Errorf("limit=2 returned %d flows", len(got))
	}

	// A host only ever seen as responder still matches.
	if got := decode[[]storage.FlowRecord](t, get(t, h, "/api/v1/hosts/10.0.0.9/flows")); len(got) != 5 {
		t.Errorf("responder-side match returned %d flows, want 5", len(got))
	}

	// The shared 400s.
	for _, q := range []string{"?class=bogus", "?min_confidence=abc", "?from=yesterday", "?to=nope",
		"?from=2026-03-01T13:00:00Z&to=2026-03-01T12:00:00Z"} {
		if rr := get(t, h, "/api/v1/hosts/10.0.0.5/flows"+q); rr.Code != http.StatusBadRequest {
			t.Errorf("flows%s = %d, want 400", q, rr.Code)
		}
	}
}

func TestHostFlowsTimeRange(t *testing.T) {
	h := investigateServer(t)

	// Only the +10s scan flow falls in this window.
	got := decode[[]storage.FlowRecord](t, get(t, h,
		"/api/v1/hosts/10.0.0.5/flows?from=2026-03-01T12:00:05Z&to=2026-03-01T12:00:15Z"))
	if len(got) != 1 || got[0].ID != 4 {
		t.Errorf("time-ranged flows = %+v, want flow 4 only", got)
	}
	// Same window on the classification route.
	cls := decode[[]storage.Classification](t, get(t, h,
		"/api/v1/hosts/10.0.0.5/classifications?from=2026-03-01T12:00:05Z&to=2026-03-01T12:00:15Z"))
	if len(cls) != 1 || cls[0].FlowID != 4 {
		t.Errorf("time-ranged classifications = %+v", cls)
	}
}

func TestHostClassifications(t *testing.T) {
	h := investigateServer(t)

	all := decode[[]storage.Classification](t, get(t, h, "/api/v1/hosts/10.0.0.5/classifications"))
	if len(all) != 4 || all[0].FlowID != 4 {
		t.Fatalf("want 4 newest-first verdicts, got %+v", all)
	}
	scan := decode[[]storage.Classification](t, get(t, h, "/api/v1/hosts/10.0.0.5/classifications?class=scan"))
	if len(scan) != 1 || scan[0].Result.Class != "scan" {
		t.Errorf("class=scan = %+v", scan)
	}
	// 10.0.0.6 never talked to 10.0.0.5.
	if got := decode[[]storage.Classification](t, get(t, h, "/api/v1/hosts/10.0.0.6/classifications")); len(got) != 1 {
		t.Errorf("10.0.0.6 verdicts = %d, want 1", len(got))
	}
	if rr := get(t, h, "/api/v1/hosts/10.0.0.5/classifications?class=bogus"); rr.Code != http.StatusBadRequest {
		t.Errorf("class=bogus = %d, want 400", rr.Code)
	}
}

// An IPv6 address (including a v4-mapped spelling) canonicalises to the same
// profile key the aggregator stored.
func TestHostAddressCanonicalisation(t *testing.T) {
	store := storage.NewMem(50, 50)
	ix := insight.New(insight.Options{})
	t.Cleanup(func() { _ = ix.Close() })
	fr := storage.FlowRecord{
		ID: 1, Proto: "tcp", InitiatorIP: "2001:db8::1", InitiatorPort: 1234,
		ResponderIP: "10.0.0.1", ResponderPort: 443,
		FirstSeen: hostBase, LastSeen: hostBase, CloseReason: "fin_rst",
	}
	cl := storage.Classification{FlowID: 1, TS: hostBase, InitiatorIP: "2001:db8::1", ResponderIP: "10.0.0.1"}
	store.PutFlow(fr)
	store.PutClassification(cl)
	ix.Observe(&fr, &cl)
	ix.Sync()

	rt := inference.NewRuntime(inference.NewHeuristic("heuristic-v1", inference.RolePrimary))
	h := New(config.Default(), events.New(), store, rt, nil, nil, nil, nil, nil, nil, ix, nil, nil, nil, nil).Handler()

	for _, spelling := range []string{"2001:db8::1", "2001:0db8:0000::0001"} {
		if rr := get(t, h, "/api/v1/hosts/"+spelling); rr.Code != http.StatusOK {
			t.Errorf("GET /api/v1/hosts/%s = %d, want 200", spelling, rr.Code)
		}
	}
	// A v4-mapped spelling of the responder resolves to the plain v4 profile.
	if rr := get(t, h, "/api/v1/hosts/::ffff:10.0.0.1"); rr.Code != http.StatusOK {
		t.Errorf("v4-mapped lookup = %d, want 200", rr.Code)
	}
}

// With no index wired the routes degrade rather than panic.
func TestHostRoutesWithoutIndex(t *testing.T) {
	h := seededServer(t)
	if rr := get(t, h, "/api/v1/hosts"); rr.Code != http.StatusOK {
		t.Errorf("hosts without an index = %d, want 200", rr.Code)
	}
	if rr := get(t, h, "/api/v1/hosts/10.0.0.1"); rr.Code != http.StatusNotFound {
		t.Errorf("host without an index = %d, want 404", rr.Code)
	}
	if rr := get(t, h, "/api/v1/hosts/10.0.0.1/similar"); rr.Code != http.StatusNotFound {
		t.Errorf("similar without an index = %d, want 404", rr.Code)
	}
	if rr := get(t, h, "/api/v1/timeline"); rr.Code != http.StatusOK {
		t.Errorf("timeline without an index = %d, want 200", rr.Code)
	}
}
