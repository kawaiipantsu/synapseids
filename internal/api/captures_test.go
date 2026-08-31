package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

type stubCaptures struct{ rows []capture.SourceStatus }

func (s stubCaptures) List() []capture.SourceStatus { return s.rows }

func (s stubCaptures) Get(name string) (capture.SourceStatus, bool) {
	for _, r := range s.rows {
		if r.Name == name {
			return r, true
		}
	}
	return capture.SourceStatus{}, false
}

// The GET-only tests never exercise these; the mutating routes are covered
// against a real *capture.Manager below.
func (s stubCaptures) Add(string, capture.Source, capture.SourceMeta) error { return nil }
func (s stubCaptures) Remove(string) bool                                   { return false }

func serverWithCaptures(cp CaptureStatusProvider) http.Handler {
	return New(config.Default(), events.New(), storage.NewMem(100, 100),
		inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, nil, nil, nil, cp, nil).Handler()
}

// serverWithManager wires a real, idle capture.Manager into the API so the
// POST / DELETE routes run their real path (validation → capturewire.Build →
// Manager.Add/Remove). The manager is never started, so Add just registers the
// source and its status reads back as "stopped".
func serverWithManager() http.Handler {
	m := capture.NewManager()
	h := New(config.Default(), events.New(), storage.NewMem(100, 100),
		inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, nil, nil, nil, m, nil).Handler()
	return h
}

func writeTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "poip.tok")
	if err := os.WriteFile(p, []byte("s3cr3t-bearer-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("content-type", "application/json")
	}
	h.ServeHTTP(rr, r)
	return rr
}

func TestCaptureCreateAndDelete(t *testing.T) {
	h := serverWithManager()
	tok := writeTokenFile(t)
	body := `{"name":"hq","kind":"pcap-over-ip","addr":"127.0.0.1:4789","token_file":` + strconv.Quote(tok) + `}`

	rr := doJSON(t, h, "POST", "/api/v1/captures", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST code %d, body %s", rr.Code, rr.Body.String())
	}
	var created capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("POST body: %v (%s)", err, rr.Body.String())
	}
	if created.Name != "hq" || created.Kind != "pcap-over-ip" || created.Origin != "api" {
		t.Fatalf("created = %+v", created)
	}

	rr = doJSON(t, h, "GET", "/api/v1/captures", "")
	var list []capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Name != "hq" {
		t.Fatalf("GET list = %s (%v)", rr.Body.String(), err)
	}

	rr = doJSON(t, h, "GET", "/api/v1/captures/hq", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET by-name code %d", rr.Code)
	}

	rr = doJSON(t, h, "DELETE", "/api/v1/captures/hq", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE code %d, body %s", rr.Code, rr.Body.String())
	}

	rr = doJSON(t, h, "GET", "/api/v1/captures/hq", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET after DELETE code %d, want 404", rr.Code)
	}
	rr = doJSON(t, h, "GET", "/api/v1/captures", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || len(list) != 0 {
		t.Fatalf("list after DELETE = %s", rr.Body.String())
	}
}

func TestCaptureCreateValidationRejections(t *testing.T) {
	h := serverWithManager()
	cases := map[string]struct {
		body string
		want int
		frag string
	}{
		"bad json":           {`{`, http.StatusBadRequest, "bad request body"},
		"unknown field":      {`{"name":"x","kind":"nic","interface":"lo","bogus":1}`, http.StatusBadRequest, ""},
		"ssh not authorized": {`{"name":"edge","kind":"ssh","destination":"h","interface":"eth0"}`, http.StatusBadRequest, `"authorized": true`},
		"inline token":       {`{"name":"hq","kind":"pcap-over-ip","addr":"127.0.0.1:1","token":"abc"}`, http.StatusBadRequest, "inline token"},
		"unknown kind":       {`{"name":"x","kind":"tap","interface":"lo"}`, http.StatusBadRequest, "unknown kind"},
		"nic no interface":   {`{"name":"x","kind":"nic"}`, http.StatusBadRequest, "interface is required"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rr := doJSON(t, h, "POST", "/api/v1/captures", c.body)
			if rr.Code != c.want {
				t.Fatalf("code %d, want %d (body %s)", rr.Code, c.want, rr.Body.String())
			}
			if c.frag != "" && !strings.Contains(rr.Body.String(), c.frag) {
				t.Fatalf("body %q missing %q", rr.Body.String(), c.frag)
			}
		})
	}
}

func TestCaptureCreateDuplicate(t *testing.T) {
	h := serverWithManager()
	tok := writeTokenFile(t)
	body := `{"name":"hq","kind":"pcap-over-ip","addr":"127.0.0.1:4789","token_file":` + strconv.Quote(tok) + `}`
	if rr := doJSON(t, h, "POST", "/api/v1/captures", body); rr.Code != http.StatusCreated {
		t.Fatalf("first POST code %d", rr.Code)
	}
	if rr := doJSON(t, h, "POST", "/api/v1/captures", body); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate POST code %d, want 409", rr.Code)
	}
}

func TestCaptureCreateOpenFailure(t *testing.T) {
	h := serverWithManager()
	// A tcpdump source whose binary is not on PATH: config validation passes,
	// the constructor fails, and a local kind maps to 422.
	body := `{"name":"span","kind":"tcpdump","interface":"lo","binary":"synapse-no-such-binary-xyz"}`
	rr := doJSON(t, h, "POST", "/api/v1/captures", body)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("code %d, want 422 (body %s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "could not be opened") {
		t.Fatalf("body %q missing cause", rr.Body.String())
	}
	if rr := doJSON(t, h, "GET", "/api/v1/captures/span", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("failed source must not be registered, GET code %d", rr.Code)
	}
}

func TestCaptureDeleteUnknown(t *testing.T) {
	h := serverWithManager()
	if rr := doJSON(t, h, "DELETE", "/api/v1/captures/nope", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE unknown code %d, want 404", rr.Code)
	}
}

func TestCaptureCreateWithoutProvider(t *testing.T) {
	h := serverWithCaptures(nil)
	if rr := doJSON(t, h, "POST", "/api/v1/captures", `{"name":"x","kind":"nic","interface":"lo"}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no provider POST code %d, want 503", rr.Code)
	}
}

func TestCapturesEmptyWithoutProvider(t *testing.T) {
	rr := httptest.NewRecorder()
	serverWithCaptures(nil).ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var got []capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not a JSON array: %v (%s)", err, rr.Body.String())
	}
	if len(got) != 0 {
		t.Fatalf("want empty list, got %v", got)
	}
}

func TestCapturesListFields(t *testing.T) {
	row := capture.SourceStatus{
		Name: "eth0", Kind: "nic", State: capture.StateRunning,
		Packets: 10, Decoded: 9, Bytes: 1200, Drops: 3,
		PPS: 5.5, BPS: 660, LastPacket: time.Unix(1700000000, 0).UTC(),
		Filter: "(all)",
	}
	rr := httptest.NewRecorder()
	serverWithCaptures(stubCaptures{rows: []capture.SourceStatus{row}}).
		ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var raw []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 row, got %d", len(raw))
	}
	// PROJECT.md §19.14 fields plus identity.
	for _, k := range []string{
		"name", "kind", "state", "packets", "bytes", "drops",
		"pps", "bps", "last_packet", "filter", "error", "connection_latency_ms",
	} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("row missing field %q: %v", k, raw[0])
		}
	}
}

// TestCapturesShowsTcpdumpAndSSHKinds: the subprocess capture kinds (#29/#30)
// surface through GET /api/v1/captures with their kind and their raw tcpdump
// filter expression, exactly as the Manager reports them.
func TestCapturesShowsTcpdumpAndSSHKinds(t *testing.T) {
	rows := []capture.SourceStatus{
		{Name: "span", Kind: "tcpdump", State: capture.StateRunning, Filter: "tcp port 80 or udp"},
		{Name: "edge", Kind: "ssh", State: capture.StateError, Filter: "not port 22", Error: "ssh: exit 255: Permission denied (publickey)"},
	}
	rr := httptest.NewRecorder()
	serverWithCaptures(stubCaptures{rows: rows}).
		ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var got []capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
	if got[0].Kind != "tcpdump" || got[0].Filter != "tcp port 80 or udp" {
		t.Fatalf("tcpdump row = %+v", got[0])
	}
	if got[1].Kind != "ssh" || got[1].Filter != "not port 22" || got[1].State != capture.StateError {
		t.Fatalf("ssh row = %+v", got[1])
	}
}

func TestCaptureByName(t *testing.T) {
	h := serverWithCaptures(stubCaptures{rows: []capture.SourceStatus{
		{Name: "lo", Kind: "nic", State: capture.StateRunning},
	}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/lo", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("by-name code %d", rr.Code)
	}
	var one capture.SourceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &one); err != nil || one.Name != "lo" {
		t.Fatalf("by-name body = %s (%v)", rr.Body.String(), err)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/missing", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing source should 404, got %d", rr.Code)
	}
}

func TestCaptureByNameWithoutProvider(t *testing.T) {
	rr := httptest.NewRecorder()
	serverWithCaptures(nil).ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures/lo", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("no provider should 404 on by-name, got %d", rr.Code)
	}
}
func TestCapturesShowsPCAPOverIPSource(t *testing.T) {
	row := capture.SourceStatus{
		Name: "hq-sensor", Kind: "pcap-over-ip", State: capture.StateRunning,
		Packets: 512, Decoded: 512, Bytes: 400000,
		Filter: "ip", ConnLatencyMS: 42,
		LastPacket: time.Unix(1700000123, 0).UTC(),
	}
	rr := httptest.NewRecorder()
	serverWithCaptures(stubCaptures{rows: []capture.SourceStatus{row}}).
		ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/captures", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var raw []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 || raw[0]["kind"] != "pcap-over-ip" {
		t.Fatalf("kind not surfaced: %v", raw)
	}
	if raw[0]["connection_latency_ms"].(float64) != 42 {
		t.Fatalf("connection_latency_ms not surfaced: %v", raw[0]["connection_latency_ms"])
	}
	if raw[0]["filter"] != "ip" {
		t.Fatalf("filter not surfaced: %v", raw[0]["filter"])
	}
}
