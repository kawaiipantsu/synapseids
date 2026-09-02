package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiipantsu/synapseids/internal/config"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

func writeTokens(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// authServer builds a Server with the given auth config wired.
func authServer(t *testing.T, a config.Auth) http.Handler {
	t.Helper()
	srv := New(config.Default(), events.New(), storage.NewMem(100, 100),
		inference.NewRuntime(inference.NewHeuristic("h", inference.RolePrimary)),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err := srv.SetAuth(a); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	return srv.Handler()
}

func req(method, path, token, remote string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	return r
}

const tokenFile = `
# comment
viewer   view-abcdefgh
operator op-abcdefgh   runs replays
admin    admin-abcdefgh
`

func TestLoadTokens(t *testing.T) {
	ts, err := loadTokens(writeTokens(t, tokenFile))
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if len(ts) != 3 {
		t.Fatalf("loaded %d tokens, want 3", len(ts))
	}
	if r, ok := ts.lookup("op-abcdefgh"); !ok || r != RoleOperator {
		t.Errorf("op token → %v/%v, want operator/true", r, ok)
	}
	if _, ok := ts.lookup("not-a-token"); ok {
		t.Error("unknown token resolved")
	}
	if _, ok := ts.lookup(""); ok {
		t.Error("empty token resolved")
	}
}

func TestLoadTokensRejects(t *testing.T) {
	bad := map[string]string{
		"unknown role":    "superuser tok-abcdefgh",
		"missing token":   "viewer",
		"short token":     "viewer abc",
		"duplicate token": "viewer dup-abcdefgh\nadmin dup-abcdefgh",
		"empty file":      "# nothing here\n",
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTokens(writeTokens(t, body)); err == nil {
				t.Errorf("loadTokens accepted a bad file (%s)", name)
			}
		})
	}
	if _, err := loadTokens(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("loadTokens accepted a missing file")
	}
}

func TestRequiredRole(t *testing.T) {
	cases := []struct {
		method, path string
		want         Role
	}{
		{"GET", "/api/v1/status", RoleViewer},
		{"GET", "/api/v1/detections", RoleViewer},
		{"GET", "/metrics", RoleViewer},
		{"GET", "/", roleNone},
		{"GET", "/assets/index-abc.js", roleNone},
		{"POST", "/api/v1/replay", RoleOperator},
		{"POST", "/api/v1/replay/stop", RoleOperator},
		{"POST", "/api/v1/captures", RoleOperator},
		{"DELETE", "/api/v1/captures/wan", RoleOperator},
		{"POST", "/api/v1/architecture/estimate", RoleViewer},
		{"POST", "/api/v1/models/x/activate", RoleAdmin},
		{"POST", "/api/v1/datasets", RoleAdmin},
		{"DELETE", "/api/v1/datasets/x@1", RoleAdmin},
		{"PUT", "/api/v1/review/42", RoleAdmin},
		{"POST", "/api/v1/training", RoleAdmin},
	}
	for _, c := range cases {
		if got := requiredRole(c.method, c.path); got != c.want {
			t.Errorf("requiredRole(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestAuthDisabledIsPassthrough(t *testing.T) {
	h := authServer(t, config.Auth{Enabled: false})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req("POST", "/api/v1/models/x/activate", "", "203.0.113.9:5555"))
	// No auth wired: the route runs and returns its own status (not 401/403).
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("disabled auth blocked a request (%d)", rr.Code)
	}
}

func TestAuthEnforcement(t *testing.T) {
	tf := writeTokens(t, tokenFile)
	h := authServer(t, config.Auth{Enabled: true, TokensFile: tf, AllowLoopback: false})

	type tc struct {
		name         string
		method, path string
		token        string
		// blocked: expect 401/403. Otherwise: expect anything else (the handler
		// ran — this test server has nil rc/reg so some routes 503, which is
		// still "authz let it through").
		blocked bool
	}
	remote := "203.0.113.9:5555"
	for _, c := range []tc{
		{"no token", "GET", "/api/v1/status", "", true},
		{"bad token", "GET", "/api/v1/status", "wrong-token", true},
		{"viewer reads", "GET", "/api/v1/status", "view-abcdefgh", false},
		{"viewer cannot replay", "POST", "/api/v1/replay/stop", "view-abcdefgh", true},
		{"operator can replay", "POST", "/api/v1/replay/stop", "op-abcdefgh", false},
		{"operator cannot activate", "POST", "/api/v1/models/x/activate", "op-abcdefgh", true},
		{"admin can activate", "POST", "/api/v1/models/x/activate", "admin-abcdefgh", false},
		{"static stays open", "GET", "/", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req(c.method, c.path, c.token, remote))
			denied := rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden
			if denied != c.blocked {
				t.Errorf("%s %s → %d, blocked=%v want blocked=%v (%s)",
					c.method, c.path, rr.Code, denied, c.blocked, rr.Body.String())
			}
		})
	}
}

func TestAuthLoopbackBypass(t *testing.T) {
	tf := writeTokens(t, tokenFile)
	h := authServer(t, config.Auth{Enabled: true, TokensFile: tf, AllowLoopback: true})

	// Loopback + no token: an admin route runs (404), not blocked.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req("POST", "/api/v1/models/x/activate", "", "127.0.0.1:40000"))
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("allow_loopback did not exempt 127.0.0.1 (%d)", rr.Code)
	}

	// Same request from off-box still needs a token.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req("POST", "/api/v1/models/x/activate", "", "198.51.100.7:1234"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("off-box request without a token → %d, want 401", rr.Code)
	}
}

func TestAuthStreamTokenQueryParam(t *testing.T) {
	tf := writeTokens(t, tokenFile)
	h := authServer(t, config.Auth{Enabled: true, TokensFile: tf, AllowLoopback: false})

	// The WebSocket route accepts ?token= (a browser cannot set the header).
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req("GET", "/api/v1/stream?token=view-abcdefgh", "", "203.0.113.9:5555"))
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("?token= not accepted on /api/v1/stream (%d)", rr.Code)
	}

	// It is NOT accepted anywhere else.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req("GET", "/api/v1/status?token=view-abcdefgh", "", "203.0.113.9:5555"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("?token= accepted on a non-stream route → %d, want 401", rr.Code)
	}
}

// A malformed WWW-Authenticate-less 401 body must still be JSON with an error.
func TestAuthErrorBodies(t *testing.T) {
	tf := writeTokens(t, tokenFile)
	h := authServer(t, config.Auth{Enabled: true, TokensFile: tf, AllowLoopback: false})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req("GET", "/api/v1/status", "", "203.0.113.9:5555"))
	if !strings.Contains(rr.Body.String(), `"error"`) {
		t.Errorf("401 body is not a JSON error: %s", rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 without a WWW-Authenticate header")
	}
}
