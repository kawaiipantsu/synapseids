package api

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/kawaiipantsu/synapseids/internal/config"
)

// Role-based access control for the API (issue #58, PROJECT.md §21). When
// config.Auth.Enabled, a request needs a bearer token whose role covers the
// route. Loopback requests are exempt unless allow_loopback is turned off, so
// the local operator CLI and a same-host SPA keep working with no token.
//
// This is authentication + coarse authorisation only. It is not a substitute
// for the documented posture of a loopback bind behind an authenticating TLS
// reverse proxy — it is what protects the daemon when it is exposed directly.

// Role is an access level. Higher covers lower.
type Role int

// The role ladder. roleNone means "no token needed" (static assets); the three
// exported roles are cumulative — RoleOperator covers RoleViewer, and so on.
const (
	roleNone Role = iota
	// RoleViewer may read: every GET route, and GET /metrics.
	RoleViewer
	// RoleOperator adds the capture and replay POST/DELETE routes.
	RoleOperator
	// RoleAdmin adds model activation, dataset/training writes and review writes.
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseRole maps a token-file role word to a Role. ok is false for anything
// else.
func ParseRole(s string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin":
		return RoleAdmin, true
	default:
		return roleNone, false
	}
}

// tokenSet maps sha256(token) → the role that token carries. The digest is the
// key so an attacker who reads process memory or a heap dump does not get a
// usable token, and lookups are constant-time in the token value.
type tokenSet map[[32]byte]Role

// loadTokens parses a token file: one `<role> <token> [label...]` per line,
// blank lines and `#` comments skipped. It rejects an unknown role, an empty or
// duplicate token, and a file with no usable line.
func loadTokens(path string) (tokenSet, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path, same trust as the config file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := make(tokenSet)
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want `<role> <token> [label]`", line)
		}
		role, ok := ParseRole(fields[0])
		if !ok {
			return nil, fmt.Errorf("line %d: unknown role %q (want viewer, operator or admin)", line, fields[0])
		}
		tok := fields[1]
		if len(tok) < 8 {
			return nil, fmt.Errorf("line %d: token is shorter than 8 characters", line)
		}
		sum := sha256.Sum256([]byte(tok))
		if _, dup := out[sum]; dup {
			return nil, fmt.Errorf("line %d: this token is already assigned a role", line)
		}
		out[sum] = role
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no tokens defined")
	}
	return out, nil
}

// lookup returns the role for a presented token, and whether it is known. The
// token is compared as a SHA-256 digest — a fixed-width value, so the map probe
// carries no length signal — and every stored digest is walked with a
// constant-time compare so "unknown token" and "known token" take the same time
// regardless of how early a byte differs.
func (ts tokenSet) lookup(tok string) (Role, bool) {
	if tok == "" {
		return roleNone, false
	}
	sum := sha256.Sum256([]byte(tok))
	role, found := roleNone, false
	for k, v := range ts {
		if subtle.ConstantTimeCompare(k[:], sum[:]) == 1 {
			role, found = v, true
		}
	}
	return role, found
}

// authGuard is the middleware built from config.Auth. A disabled guard is a
// pass-through.
type authGuard struct {
	enabled       bool
	allowLoopback bool
	tokens        tokenSet
}

func newAuthGuard(cfg config.Auth) (*authGuard, error) {
	g := &authGuard{enabled: cfg.Enabled, allowLoopback: cfg.AllowLoopback}
	if !cfg.Enabled {
		return g, nil
	}
	ts, err := loadTokens(cfg.TokensFile)
	if err != nil {
		return nil, fmt.Errorf("tokens_file %q: %w", cfg.TokensFile, err)
	}
	g.tokens = ts
	return g, nil
}

// summary is one line for the startup log.
func (g *authGuard) summary() string {
	if !g.enabled {
		return "auth: disabled — the API is open (bind to loopback and proxy, PROJECT.md §21)"
	}
	counts := map[Role]int{}
	for _, r := range g.tokens {
		counts[r]++
	}
	return fmt.Sprintf("auth: enabled — %d token(s) (viewer=%d operator=%d admin=%d), allow_loopback=%t",
		len(g.tokens), counts[RoleViewer], counts[RoleOperator], counts[RoleAdmin], g.allowLoopback)
}

func (g *authGuard) wrap(next http.Handler) http.Handler {
	if g == nil || !g.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		need := requiredRole(r.Method, r.URL.Path)
		if need == roleNone {
			next.ServeHTTP(w, r)
			return
		}
		if g.allowLoopback && isLoopbackAddr(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}

		tok := bearerToken(r)
		if tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="synapseids"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		have, ok := g.tokens.lookup(tok)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		if have < need {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("role %q required; this token is %q", need, have),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken pulls the token from `Authorization: Bearer <t>`, or — for the
// WebSocket route only, where a browser cannot set request headers — from a
// `token` query parameter.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	if r.URL.Path == "/api/v1/stream" {
		return strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return ""
}

func isLoopbackAddr(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requiredRole is the route → minimum-role table, derived from method + path so
// a new GET route is covered without a table edit.
//
//   - anything outside /api/v1 and /metrics  → roleNone (the SPA shell, assets)
//   - /metrics and every GET / HEAD          → RoleViewer
//   - POST/DELETE on captures, POST on replay, the stateless architecture
//     estimator                              → RoleOperator
//   - every other mutating /api/v1 route     → RoleAdmin
func requiredRole(method, path string) Role {
	if path == "/metrics" {
		return RoleViewer
	}
	if !strings.HasPrefix(path, "/api/v1/") {
		return roleNone
	}
	if method == http.MethodGet || method == http.MethodHead {
		return RoleViewer
	}
	switch {
	case path == "/api/v1/architecture/estimate":
		return RoleViewer // pure calculator, no state change
	case strings.HasPrefix(path, "/api/v1/captures"):
		return RoleOperator
	case path == "/api/v1/replay" || path == "/api/v1/replay/stop":
		return RoleOperator
	default:
		return RoleAdmin
	}
}
