# 0035 — API access control: bearer tokens, three roles, loopback exempt

**Status:** Accepted, 2026-09-01

## Context

PROJECT.md §21 requires the daemon to "authenticate non-local UI/API access".
Until now the mutating routes — `POST/DELETE /api/v1/captures`, model
activate/deactivate, replay, dataset create/delete, the trainer-facing training
POSTs, review writes — were unauthenticated, gated only by the loopback bind and
`TODO(#58)` markers. Issue #58.

The documented deployment is still "bind to loopback, terminate TLS + auth in an
`nginx` reverse proxy". RBAC here is the control for when the daemon is exposed
directly, and a second layer when it is not.

## Decision

### Bearer tokens in a file, mapped to a role

`auth.tokens_file` holds `<role> <token> [label]` lines. Tokens are opaque, ≥ 8
chars, never inline in `synapse.json` (§23, same rule as the SYNPOIP bearer
token). The daemon reads the file once at start-up into `map[sha256(token)]role`
— the digest is the key, so a heap dump does not yield a usable token, and
`lookup` walks every entry with `crypto/subtle.ConstantTimeCompare` so "unknown"
and "known" take the same time. A malformed file (missing file, unknown role,
short/duplicate token, no usable line) is a fatal start-up error, like any other
config mistake.

No hashing scheme (bcrypt/argon2) on the stored side: these are machine tokens
in a root-only file, not user passwords, and the file *is* the secret. If it
leaks, rotate it.

### Three cumulative roles, derived from method + path

`viewer` < `operator` < `admin`.

- `viewer` — every `GET`, and `GET /metrics`.
- `operator` — `viewer` + the capture and replay routes (run captures, start /
  stop replays).
- `admin` — everything: model activation, dataset and training writes, review
  writes.

`requiredRole(method, path)` is a function, not a table: a new `GET` route is
covered automatically; only the operator/admin split for non-GET routes is
enumerated. `POST /api/v1/architecture/estimate` is special-cased back to
`viewer` because it changes nothing. The SPA shell (`/`, `/assets/*`) is never
gated — it has to load so a token can be entered.

### Loopback is exempt by default

`auth.allow_loopback` (default `true`) lets a request from `127.0.0.0/8` or `::1`
through without a token. This keeps the local `synapse` CLI and a same-host
browser working unchanged when RBAC is switched on, which is the common case
(daemon on the box, `nginx` in front doing the real auth). Set it `false` to
require a token even from localhost.

### Transport of the token

`Authorization: Bearer <token>` everywhere. The WebSocket route
`GET /api/v1/stream` *also* accepts `?token=<token>` because a browser cannot set
a request header on `new WebSocket()`; no other route does.

- `synapse` CLI: `--token` / `SYNAPSE_TOKEN`.
- SPA: a token in `localStorage`, adopted from a one-time `…/?token=<t>` URL (then
  stripped from history) and attached to every request by a `window.fetch`
  wrapper. A dedicated token UI on the Settings page is a follow-up.

### Middleware placement

`logMiddleware(authGuard.wrap(mux))` — the access log sees the final `401`/`403`.
A disabled guard is a pass-through, so `New` still returns an open API and no
test had to change.

## Consequences

- New `auth` config block; disabled by default → zero behaviour change for an
  existing deployment.
- `Server.SetAuth(config.Auth) error` (a setter, like `SetMetrics`), called once
  by the daemon; a load failure is fatal.
- The `TODO(#58)` markers across `internal/api` are replaced with the actual role
  each route now needs.
- Not built here: per-token rate limiting, token expiry/rotation tooling, an
  audit trail of *who* activated a model (the audit log records the action, not
  the token), and the SPA Settings token field.

## Alternatives rejected

- **mTLS only.** Right for the sensor↔collector link (ADR 0018), heavy for an
  operator opening a dashboard.
- **A `users`/`sessions` store with login.** A password DB and session cookies
  for what is a handful of machine tokens; the reverse proxy already owns the
  human-login story.
- **Gate everything at `admin`.** Kills the "NOC wall-board" and "SOC analyst who
  can run a replay but not activate a model" cases the three roles exist for.
