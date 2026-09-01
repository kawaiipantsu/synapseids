# 0008 — TypeScript + React SPA with committed build output

**Status:** Accepted, 2026-08-31

## Context

Phase 1 shipped the operator UI as a single hand-written `web/index.html` —
vanilla JS, one rolling classification log, embedded with `//go:embed
index.html`. PROJECT.md §19 specifies a much larger UI (a Dashboard, a
full-screen Flow Log with filters and kiosk mode, a Flow Inspector, and a dozen
more views across LIVE / CAPTURE / ML / SYSTEM), and §27 names the frontend
stack: "TypeScript + React (or equivalent modern SPA)" with "a charting library
chosen for streaming performance". GitHub issue #20 (the last open child of
EPIC #1) is to replace the vanilla shell with that SPA.

Two hard constraints shape *how* it lands, not *whether*:

- **The Go build must stay Node-free, offline and cross-compilable.**
  `CGO_ENABLED=0`, the four static Linux targets and an offline `go build` are
  non-negotiable (§27, §28.16, [ADR 0001](0001-go-owns-the-data-plane.md)). CI
  and `make build-linux` run zero npm.
- **`internal/api` should not have to change.** Sibling branches are
  concurrently editing `api.go`; the UI work must not collide with them or add a
  server-side routing surface.

A build step that runs `npm` during `go build` (or a Go-native bundler, or
`go:generate` calling Vite) would break the first constraint. Client-side
history routing (`/flow-log`) would need an SPA-fallback handler in
`internal/api`, breaking the second.

## Decision

- **Stack:** TypeScript 5 + React 18, bundled with **Vite** (as of issue #147,
  Vite 8; the Node floor is `^20.19 || >=22.12`, stated in `web/ui/README.md` and
  `package.json` `engines`). Dependencies are locked with `package-lock.json` and
  installed with `npm ci`. The frontend npm tree is sanctioned by §27 and is
  entirely separate from the Go module, which keeps its **zero third-party Go
  dependencies**.
- **Charts:** **uPlot** for the streaming sparklines — ~15 KB gzipped, canvas
  based, no framework. No heavier chart library is added.
- **Routing:** **hash routing** only (`/#/flow-log`). Every document request
  stays on `/`, so synapsed needs no SPA-fallback route and `internal/api` is
  untouched. A clean-URL router is a later issue.
- **The built bundle is committed.** SPA source lives in `web/ui/`; `vite build`
  writes `web/ui/../dist` → **`web/dist/`**, which is committed to the
  repository. `web/web.go` embeds it with `//go:embed all:dist` and `FS()`
  returns the `dist` subtree rooted at `/`. `go build` only ever reads those
  committed files — it never invokes Vite.
- **Rebuild is a manual, reviewed step.** `make web` (`npm ci && npm run build`)
  regenerates `web/dist/`; the contributor commits the result. `make web-dev`
  runs the Vite dev server proxying `/api` and `/api/v1/stream` to
  `127.0.0.1:8080`; `make web-check` runs `tsc --noEmit`. `make clean` removes
  `web/ui/node_modules` and the Vite cache but leaves `web/dist/` in git.
- **Phase-1 scope.** Only the LIVE views the vertical slice needs are wired:
  Dashboard, Flow Log, Flow Inspector, and Replay control. Every other §19 view
  renders a "Planned — Phase N" placeholder naming its tracking epic. The
  committed bundle loads no external CDN or font resources; the previous shell's
  dark-terminal palette, per-class colours and `⟦THUGS⟧ · (c) 2026` mark are
  carried over.

## Consequences

- `go build`, `make build-linux` and CI stay exactly as fast and as offline as
  before; a fresh checkout with no Node produces a working `synapsed` with the
  full UI embedded.
- `web/dist/` is a generated artifact living in version control. Diffs on it are
  bundle churn (content-hashed filenames), and a stale `web/dist/` that does not
  match `web/ui/` is possible if a contributor forgets `make web`. Mitigations: a
  short list in `CLAUDE.md`/`docs`, and a candidate CI check (`make web` + `git
  diff --exit-code web/dist`) tracked as a follow-up.
- The Node toolchain is now a contributor prerequisite for UI work only. Nothing
  on the Go side depends on it.
- Hash routing means no deep-link server support and slightly uglier URLs; the
  trade for a zero-change `internal/api` is deliberate and reversible.
- `web.FS()` keeps its signature, so `internal/api` compiles unchanged; the only
  Go edit is `web/web.go`'s embed directive.
- uPlot is a new (frontend) dependency; it is mature, single-purpose and matches
  the §27 "streaming performance" guidance.

**Revisit when:** the SPA grows past the Phase-1 views and bundle size or build
time makes route-level code-splitting worthwhile; or a clean-URL router is
wanted (needs an SPA-fallback handler in `internal/api`); or CI gains a
Node job, at which point building `web/dist/` in CI instead of committing it
becomes an option worth weighing against the offline-build guarantee.

---

⟦THUGS⟧ (c) 2026
