# SynapseIDS operator SPA

TypeScript + React + Vite. The built output lives in [`../dist`](../dist) and is
committed and embedded by `web/web.go` (`//go:embed all:dist`), so **the Go build
never needs Node**. Run the build only after changing something under `web/ui/`,
and commit `web/dist/` in the same change.

## Toolchain

| Tool | Version |
|---|---|
| Node.js | **`^20.19.0` or `>=22.12.0`** — the floor Vite 8 requires. Enforced by `package.json` `engines`. |
| npm | whatever ships with that Node. |

Node 18 was the floor through the Vite 6 era; Vite 8 (issue #147) raised it. CI
builds the SPA on Node 22.

## Commands

```bash
npm ci            # install the locked dependencies
npm run build     # typecheck, then `vite build` into ../dist  (== `make web`)
npm run dev       # Vite dev server, proxying /api and /api/v1/stream to :8080
npm run typecheck # tsc --noEmit
npm run test      # tsc -p tsconfig.test.json, then node --test over .test-build/
```

Two consecutive `npm run build` runs must produce byte-identical assets (the
filenames are content hashes). The CI `web-build` job rebuilds and fails if the
committed `web/dist` does not match — which also catches a hand-edited or stale
`dist`.

## Chunking

`vite.config.ts` splits React (and `react-dom` / `scheduler`) into their own
cacheable chunk via the **function** form of `build.rollupOptions.output.manualChunks`
— Vite 8 dropped the object form.
