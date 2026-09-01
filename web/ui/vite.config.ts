import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The SPA is served by synapsed from an embedded copy of the build output
// (web/dist, //go:embed all:dist). Hash routing keeps every document request on
// "/", so `base: './'` (relative asset URLs) is all that is needed — no
// server-side SPA fallback. The Go build never runs Vite; `make web` does, and
// the result in ../dist is committed.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    // No external CDN / font fetches: everything is inlined or emitted as a
    // local asset so the committed bundle works fully offline.
    rollupOptions: {
      output: {
        // Keep React (and its runtime deps) in their own cacheable chunk — it
        // is ~140 kB of the bundle and changes far less often than app code.
        // Vite 8 dropped the object form of manualChunks; this is the function
        // form (issue #147).
        manualChunks(id) {
          if (/\/node_modules\/(react|react-dom|scheduler)\//.test(id)) {
            return 'react'
          }
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      // Order matters: the WebSocket route is matched before the REST prefix.
      '/api/v1/stream': {
        target: 'ws://127.0.0.1:8080',
        ws: true,
        changeOrigin: true,
      },
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
