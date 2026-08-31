// Package web embeds the built SynapseIDS operator SPA (TypeScript + React,
// bundled with Vite) that synapsed serves at "/" when no external web root is
// configured (PROJECT.md §19, §27).
//
// The build output under dist/ is committed to the repository and embedded
// here so that `go build` never needs Node or npm and stays fully offline
// (docs/adr/0004-react-spa-and-committed-build-output.md). The SPA source lives
// in web/ui/; after changing it, run `make web` and commit the refreshed
// web/dist/.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// FS returns the built SPA rooted so that "/" resolves to dist/index.html.
func FS() fs.FS {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		// Unreachable: dist/ is committed and embedded at build time.
		panic("web: embedded dist/ subtree missing: " + err.Error())
	}
	return sub
}
