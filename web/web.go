// Package web embeds the built-in single-page rolling flow-classification log
// that synapsed serves at "/" when no external web root is configured. It is a
// dependency-free placeholder; a full TypeScript + React SPA is tracked
// separately (PROJECT.md §19, §27).
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html
var assets embed.FS

// FS returns the embedded web assets rooted so that "/" resolves to index.html.
func FS() fs.FS { return assets }
