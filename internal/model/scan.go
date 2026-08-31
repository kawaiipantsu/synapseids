package model

import (
	"os"
	"path/filepath"
)

// Logf is the logging sink Scan writes one line per bundle to. cmd/synapsed
// passes log.Printf.
type Logf func(format string, args ...any)

// Scan loads and validates every immediate subdirectory of dir as a model
// bundle and logs one line per bundle. It is a startup diagnostic only: it adds
// nothing to the inference runtime and activates nothing — not even a bundle
// that matches primary (PROJECT.md §28.10). A missing dir is not an error: Scan
// logs nothing and returns nil.
//
// primary is compared against both the bundle directory name and the bundle's
// metadata model_id, so it works whichever identifier the operator configured;
// a match only produces an extra "activation is a separate explicit step" line.
//
// It returns the bundles that both loaded and validated, in directory order, so
// a later explicit activation step has them without re-scanning.
func Scan(dir, primary string, logf Logf) []*Bundle {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("model scan: cannot read %q: %v", dir, err)
		}
		return nil
	}

	var ok []*Bundle
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		b, err := Load(filepath.Join(dir, name))
		if err == nil {
			err = b.Validate()
		}
		if err != nil {
			logf("rejected model bundle %q: %v", name, err)
			continue
		}
		m := b.Meta()
		logf("loaded model %q (family %s, %d params) — INACTIVE", name, m.Family, m.ParameterCount)
		if primary != "" && (name == primary || m.ModelID == primary) {
			logf("model %q present and valid; activation is a separate explicit step (not yet wired)", primary)
		}
		ok = append(ok, b)
	}
	return ok
}
