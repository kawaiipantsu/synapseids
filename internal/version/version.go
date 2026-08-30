// Package version carries build metadata stamped in by the Makefile via -ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These are overridden at build time with:
//
//	-X github.com/kawaiipantsu/synapseids/internal/version.Version=...
var (
	// Version is the release version, e.g. "0.1.0" or "0.1.0-dev".
	Version = "0.1.0-dev"
	// Commit is the short git SHA, or "unknown".
	Commit = "unknown"
	// Date is an RFC3339 UTC build timestamp, or "unknown".
	Date = "unknown"
	// Dirty is "true" when the working tree had uncommitted changes at build time.
	Dirty = "false"
)

// String returns a multi-line, human-readable build stamp for the given command.
func String(cmd string) string {
	dirty := ""
	if Dirty == "true" {
		dirty = " (dirty)"
	}
	return fmt.Sprintf(
		"%s v%s%s\ncommit:  %s\nbuilt:   %s\ngo:      %s\nos/arch: %s/%s",
		cmd, Version, dirty, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}

// Short returns a one-line version string for the given command.
func Short(cmd string) string {
	return fmt.Sprintf("%s v%s (%s)", cmd, Version, Commit)
}
