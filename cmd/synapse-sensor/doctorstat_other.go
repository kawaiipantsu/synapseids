//go:build !unix

package main

// Non-Unix stub. The selftest targets FreeBSD (OPNsense) and is developed on
// Linux; it stays compilable elsewhere so `go build ./...` on any GOOS keeps
// working, and the ownership checks degrade to a WARN rather than a build error.

import (
	"errors"
	"io/fs"
	"os"
)

func ownerGroupMode(path string) (owner, group string, mode fs.FileMode, err error) {
	fi, statErr := os.Stat(path)
	if statErr != nil {
		return "", "", 0, statErr
	}
	return "", "", fi.Mode().Perm(), errors.New("file ownership is not available on this platform")
}
