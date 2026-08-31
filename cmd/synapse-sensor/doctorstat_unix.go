//go:build unix

package main

// ownerGroupMode resolves a path's owner name, group name and permission bits.
//
// doctor needs the *names* because every message it prints is meant to be
// compared by eye against `ls -l` output, and because the group-membership test
// for /dev/bpf* is expressed in group names. syscall.Stat_t's Uid/Gid fields are
// spelled identically on Linux, FreeBSD and Darwin, so one unix-tagged file
// covers every platform this repo builds for.

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func ownerGroupMode(path string) (owner, group string, mode fs.FileMode, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", fi.Mode().Perm(), fmt.Errorf("no stat information for %s on this platform", path)
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	owner, group = uid, gid
	if u, lookupErr := user.LookupId(uid); lookupErr == nil {
		owner = u.Username
	}
	if g, lookupErr := user.LookupGroupId(gid); lookupErr == nil {
		group = g.Name
	}
	return owner, group, fi.Mode().Perm(), nil
}
