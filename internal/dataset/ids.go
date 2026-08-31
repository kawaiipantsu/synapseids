package dataset

import (
	"fmt"
	"strings"
)

// Identifier limits. An id becomes one or two directory names and a version
// becomes a third, so both are validated strictly enough that no input can
// escape the dataset root or collide on a case-insensitive filesystem.
const (
	MaxIDLen      = 128
	MaxVersionLen = 64
	MaxSegmentLen = 64
)

// ValidateID checks a dataset id. PROJECT.md §14 writes ids as
// "thugs/lab-attacks-2026-08" — a location or owner namespace, a "/", then a
// name — so exactly one "/" is allowed and each side is a slug.
//
// The rules, all of them deliberate:
//
//   - one or two segments, separated by a single "/";
//   - each segment is 1..64 characters of [a-z0-9], ".", "_" or "-";
//   - each segment starts and ends with [a-z0-9], so "." , ".." , "-x" and
//     "x-" are all rejected and no segment can be a relative path element;
//   - lowercase only, so two ids cannot collide on a case-insensitive
//     filesystem;
//   - no "@" (it separates id from version in a reference), no ":", no
//     backslash, no control characters, nothing that is not on the list above.
//
// Path traversal is impossible by construction rather than by filtering: the
// only characters that survive are slug characters, and ".." cannot form
// because a segment may not start with ".".
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if len(id) > MaxIDLen {
		return fmt.Errorf("%w: id is %d characters, the limit is %d", ErrInvalid, len(id), MaxIDLen)
	}
	segs := strings.Split(id, "/")
	if len(segs) > 2 {
		return fmt.Errorf("%w: id %q may contain at most one %q (e.g. \"thugs/lab-attacks-2026-08\")", ErrInvalid, id, "/")
	}
	for _, s := range segs {
		if err := validateSegment("id", id, s); err != nil {
			return err
		}
	}
	return nil
}

// ValidateVersion checks a version label. It is a single segment: no "/", so a
// version can never add a directory level, and no "@", so a reference always
// splits unambiguously.
func ValidateVersion(v string) error {
	if v == "" {
		return fmt.Errorf("%w: version is required", ErrInvalid)
	}
	if len(v) > MaxVersionLen {
		return fmt.Errorf("%w: version is %d characters, the limit is %d", ErrInvalid, len(v), MaxVersionLen)
	}
	if strings.Contains(v, "/") {
		return fmt.Errorf("%w: version %q may not contain %q", ErrInvalid, v, "/")
	}
	return validateSegment("version", v, v)
}

// validateSegment enforces the shared slug rule on one path segment. what and
// whole only shape the error message.
func validateSegment(what, whole, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s %q has an empty segment", ErrInvalid, what, whole)
	}
	if len(s) > MaxSegmentLen {
		return fmt.Errorf("%w: %s %q has a segment longer than %d characters", ErrInvalid, what, whole, MaxSegmentLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if i == 0 || i == len(s)-1 {
				return fmt.Errorf("%w: %s %q must start and end with a letter or digit", ErrInvalid, what, whole)
			}
		case c >= 'A' && c <= 'Z':
			return fmt.Errorf("%w: %s %q must be lowercase", ErrInvalid, what, whole)
		default:
			return fmt.Errorf("%w: %s %q may only contain a-z, 0-9, %q, %q and %q", ErrInvalid, what, whole, ".", "_", "-")
		}
	}
	return nil
}
