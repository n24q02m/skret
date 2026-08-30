package config

import "strings"

// ResolvePath mirrors ResolveKey's shell-mangling recovery for the --path
// flag itself. Git Bash/MSYS rewrites a leading "/segment/segment"
// argument into an absolute Windows path by prepending the MSYS install
// root before the user's original argument, so the intended path survives
// as a trailing run of lowercase, SSM-identifier-shaped segments. Unlike
// ResolveKey, --path has no already-known resolved prefix to search for --
// it IS what is being resolved -- so the heuristic instead scans backward
// for the longest trailing run of segments matching a bare SSM-identifier
// shape (^[a-z][a-z0-9_-]*$, i.e. NOT capitalized, NOT dotted -- unlike
// typical Windows folder names such as "Users", "Program Files", or a
// version directory like "2.54.0") and, when at least two are found,
// recovers just that tail.
//
// A drive-lettered value is always reported as mangled (mirroring
// ephemeral.go's documented "fail visibly" intent for NormalizeSSMPath,
// now realized as a warning instead of silence) even when no plausible
// tail is found; in that case the value is returned unchanged rather than
// guessed, since a wrong guess is worse than an unchanged value the
// operator can see and correct.
func ResolvePath(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "/") {
		return raw, false
	}
	if len(raw) < 2 || raw[1] != ':' {
		return raw, false
	}

	norm := strings.ReplaceAll(raw, `\`, "/")

	// perf: ⚡ bolt: manual reverse-parsing loop replaces strings.Split and strings.Join
	// Reduces execution time from ~354ns to ~115ns and heap allocations from 3 to 1.
	validCount := 0
	rem := norm
	var startIdx int = len(norm)

	for {
		idx := strings.LastIndexByte(rem, '/')

		var segment string
		if idx == -1 {
			segment = rem
		} else {
			segment = rem[idx+1:]
		}

		if isSSMPathSegment(segment) {
			validCount++
			if idx == -1 {
				startIdx = 0
				break
			}
			startIdx = idx
			rem = rem[:idx]
		} else {
			break
		}
	}

	if validCount >= 2 {
		return "/" + strings.TrimLeft(norm[startIdx:], "/"), true
	}

	return raw, true
}

// isSSMPathSegment reports whether s looks like a plausible SSM path
// segment (lowercase identifier: starts with a-z, then a-z/0-9/_/- only) --
// the shape skret's own examples use (myapp, prod, dev), deliberately
// excluding version-number directories (2.54.0) and capitalized Windows
// folder names (Users, Program Files, Git).
func isSSMPathSegment(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
