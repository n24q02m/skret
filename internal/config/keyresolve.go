package config

import "strings"

// ResolveKey maps a user-supplied key to a fully-qualified provider key using
// the resolved path prefix. It accepts a bare leaf ("DB_PASSWORD"), an
// already-qualified key ("/myapp/prod/DB_PASSWORD"), a genuine absolute key
// outside the configured path (passed through), and recovers keys mangled by
// POSIX-emulation shells on Windows — Git Bash/MSYS rewrites a leading "/arg"
// into "C:/.../<arg>". The bool reports whether mangling was recovered so the
// caller can warn the operator.
func ResolveKey(resolvedPath, key string) (string, bool) {
	rp := strings.TrimRight(resolvedPath, "/")
	if rp == "" || key == "" {
		return key, false
	}
	if key == rp || strings.HasPrefix(key, rp+"/") {
		return key, false
	}
	if i := strings.Index(key, rp+"/"); i > 0 {
		return key[i:], true
	}
	if strings.HasPrefix(key, "/") {
		return key, false
	}
	return rp + "/" + key, false
}
