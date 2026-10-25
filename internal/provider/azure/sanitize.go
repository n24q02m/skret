package azure

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

// maxNameLen is Key Vault's secret-name length limit.
const maxNameLen = 127

// sanitizeKey maps an arbitrary skret key onto Key Vault's secret-name
// space ([0-9a-zA-Z-], 1-127 chars). Disallowed characters (path
// separators, underscores, dots, unicode) become '-', consecutive dashes
// collapse, and leading/trailing dashes trim. Applied on BOTH read and
// write paths so `set DB_URL` / `get DB_URL` round-trip. The mapping is
// deterministic but not injective: "db_url" and "db-url" both store as
// "db-url" (documented provider behavior).
func sanitizeKey(key string) (string, error) {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := b.String()
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	// Every surviving rune is ASCII, so byte slicing cannot split a rune.
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
		name = strings.TrimRight(name, "-")
	}
	if name == "" {
		return "", fmt.Errorf("key sanitizes to an empty Azure Key Vault name (allowed: alphanumeric and dash)")
	}
	return name, nil
}

// versionNumber folds a Key Vault version ID (a 32-char random hex string,
// 128 bits) into the non-negative int64 space the provider contract uses.
// The first 15 hex characters (60 bits) are taken directly; IDs that are
// not parseable hex fall back to FNV-1a. Two versions of one secret
// colliding on this fold is negligible (< 2^-50 even for thousands of
// versions of a single secret).
func versionNumber(versionID string) int64 {
	id := strings.ToLower(versionID)
	if len(id) >= 15 {
		if v, err := strconv.ParseUint(id[:15], 16, 64); err == nil {
			return int64(v & 0x7fffffffffffffff)
		}
	}
	h := fnv.New64a()
	h.Write([]byte(id)) // never returns an error
	return int64(h.Sum64() & 0x7fffffffffffffff)
}
