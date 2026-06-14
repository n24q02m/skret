package exec

import (
	"fmt"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
)

// BuildEnv merges secrets into existing env vars.
// Existing env vars override secret values (user control).
// Keys in exclude list are never injected.
// Secret values are injected byte-exact: '$' is never expanded, so values like
// bcrypt hashes ($2a$14$...) or URLs with '$' in the password survive verbatim.
// Cross-secret references are served by the explicit `skret template` command.
func BuildEnv(secrets []*provider.Secret, existing []string, pathPrefix string, exclude []string) []string {
	// ⚡ Bolt: Early return for empty secrets avoids expensive cache initializations
	if len(secrets) == 0 {
		return existing
	}

	var excludeSet map[string]bool
	if len(exclude) > 0 {
		excludeSet = make(map[string]bool, len(exclude))
		for _, e := range exclude {
			excludeSet[strings.ToUpper(e)] = true
		}
	}

	existingMap := make(map[string]string, len(existing))
	env := make([]string, 0, len(existing)+len(secrets))
	for _, e := range existing {
		idx := strings.IndexByte(e, '=')
		if idx >= 0 {
			existingMap[e[:idx]] = e[idx+1:]
		} else {
			existingMap[e] = ""
		}
		env = append(env, e)
	}

	secretVars := make(map[string]string, len(secrets))
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, pathPrefix)
		if excludeSet[name] {
			continue
		}
		if _, exists := existingMap[name]; exists {
			continue
		}

		// Sanitize value:
		// 1. Remove null bytes as they cause syscall.Exec to fail with "invalid argument".
		// 2. Replace newlines/carriage returns with spaces to prevent environment entry corruption
		//    and potential injection in tools that parse 'env' output line-by-line.
		val := s.Value
		if strings.ContainsAny(val, "\x00\n\r") {
			// ⚡ Bolt: Use a single-pass builder to avoid multiple intermediate string allocations
			var b strings.Builder
			b.Grow(len(val))
			for i := 0; i < len(val); i++ {
				c := val[i]
				switch c {
				case '\x00', '\r':
					// Remove
				case '\n':
					b.WriteByte(' ')
				default:
					b.WriteByte(c)
				}
			}
			val = b.String()
		}
		secretVars[name] = val
	}

	for k, v := range secretVars {
		env = append(env, k+"="+v)
	}

	return env
}

// KeyToEnvName converts a secret key to an environment variable name.
// It strips the path prefix, then maps "/", "-", "=", space, newline and CR to
// "_" and uppercases ASCII letters, so a key like "/app/prod/api-key" becomes the
// valid env var name "API_KEY". Non-ASCII bytes are preserved (e.g. "秘=密" ->
// "秘_密"); the sanitization is applied uniformly regardless of any non-ASCII
// bytes. This is the single source of truth for key-to-env-var conversion.
func KeyToEnvName(key, pathPrefix string) string {
	name := key
	if pathPrefix != "" && strings.HasPrefix(key, pathPrefix) {
		name = key[len(pathPrefix):]
		if name != "" && name[0] == '/' {
			name = name[1:]
		}
	}

	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c == '/' || c == '-' || c == '=' || c == ' ' || c == '\n' || c == '\r':
			b.WriteByte('_')
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		default:
			// ASCII uppercase/digits/other and all non-ASCII (UTF-8 continuation)
			// bytes are kept verbatim.
			b.WriteByte(c)
		}
	}
	return b.String()
}

// DetectEnvNameCollisions reports an error when two DISTINCT secret keys map to
// the same environment variable name. Without this guard one secret would
// silently overwrite the other (or be dropped), so a process could run with the
// wrong secret value with no indication. Excluded names are ignored. Duplicate
// occurrences of the SAME key are not a collision (last-write-wins dedup).
func DetectEnvNameCollisions(secrets []*provider.Secret, pathPrefix string, exclude []string) error {
	var excludeSet map[string]bool
	if len(exclude) > 0 {
		excludeSet = make(map[string]bool, len(exclude))
		for _, e := range exclude {
			excludeSet[strings.ToUpper(e)] = true
		}
	}

	nameToKey := make(map[string]string, len(secrets))
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, pathPrefix)
		if excludeSet[name] {
			continue
		}
		if prev, ok := nameToKey[name]; ok && prev != s.Key {
			return fmt.Errorf("env var name %q is produced by two distinct keys %q and %q; rename one so secrets are not silently lost", name, prev, s.Key)
		}
		nameToKey[name] = s.Key
	}
	return nil
}
