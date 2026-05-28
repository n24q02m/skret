package exec

import (
	"os"
	"strings"

	"github.com/n24q02m/skret/internal/provider"
)

// BuildEnv merges secrets into existing env vars.
// Existing env vars override secret values (user control).
// Keys in exclude list are never injected.
func BuildEnv(secrets []*provider.Secret, existing []string, pathPrefix string, exclude []string) []string {
	excludeSet := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excludeSet[strings.ToUpper(e)] = true
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
		secretVars[name] = s.Value
	}
	// Resolved cache to avoid redundant expansions
	resolved := make(map[string]string, len(secretVars))
	// Cycle detection map
	resolving := make(map[string]bool, len(secretVars))

	var resolve func(string) string
	resolve = func(ref string) string {
		// 1. check existing environment variables (highest priority)
		if val, ok := existingMap[ref]; ok {
			return val
		}
		// 2. check already resolved secrets
		if val, ok := resolved[ref]; ok {
			return val
		}
		// 3. check if it is a secret that needs resolving
		val, ok := secretVars[ref]
		if !ok {
			// fallback to host env
			return os.Getenv(ref)
		}

		// Cycle detection
		if resolving[ref] {
			return val // Return raw value to break cycle
		}

		resolving[ref] = true
		defer func() { resolving[ref] = false }()
		if strings.IndexByte(val, '$') >= 0 {
			val = os.Expand(val, resolve)
		}

		resolved[ref] = val
		return val
	}

	for k := range secretVars {
		secretVars[k] = resolve(k)
	}

	for k, v := range secretVars {
		env = append(env, k+"="+v)
	}

	return env
}

// KeyToEnvName converts a secret key to an environment variable name.
// It strips the path prefix, replaces "/"" with "_"", and uppercases.
// This is the single source of truth for key-to-env-var conversion.
func KeyToEnvName(key, pathPrefix string) string {
	name := key
	if pathPrefix != "" && strings.HasPrefix(key, pathPrefix) {
		name = key[len(pathPrefix):]
		if name != "" && name[0] == '/' {
			name = name[1:]
		}
	}

	needsTransform := false
	hasNonAscii := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 0x80 {
			hasNonAscii = true
			needsTransform = true
			break
		}
		if c == '/' || (c >= 'a' && c <= 'z') {
			needsTransform = true
		}
	}

	if !needsTransform {
		return name
	}

	if hasNonAscii {
		return strings.ToUpper(strings.ReplaceAll(name, "/", "_"))
	}

	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '/':
			b.WriteByte('_')
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
