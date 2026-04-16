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
		excludeSet[transformToEnvName(e)] = true
	}

	existingMap := make(map[string]string, len(existing))
	env := make([]string, 0, len(existing)+len(secrets))
	for _, e := range existing {
		key, val, _ := strings.Cut(e, "=")
		existingMap[key] = val
		env = append(env, e)
	}

	hasPrefix := pathPrefix != ""
	prefixLen := len(pathPrefix)

	secretVars := make(map[string]string)
	for _, s := range secrets {
		name := s.Key
		if hasPrefix && strings.HasPrefix(name, pathPrefix) {
			name = name[prefixLen:]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		name = transformToEnvName(name)

		if excludeSet[name] {
			continue
		}
		if _, exists := existingMap[name]; exists {
			continue
		}
		secretVars[name] = s.Value
	}

	// Expand secret references (up to 10 iterations to prevent infinite loops)
	for i := 0; i < 10; i++ {
		changed := false
		for k, v := range secretVars {
			newVal := os.Expand(v, func(ref string) string {
				// 1. check existing environment variables (highest priority)
				if val, ok := existingMap[ref]; ok {
					return val
				}
				// 2. check other secrets
				if sv, ok := secretVars[ref]; ok {
					return sv
				}
				// 3. fallback to host env
				return os.Getenv(ref)
			})
			if newVal != v {
				secretVars[k] = newVal
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	for k, v := range secretVars {
		env = append(env, k+"="+v)
	}

	return env
}

// KeyToEnvName converts a secret key to an environment variable name.
// It strips the path prefix, replaces "/" with "_", and uppercases.
// This is the single source of truth for key-to-env-var conversion.
func KeyToEnvName(key, pathPrefix string) string {
	name := key
	if pathPrefix != "" && strings.HasPrefix(key, pathPrefix) {
		name = key[len(pathPrefix):]
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
	}
	return transformToEnvName(name)
}

func transformToEnvName(s string) string {
	needsTransform := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' || (c >= 'a' && c <= 'z') {
			needsTransform = true
			break
		}
	}
	if !needsTransform {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			b.WriteByte('_')
		} else if c >= 'a' && c <= 'z' {
			b.WriteByte(c - 32)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
