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

	// Optimization: use a map for O(1) lookup of existing environment variables.
	// This avoids nested loops during secret expansion.
	existingMap := make(map[string]string)
	env := make([]string, 0, len(existing)+len(secrets))
	for _, e := range existing {
		key, val, _ := strings.Cut(e, "=")
		existingMap[key] = val
		env = append(env, e)
	}

	secretVars := make(map[string]string)
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, pathPrefix)
		if _, ok := existingMap[name]; ok || excludeSet[name] {
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
				// Optimized: O(1) lookup in existingMap instead of O(N) loop over existing slice.
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
// It strips the path prefix, replaces "/"" with "_"", and uppercases.
// This is the single source of truth for key-to-env-var conversion.
func KeyToEnvName(key, pathPrefix string) string {
	name := key
	if pathPrefix != "" && strings.HasPrefix(key, pathPrefix) {
		name = key[len(pathPrefix):]
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
	}
	name = strings.ReplaceAll(name, "/", "_")
	return strings.ToUpper(name)
}
