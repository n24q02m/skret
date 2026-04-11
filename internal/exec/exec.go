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

	// ⚡ Bolt: Use map[string]string for O(1) lookups during variable expansion
	// instead of O(N) linear search over the `existing` slice.
	existingVars := make(map[string]string, len(existing))
	env := make([]string, 0, len(existing)+len(secrets))
	for _, e := range existing {
		key, val, _ := strings.Cut(e, "=")
		existingVars[key] = val
		env = append(env, e)
	}

	secretVars := make(map[string]string)
	for _, s := range secrets {
		name := KeyToEnvName(s.Key, pathPrefix)
		if _, exists := existingVars[name]; excludeSet[name] || exists {
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
				// ⚡ Bolt: O(1) map lookup replaces O(N) linear search
				if ev, ok := existingVars[ref]; ok {
					return ev
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
		if name != "" && name[0] == '/' {
			name = name[1:]
		}
	}
	name = strings.ReplaceAll(name, "/", "_")
	return strings.ToUpper(name)
}
