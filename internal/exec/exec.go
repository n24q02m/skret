package exec

import (
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

	existingKeys := make(map[string]bool)
	env := make([]string, 0, len(existing)+len(secrets))
	for _, e := range existing {
		key, _, _ := strings.Cut(e, "=")
		existingKeys[key] = true
		env = append(env, e)
	}

	for _, s := range secrets {
		name := keyToEnvName(s.Key, pathPrefix)
		if excludeSet[name] || existingKeys[name] {
			continue
		}
		env = append(env, name+"="+s.Value)
	}

	return env
}

func keyToEnvName(key, pathPrefix string) string {
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
