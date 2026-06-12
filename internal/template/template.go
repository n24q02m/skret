// Package template renders text templates by substituting ${KEY} references
// with secret values. Braces are required so bare $VAR in the target file
// (nginx $host, shell $PATH) is never touched.
package template

import (
	"regexp"
	"sort"
)

// tokenRe matches either a $$ escape sequence or a ${KEY} reference where KEY
// is a valid env-var identifier. $$ is an escape that collapses to a single $,
// so $${KEY} renders as the literal ${KEY} (never substituted).
var tokenRe = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Render substitutes each ${KEY} whose KEY is present in secrets with its value.
// References whose key is absent are left verbatim and their keys returned in
// missing (deduped, sorted). $$ is an escape that collapses to a single $, so
// $${KEY} renders as the literal ${KEY} (never substituted). Text that is not a
// valid ${KEY} reference is passed through unchanged.
func Render(content string, secrets map[string]string) (string, []string) {
	missingSet := map[string]bool{}
	out := tokenRe.ReplaceAllStringFunc(content, func(match string) string {
		if match == "$$" {
			return "$" // escape: $$ -> $, so $${KEY} renders as the literal ${KEY}
		}
		key := match[2 : len(match)-1] // strip "${" and "}"
		if v, ok := secrets[key]; ok {
			return v
		}
		missingSet[key] = true
		return match
	})

	if len(missingSet) == 0 {
		return out, nil
	}
	missing := make([]string, 0, len(missingSet))
	for k := range missingSet {
		missing = append(missing, k)
	}
	sort.Strings(missing)
	return out, missing
}
