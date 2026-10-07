// Package template renders text templates by substituting ${KEY} references
// with secret values. Braces are required so bare $VAR in the target file
// (nginx $host, shell $PATH) is never touched.
package template

import (
	"sort"
	"strings"
)

// Render substitutes each ${KEY} whose KEY is present in secrets with its value.
// References whose key is absent are left verbatim and their keys returned in
// missing (deduped, sorted). $$ is an escape that collapses to a single $, so
// $${KEY} renders as the literal ${KEY} (never substituted). Text that is not a
// valid ${KEY} reference is passed through unchanged.
func Render(content string, secrets map[string]string) (string, []string) {
	idx := strings.IndexByte(content, '$')
	if idx == -1 {
		return content, nil
	}

	var missingSet map[string]bool
	var b strings.Builder
	b.Grow(len(content) + 16)
	b.WriteString(content[:idx])

	for i := idx; i < len(content); {
		if content[i] != '$' || i+1 >= len(content) {
			b.WriteByte(content[i])
			i++
			continue
		}
		if content[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if content[i+1] == '{' {
			rel := strings.IndexByte(content[i+2:], '}')
			if rel < 0 {
				b.WriteByte('$')
				b.WriteByte('{')
				i += 2
				continue
			}
			end := i + 2 + rel
			key := content[i+2 : end]

			valid := true
			if key == "" {
				valid = false
			} else {
				for j := 0; j < len(key); j++ {
					c := key[j]
					if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
						continue
					}
					if j > 0 && c >= '0' && c <= '9' {
						continue
					}
					valid = false
					break
				}
			}

			if !valid {
				b.WriteString(content[i : end+1])
				i = end + 1
				continue
			}

			if v, ok := secrets[key]; ok {
				b.WriteString(v)
			} else {
				if missingSet == nil {
					missingSet = make(map[string]bool)
				}
				missingSet[key] = true
				b.WriteString(content[i : end+1])
			}
			i = end + 1
			continue
		}

		b.WriteByte('$')
		i++
	}

	out := b.String()
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
