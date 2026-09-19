// Package ref resolves ${NAME} references between secret values at read
// time (get/env/run), so one secret can be composed from others in the same
// environment scope: DB_URL=postgres://${DB_USER}:${DB_PASS}@host.
//
// It is deliberately separate from internal/template: template renders
// template FILES with single-pass substitution and collapses $$ to $, while
// reference resolution here is transitive (A -> B -> C) and preserves escape
// sequences byte-exact (\${NAME} and $${NAME} are never resolved).
package ref

import (
	"fmt"
	"strings"
)

// MaxDepth is the deepest reference chain resolution follows. A chain of
// MaxDepth references resolves; anything deeper fails with KindDepth.
const MaxDepth = 10

// Kind classifies resolution failures so callers can map them onto exit
// codes and remediation hints.
type Kind int

const (
	// KindMissing: the referenced name does not exist in the scope.
	KindMissing Kind = iota
	// KindCycle: the chain of references loops back into itself.
	KindCycle
	// KindDepth: the chain of references exceeds MaxDepth.
	KindDepth
)

// Error is a reference-resolution failure. Name is set for KindMissing;
// Chain is the reference path (outermost key first) for KindCycle/KindDepth.
type Error struct {
	Kind  Kind
	Name  string
	Chain []string
}

func (e *Error) Error() string {
	switch e.Kind {
	case KindMissing:
		return fmt.Sprintf("reference ${%s} not found in environment scope", e.Name)
	case KindCycle:
		return "reference cycle: " + strings.Join(e.Chain, " -> ")
	default:
		return fmt.Sprintf("reference chain deeper than %d hops: %s", MaxDepth, strings.Join(e.Chain, " -> "))
	}
}

// Lookup returns the raw stored value for a reference name and whether the
// name exists in the scope.
type Lookup func(name string) (value string, ok bool)

// Resolve expands every ${NAME} reference in value, transitively, using
// lookup for raw stored values. Values without references come back
// byte-exact. Escapes — a \ or $ byte immediately before ${ — suppress
// resolution for that span: \${NAME} and $${NAME} stay byte-exact and their
// payload is never resolved. Tokens whose payload is not a valid
// environment-variable name (e.g. ${VAR:-default}, ${a.b}, ${}) are not
// references and pass through byte-exact.
func Resolve(value string, lookup Lookup) (string, error) {
	return expand(value, nil, lookup)
}

// expand scans s left to right, copying non-reference bytes verbatim and
// resolving reference tokens against lookup. chain is the reference path that
// led here (outermost first), used for cycle and depth checks.
func expand(s string, chain []string, lookup Lookup) (string, error) {
	if len(chain) > MaxDepth {
		return "", &Error{Kind: KindDepth, Chain: chain}
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}
		rel := strings.IndexByte(s[i+2:], '}')
		if rel < 0 {
			// Unclosed "${...": literal to the end of the value.
			b.WriteString(s[i:])
			break
		}
		end := i + 2 + rel // index of '}'
		name := s[i+2 : end]
		// Escaped (preceding \ or $ byte) or not a valid env name: copy the
		// whole span byte-exact and do not look inside it.
		if (i > 0 && (s[i-1] == '\\' || s[i-1] == '$')) || !isRefName(name) {
			b.WriteString(s[i : end+1])
			i = end + 1
			continue
		}
		raw, ok := lookup(name)
		if !ok {
			return "", &Error{Kind: KindMissing, Name: name, Chain: append(chain, name)}
		}
		for _, c := range chain {
			if c == name {
				return "", &Error{Kind: KindCycle, Chain: append(chain, name)}
			}
		}
		resolved, err := expand(raw, append(chain, name), lookup)
		if err != nil {
			return "", err
		}
		b.WriteString(resolved)
		i = end + 1
	}
	return b.String(), nil
}

// isRefName reports whether name is a valid environment-variable identifier:
// ASCII letters, digits, underscores, not starting with a digit.
func isRefName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		c := name[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}
