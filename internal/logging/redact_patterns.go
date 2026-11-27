package logging

import "regexp"

// NamedPattern is one of the secret shapes the log redactor masks, exposed so
// other surfaces (output redaction, the protect pre-commit check) apply the
// same rules instead of keeping their own copies.
type NamedPattern struct {
	// Name is a stable, human-readable rule identifier (e.g. "github-pat").
	Name string
	// Regexp matches the secret. It never matches across whitespace.
	Regexp *regexp.Regexp
	// Generic marks heuristic shapes (key=value assignments, long base64-like
	// runs) that also match ordinary content such as hashes and lockfiles.
	Generic bool
}

// unnamedPattern is the fallback name for a pattern missing from patternNames.
const unnamedPattern = "secret-pattern"

// patternNames maps each secretPatterns entry (keyed by its fast-path
// substring, which is unique per pattern) to its rule name.
var patternNames = map[string]struct {
	name    string
	generic bool
}{
	"=":      {"secret-assignment", true},
	"sk-":    {"sk-api-key", false},
	"dp.st.": {"doppler-service-token", false},
	"ghp_":   {"github-pat", false},
	"AKIA":   {"aws-access-key-id", false},
	"":       {"base64-blob", true},
}

// Patterns returns the log redactor's secret patterns, in application order.
func Patterns() []NamedPattern {
	out := make([]NamedPattern, 0, len(secretPatterns))
	for _, p := range secretPatterns {
		meta, ok := patternNames[p.fast]
		if !ok {
			meta.name = unnamedPattern
		}
		out = append(out, NamedPattern{Name: meta.name, Regexp: p.re, Generic: meta.generic})
	}
	return out
}
