package logging

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatterns_EveryPatternIsNamed(t *testing.T) {
	got := Patterns()
	require.Len(t, got, len(secretPatterns))

	seen := make(map[string]bool)
	for i, p := range got {
		assert.NotEmpty(t, p.Name, "pattern %d has no name", i)
		assert.NotEqual(t, unnamedPattern, p.Name, "pattern %d (%s) is missing from patternNames", i, p.Regexp)
		assert.False(t, seen[p.Name], "duplicate pattern name %q", p.Name)
		seen[p.Name] = true
		assert.Same(t, secretPatterns[i].re, p.Regexp)
	}
}

func TestPatterns_GenericFlagMarksHeuristics(t *testing.T) {
	generic := make(map[string]bool)
	for _, p := range Patterns() {
		generic[p.Name] = p.Generic
	}
	assert.True(t, generic["secret-assignment"])
	assert.True(t, generic["base64-blob"])
	for _, name := range []string{"sk-api-key", "doppler-service-token", "github-pat", "aws-access-key-id"} {
		v, ok := generic[name]
		assert.True(t, ok, "missing pattern %q", name)
		assert.False(t, v, "pattern %q should be a specific format", name)
	}
}

func TestPatterns_SpecificPatternsMatchTheirFormat(t *testing.T) {
	samples := map[string]string{
		"sk-api-key":            "sk-" + strings.Repeat("A1", 12),
		"doppler-service-token": "dp.st." + "dev" + "XXXXXXXX",
		"github-pat":            "ghp_" + strings.Repeat("a1", 18),
		"aws-access-key-id":     "AKIA" + "IOSFODNN7EXAMPLE",
	}
	for _, p := range Patterns() {
		sample, ok := samples[p.Name]
		if !ok {
			continue
		}
		assert.True(t, p.Regexp.MatchString(sample), "%s should match its sample", p.Name)
	}
}

func TestPatterns_UnknownFastPrefixFallsBack(t *testing.T) {
	saved := secretPatterns
	t.Cleanup(func() { secretPatterns = saved })
	secretPatterns = append(append([]pattern(nil), saved...), pattern{re: saved[0].re, fast: "unregistered"})

	got := Patterns()
	assert.Equal(t, unnamedPattern, got[len(got)-1].Name)
}
