package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runGenerate invokes `skret generate` from dir and returns stdout, stderr
// and the command error. Generation is offline, so dir needs no config
// unless the args use --set.
func runGenerate(t *testing.T, dir string, args ...string) (string, string, error) {
	t.Helper()
	t.Chdir(dir)

	var out, errBuf bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(append([]string{"generate"}, args...))
	err := cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestGenerateCmd_Registered(t *testing.T) {
	cmd := NewRootCmd()
	found, _, err := cmd.Find([]string{"generate"})
	require.NoError(t, err)
	assert.Equal(t, "generate", found.Name())
}

// TestGenerateCmd_WorksWithoutConfig — generation is offline; no
// .skret.yaml or provider may be required without --set.
func TestGenerateCmd_WorksWithoutConfig(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "password", "--length", "32")
	require.NoError(t, err)
	assert.Len(t, strings.TrimSuffix(out, "\n"), 32)
}

func TestGenerateCmd_TypeAndCharsetMembership(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		matches *regexp.Regexp
	}{
		{
			name:    "password alnum default charset",
			args:    []string{"--type", "password", "--length", "40"},
			matches: regexp.MustCompile(`^[a-zA-Z0-9]{40}$`),
		},
		{
			name:    "password alnum explicit",
			args:    []string{"--type", "password", "--length", "24", "--charset", "alnum"},
			matches: regexp.MustCompile(`^[a-zA-Z0-9]{24}$`),
		},
		{
			name:    "password alnum+symbols",
			args:    []string{"--type", "password", "--length", "64", "--charset", "alnum+symbols"},
			matches: regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_=+\[\]{};:,.\-]{64}$`),
		},
		{
			name:    "password symbols only",
			args:    []string{"--type", "password", "--length", "32", "--charset", "symbols"},
			matches: regexp.MustCompile(`^[!@#$%^&*()_=+\[\]{};:,.\-]{32}$`),
		},
		{
			name:    "hex",
			args:    []string{"--type", "hex", "--length", "16"},
			matches: regexp.MustCompile(`^[0-9a-f]{16}$`),
		},
		{
			name:    "base64",
			args:    []string{"--type", "base64", "--length", "48"},
			matches: regexp.MustCompile(`^[A-Za-z0-9+/]{48}$`),
		},
		{
			name:    "uuid is version 4 variant rfc4122",
			args:    []string{"--type", "uuid"},
			matches: regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := runGenerate(t, t.TempDir(), tt.args...)
			require.NoError(t, err)
			value, hasNL := strings.CutSuffix(out, "\n")
			require.True(t, hasNL, "default table output must end with exactly one newline")
			assert.Regexp(t, tt.matches, value)
		})
	}
}

// TestGenerateCmd_SymbolsAllPresent — with ~1600 draws over 22 symbols every
// symbol must appear (P(miss) < 1e-70), guarding against a silently
// truncated alphabet.
func TestGenerateCmd_SymbolsAllPresent(t *testing.T) {
	seen := map[rune]bool{}
	for range 50 {
		out, _, err := runGenerate(t, t.TempDir(), "--type", "password", "--length", "32", "--charset", "symbols")
		require.NoError(t, err)
		for _, r := range strings.TrimSuffix(out, "\n") {
			seen[r] = true
		}
	}
	for _, r := range generateSymbols {
		assert.True(t, seen[r], "symbol %q never generated", r)
	}
	assert.Len(t, seen, len(generateSymbols))
}

// TestGenerateCmd_CountUniqueAndLineFormat — --count N emits N distinct
// newline-separated values (collision probability for 16-hex-char values is
// negligible, so distinctness is a real distribution check, not a tautology).
func TestGenerateCmd_CountUniqueAndLineFormat(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "hex", "--length", "16", "--count", "50")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	require.Len(t, lines, 50)
	unique := map[string]bool{}
	for _, l := range lines {
		assert.Regexp(t, `^[0-9a-f]{16}$`, l)
		unique[l] = true
	}
	assert.Len(t, unique, 50, "all 50 values must be distinct")
}

func TestGenerateCmd_PlainExactBytes(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "hex", "--length", "16", "--plain")
	require.NoError(t, err)
	assert.Len(t, out, 16, "--plain must emit exactly length bytes, no newline")
	assert.Regexp(t, `^[0-9a-f]{16}$`, out)
}

func TestGenerateCmd_JSONEnvelopeSingle(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "hex", "--length", "16", "--format", "json")
	require.NoError(t, err)
	var res GenerateResult
	require.NoError(t, json.Unmarshal([]byte(out), &res))
	assert.Equal(t, "hex", res.Type)
	assert.Equal(t, 16, res.Length)
	assert.Regexp(t, `^[0-9a-f]{16}$`, res.Value)
	assert.Empty(t, res.Key, "no --set means no key field")
}

func TestGenerateCmd_JSONEnvelopeMultiple(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "base64", "--length", "8", "--count", "3", "--format", "json")
	require.NoError(t, err)
	var results []GenerateResult
	require.NoError(t, json.Unmarshal([]byte(out), &results))
	require.Len(t, results, 3)
	seen := map[string]bool{}
	for _, r := range results {
		assert.Equal(t, "base64", r.Type)
		assert.Equal(t, 8, r.Length)
		assert.Len(t, r.Value, 8)
		seen[r.Value] = true
	}
	assert.Len(t, seen, 3)
}

func TestGenerateCmd_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{name: "unknown type", args: []string{"--type", "token"}, wantMsg: "unknown --type"},
		{name: "unknown charset", args: []string{"--charset", "leet"}, wantMsg: "unknown --charset"},
		{name: "length zero", args: []string{"--length", "0"}, wantMsg: "--length must be between 1 and"},
		{name: "length negative", args: []string{"--length", "-5"}, wantMsg: "--length must be between 1 and"},
		{name: "length over cap", args: []string{"--length", "1048577"}, wantMsg: "--length must be between 1 and"},
		{name: "count zero", args: []string{"--count", "0"}, wantMsg: "--count must be between 1 and"},
		{name: "count over cap", args: []string{"--count", "10001"}, wantMsg: "--count must be between 1 and"},
		{name: "uuid with length", args: []string{"--type", "uuid", "--length", "10"}, wantMsg: "--length does not apply to uuid"},
		{name: "uuid with charset", args: []string{"--type", "uuid", "--charset", "symbols"}, wantMsg: "--charset does not apply to uuid"},
		{name: "charset with hex", args: []string{"--type", "hex", "--charset", "symbols"}, wantMsg: "--charset only applies to --type password"},
		{name: "unknown format", args: []string{"--format", "yaml"}, wantMsg: "unknown --format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := runGenerate(t, t.TempDir(), tt.args...)
			require.Error(t, err)
			assert.Empty(t, out, "invalid invocation must not write to stdout")
			assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

// cyclicReader yields every byte value 0..255 in order, forever — a
// deterministic stream that exercises the rejection-sampling path exactly.
type cyclicReader struct{ next byte }

func (c *cyclicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.next
		c.next++
	}
	return len(p), nil
}

// TestRandomFromAlphabet_RejectionSamplingUnbiased — for each alphabet the
// cyclic stream (bytes 0..255 repeating) must yield identical counts per
// symbol: bytes at or above the limit must be rejected, and the accepted
// prefix must divide evenly. A naive b%k mapping or a byte-wrapping limit
// (k dividing 256 historically wrapped the limit to 0, rejecting every
// byte and looping forever) breaks these exact counts.
func TestRandomFromAlphabet_RejectionSamplingUnbiased(t *testing.T) {
	orig := genRandReader
	genRandReader = &cyclicReader{next: 0}
	defer func() { genRandReader = orig }()

	// n per alphabet = two full cycles of accepted bytes, so an unbiased
	// implementation emits every symbol exactly wantEach times.
	tests := []struct {
		name     string
		alphabet string
		n        int
		wantEach int
	}{
		{name: "hex k=16 accepts all", alphabet: generateHex, n: 512, wantEach: 32},
		{name: "base64 k=64 accepts all", alphabet: generateBase64, n: 512, wantEach: 8},
		{name: "alnum k=62 rejects 8", alphabet: generateAlnum, n: 496, wantEach: 8},
		{name: "symbols k=22 rejects 14", alphabet: generateSymbols, n: 484, wantEach: 22},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := randomFromAlphabet(tt.n, tt.alphabet, genRandReader)
			require.NoError(t, err)
			require.Len(t, out, tt.n, "rejected bytes must not shrink output length")

			counts := map[byte]int{}
			for i := range out {
				counts[out[i]]++
			}
			require.Len(t, counts, len(tt.alphabet), "every alphabet symbol must be emitted")
			for i := range tt.alphabet {
				assert.Equal(t, tt.wantEach, counts[tt.alphabet[i]],
					"symbol %q count over two unbiased cycles", tt.alphabet[i])
			}
		})
	}
}

func TestRandomFromAlphabet_ShortReadErrors(t *testing.T) {
	_, err := randomFromAlphabet(10, generateHex, strings.NewReader("abc"))
	require.Error(t, err)
}

func TestUUIDV4_ErrorsOnShortRandomStream(t *testing.T) {
	_, err := uuidV4(strings.NewReader("short"))
	require.Error(t, err)
}

// TestGenerateCmd_SetStoresValue — --set reuses the provider set path; the
// stored value must equal the stdout value, and the status goes to stderr.
func TestGenerateCmd_SetStoresValue(t *testing.T) {
	dir := writeEmptyLocalConfig(t)
	out, errBuf, err := runGenerate(t, dir, "--type", "hex", "--length", "16", "--set", "GEN_KEY")
	require.NoError(t, err)

	value := strings.TrimSuffix(out, "\n")
	assert.Regexp(t, `^[0-9a-f]{16}$`, value)
	assert.Contains(t, errBuf, "Set GEN_KEY")

	t.Chdir(dir)
	_, p, err := loadProvider(&GlobalOpts{})
	require.NoError(t, err)
	defer p.Close()
	secret, err := p.Get(t.Context(), "GEN_KEY")
	require.NoError(t, err, "the generated value must be readable back from the provider")
	assert.Equal(t, value, secret.Value)
}

func TestGenerateCmd_SetJSONEnvelopeIncludesKey(t *testing.T) {
	dir := writeEmptyLocalConfig(t)
	out, _, err := runGenerate(t, dir, "--type", "password", "--length", "20", "--set", "JSON_KEY", "--format", "json")
	require.NoError(t, err)
	var res GenerateResult
	require.NoError(t, json.Unmarshal([]byte(out), &res))
	assert.Equal(t, "JSON_KEY", res.Key)
	assert.Len(t, res.Value, 20)
}

func TestGenerateCmd_SetWithCountRejected(t *testing.T) {
	dir := writeEmptyLocalConfig(t)
	_, _, err := runGenerate(t, dir, "--type", "hex", "--length", "8", "--count", "2", "--set", "K")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
}

func TestGenerateCmd_PlainWithCountRejected(t *testing.T) {
	_, _, err := runGenerate(t, t.TempDir(), "--type", "hex", "--length", "8", "--count", "2", "--plain")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
}

// TestGenerateCmd_MissingConfigFailsBeforeGeneration — a --set without a
// config must fail with the config exit code and leave stdout empty (the
// generated value is discarded, never half-emitted).
func TestGenerateCmd_MissingConfigFailsBeforeGeneration(t *testing.T) {
	out, _, err := runGenerate(t, t.TempDir(), "--type", "hex", "--length", "8", "--set", "K")
	require.Error(t, err)
	assert.Empty(t, out)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	var se *skret.Error
	require.True(t, errors.As(err, &se))
}
