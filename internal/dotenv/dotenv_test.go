package dotenv_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/dotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoundTrip is the core contract: Encode then Decode returns the exact bytes
// for every adversarial value, so secrets survive env/sync -> import.
func TestRoundTrip(t *testing.T) {
	values := map[string]string{
		"plain":            "simplevalue",
		"bcrypt":           "$2a$14$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"pg-url-dollar":    "postgres://u:p$word@host/db",
		"ref-like":         "x${HOME}y",
		"double-dollar":    "price-$$100",
		"double-quote":     `has"quote`,
		"single-quote":     "has'quote",
		"backtick":         "a`b",
		"backslash":        `a\b`,
		"newline":          "line1\nline2",
		"crlf":             "line1\r\nline2",
		"tab":              "a\tb",
		"equals":           "k=v=w",
		"hash":             "a#b",
		"leading-space":    "  lead",
		"trailing-space":   "trail  ",
		"only-spaces":      "   ",
		"empty":            "",
		"unicode":          "秘密",
		"regex-metachars":  ".*[a-z](x|y)",
		"pem-like":         "-----BEGIN KEY-----\nabc\\n+def==\n-----END KEY-----",
		"quotes-and-slash": `a"b\c'd`,
	}
	for name, want := range values {
		t.Run(name, func(t *testing.T) {
			line := dotenv.Encode("KEY", want)
			k, got, ok := dotenv.Decode(line)
			require.True(t, ok, "Decode must succeed for line %q", line)
			assert.Equal(t, "KEY", k)
			assert.Equal(t, want, got, "round-trip mismatch for line %q", line)
		})
	}
}

func TestEncode_SafeValuesBare(t *testing.T) {
	assert.Equal(t, "KEY=simple", dotenv.Encode("KEY", "simple"))
	assert.Equal(t, "KEY=a-b_c.123", dotenv.Encode("KEY", "a-b_c.123"))
}

func TestEncode_DollarValueQuotedNotExpandable(t *testing.T) {
	// A value with '$' is quoted (consumer-expansion hazard) and escaped only as needed.
	assert.Equal(t, `KEY="a$b"`, dotenv.Encode("KEY", "a$b"))
}

func TestDecode_SkipsCommentsAndBlanks(t *testing.T) {
	for _, line := range []string{"", "   ", "# comment", "  # spaced comment"} {
		_, _, ok := dotenv.Decode(line)
		assert.False(t, ok, "line %q should be skipped", line)
	}
}

func TestDecode_StripsExportPrefix(t *testing.T) {
	k, v, ok := dotenv.Decode(`export FOO="bar"`)
	require.True(t, ok)
	assert.Equal(t, "FOO", k)
	assert.Equal(t, "bar", v)
}

func TestDecode_SingleQuotedIsLiteral(t *testing.T) {
	// Single quotes do not process escapes: backslash-n stays two characters.
	k, v, ok := dotenv.Decode(`FOO='a\nb'`)
	require.True(t, ok)
	assert.Equal(t, "FOO", k)
	assert.Equal(t, `a\nb`, v)
}

func TestDecode_BareValueVerbatim(t *testing.T) {
	// No TrimSpace: trailing space in a bare value is preserved (byte-faithful diff).
	_, v, ok := dotenv.Decode("FOO=secret ")
	require.True(t, ok)
	assert.Equal(t, "secret ", v)
}

func TestDecode_BacktickNotAQuote(t *testing.T) {
	// Backtick is not a dotenv quote delimiter; a backtick-wrapped value is literal.
	_, v, ok := dotenv.Decode("FOO=`tick`")
	require.True(t, ok)
	assert.Equal(t, "`tick`", v)
}

func TestDecode_NoEquals(t *testing.T) {
	_, _, ok := dotenv.Decode("JUST_A_KEY")
	assert.False(t, ok)
}
