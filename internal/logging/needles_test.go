package logging

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Fabricated test values only; none of them is a real credential.
const (
	needleValue = `p@ss "w0rd"/with+symbols&more`
	shortNeedle = "pa ss/w0rd&x"
)

// unquoted returns the %q form of v without the surrounding quotes, as it
// appears inside a quoted error message or JSON string.
func unquoted(v string) string {
	q := strconv.Quote(v)
	return q[1 : len(q)-1]
}

func TestValueNeedles_RawQuotedAndEncodedForms(t *testing.T) {
	got := ValueNeedles(needleValue, MinRedactedValueLen)
	v := []byte(needleValue)
	for name, want := range map[string]string{
		"raw":            needleValue,
		"%q":             unquoted(needleValue),
		"std base64":     base64.StdEncoding.EncodeToString(v),
		"url base64":     base64.URLEncoding.EncodeToString(v),
		"raw std base64": base64.RawStdEncoding.EncodeToString(v),
		"raw url base64": base64.RawURLEncoding.EncodeToString(v),
		"query escape":   url.QueryEscape(needleValue),
		"path escape":    url.PathEscape(needleValue),
	} {
		assert.Contains(t, got, want, name)
	}
	assert.Equal(t, needleValue, got[0], "the raw value comes first")
}

func TestValueNeedles_MultilineValue(t *testing.T) {
	const v = "-----BEGIN FAKE KEY-----\nMIIfakeLINEone\r\nMIIfakeLINEtwo\n-----END FAKE KEY-----"
	got := ValueNeedles(v, MinRedactedValueLen)
	for _, line := range []string{"-----BEGIN FAKE KEY-----", "MIIfakeLINEone", "MIIfakeLINEtwo", "-----END FAKE KEY-----"} {
		assert.Contains(t, got, line, "each line is a needle, without its CR")
	}
	assert.Contains(t, got, unquoted(v), "JSON-style escaping")

	const lf = "line-one-value\nline-two-value"
	assert.Contains(t, ValueNeedles(lf, MinRedactedValueLen), "line-one-value\r\nline-two-value",
		"an LF value is also matched as printed with CRLF")
}

func TestValueNeedles_EmbeddedBase64(t *testing.T) {
	const v = "s3cr3t-Value"
	header := base64.StdEncoding.EncodeToString([]byte("user:" + v))
	covered := false
	for _, n := range ValueNeedles(v, MinRedactedValueLen) {
		if len(n) >= 8 && strings.Contains(header, n) {
			covered = true
		}
	}
	assert.True(t, covered, "a needle covers the value base64-encoded at an offset (basic auth)")
}

func TestValueNeedles_LengthFilterAndDedup(t *testing.T) {
	assert.Nil(t, ValueNeedles("abc", MinRedactedValueLen), "values shorter than minLen have no needles")
	assert.Nil(t, ValueNeedles("", 1))

	got := ValueNeedles("ab\nlong-line-value", 4)
	assert.NotContains(t, got, "ab", "derived needles shorter than minLen are dropped")
	assert.Contains(t, got, "long-line-value")

	seen := map[string]bool{}
	for _, n := range ValueNeedles(needleValue, 1) {
		assert.False(t, seen[n], "duplicate needle %q", n)
		assert.NotEmpty(t, n)
		seen[n] = true
	}
}

func TestEmbeddedBase64_ValueTooShortForOffset(t *testing.T) {
	assert.Empty(t, embeddedBase64(base64.RawStdEncoding, []byte("a"), 1))
	assert.NotEmpty(t, embeddedBase64(base64.RawStdEncoding, []byte("abc"), 0))
}

// Redactor derives its needles from ValueNeedles, so a value printed
// base64-encoded or URL-escaped is scrubbed from log text too.
func TestRedactorUsesValueNeedles(t *testing.T) {
	r := NewRedactor()
	r.Add(shortNeedle)
	for _, form := range []string{
		base64.StdEncoding.EncodeToString([]byte(shortNeedle)),
		url.QueryEscape(shortNeedle),
	} {
		assert.Equal(t, "value [REDACTED] end", r.Redact("value "+form+" end"), form)
	}
}
