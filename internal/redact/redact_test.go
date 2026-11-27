package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fabricated test values only; none of them is a real credential.
const (
	fakeSecret   = "hunter2-correct-horse-battery"
	fakePassword = "p@ss w0rd/with+symbols&more"
)

var fakeMultiline = "-----BEGIN FAKE KEY-----\nMIIfakeLINEone0123456789\nMIIfakeLINEtwo9876543210\n-----END FAKE KEY-----"

// fakeGitHubToken matches the log redactor's ghp_ pattern; it is assembled at
// runtime so the source never contains a token-shaped literal.
func fakeGitHubToken() string { return "ghp_" + strings.Repeat("a1B2", 9) }

// mask writes input through a fresh Writer in the given chunk sizes (cycled)
// and returns everything that reached the destination after Close.
func mask(t *testing.T, s *Set, input string, chunks ...int) string {
	t.Helper()
	var dst bytes.Buffer
	w := s.NewWriter(&dst)
	data := []byte(input)
	for i, c := 0, 0; i < len(data); c++ {
		n := len(data) - i
		if len(chunks) > 0 {
			n = min(chunks[c%len(chunks)], n)
		}
		written, err := w.Write(data[i : i+n])
		require.NoError(t, err)
		require.Equal(t, n, written)
		i += n
	}
	require.NoError(t, w.Close())
	return dst.String()
}

func TestWriter_MasksLiteralValue(t *testing.T) {
	s := NewSet([]string{fakeSecret}, 4)
	out := mask(t, s, "db password is "+fakeSecret+" ok\n")
	assert.Equal(t, "db password is "+Marker+" ok\n", out)
}

func TestWriter_SecretSplitAtEveryChunkBoundary(t *testing.T) {
	s := NewSet([]string{fakeSecret}, 4)
	input := "before " + fakeSecret + " after\n"
	want := mask(t, s, input)
	require.NotContains(t, want, fakeSecret)
	for split := 1; split < len(input); split++ {
		got := mask(t, s, input, split, len(input))
		assert.Equal(t, want, got, "split at %d", split)
		assert.NotContains(t, got, fakeSecret[:len(fakeSecret)/2+1])
	}
}

func TestWriter_ByteAtATime(t *testing.T) {
	s := NewSet([]string{fakeSecret, fakePassword}, 4)
	input := "a=" + fakeSecret + "\nb=" + fakePassword + "\n"
	assert.Equal(t, mask(t, s, input), mask(t, s, input, 1))
	assert.Equal(t, "a="+Marker+"\nb="+Marker+"\n", mask(t, s, input, 1))
}

func TestWriter_RandomChunkingNeverLosesOrDuplicatesBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	s := NewSet([]string{fakeSecret, fakePassword, fakeMultiline}, 4)
	input := strings.Join([]string{
		"start", fakeSecret, base64.StdEncoding.EncodeToString([]byte(fakePassword)),
		url.QueryEscape(fakePassword), fakeMultiline, fakeGitHubToken(), "end\n",
	}, " | ")
	want := mask(t, s, input)
	for _, secret := range []string{fakeSecret, fakePassword, fakeMultiline, fakeGitHubToken()} {
		require.NotContains(t, want, secret)
	}
	for range 200 {
		chunks := make([]int, 1+rng.Intn(8))
		for i := range chunks {
			chunks[i] = 1 + rng.Intn(40)
		}
		assert.Equal(t, want, mask(t, s, input, chunks...), "chunks %v", chunks)
	}
}

func TestWriter_PassesCleanBytesThroughExactly(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	s := NewSet([]string{fakeSecret}, 4)
	raw := make([]byte, 4096)
	for i := range raw {
		// Printable text with whitespace, plus the secret's first bytes so
		// the writer keeps entering and abandoning partial matches.
		raw[i] = "hunt \n\tabcxyz019"[rng.Intn(16)]
	}
	for _, chunk := range []int{1, 3, 17, 512, 4096} {
		assert.Equal(t, string(raw), mask(t, s, string(raw), chunk), "chunk %d", chunk)
	}
}

func TestWriter_MultilineValue(t *testing.T) {
	s := NewSet([]string{fakeMultiline}, 4)
	lines := strings.Split(fakeMultiline, "\n")

	assert.Equal(t, "key:\n"+Marker+"\n", mask(t, s, "key:\n"+fakeMultiline+"\n", 5))
	crlf := strings.ReplaceAll(fakeMultiline, "\n", "\r\n")
	assert.Equal(t, "key:\r\n"+Marker+"\r\n", mask(t, s, "key:\r\n"+crlf+"\r\n", 3))

	// A single line of the value, printed on its own, is masked too.
	out := mask(t, s, "line: "+lines[1]+"\n", 2)
	assert.Equal(t, "line: "+Marker+"\n", out)

	// JSON-style escaping keeps every line masked.
	escaped := strings.ReplaceAll(fakeMultiline, "\n", `\n`)
	out = mask(t, s, `{"key":"`+escaped+`"}`+"\n", 7)
	for _, line := range lines {
		assert.NotContains(t, out, line)
	}
}

func TestWriter_EncodedForms(t *testing.T) {
	s := NewSet([]string{fakePassword}, 4)
	v := []byte(fakePassword)
	forms := map[string]string{
		"std base64":     base64.StdEncoding.EncodeToString(v),
		"url base64":     base64.URLEncoding.EncodeToString(v),
		"raw std base64": base64.RawStdEncoding.EncodeToString(v),
		"raw url base64": base64.RawURLEncoding.EncodeToString(v),
		"query escape":   url.QueryEscape(fakePassword),
		"path escape":    url.PathEscape(fakePassword),
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			out := mask(t, s, "value: "+form+"\n", 3)
			assert.Equal(t, "value: "+Marker+"\n", out)
		})
	}
}

func TestWriter_EmbeddedBase64(t *testing.T) {
	// Short enough that the generic base64 pattern (40+ chars) cannot be
	// what masks it: only the embedded-offset needles can.
	const short = "s3cr3t-Value"
	s := NewSet([]string{short}, 4)
	embedded := map[string]string{
		"basic auth header (offset 2)": base64.StdEncoding.EncodeToString([]byte("user:" + short)),
		"offset 1 with trailing bytes": base64.StdEncoding.EncodeToString([]byte("x" + short + "tail")),
		"offset 0 with trailing bytes": base64.URLEncoding.EncodeToString([]byte("abc" + short + "z")),
	}
	for name, form := range embedded {
		t.Run(name, func(t *testing.T) {
			require.Less(t, len(form), 40)
			out := mask(t, s, "Authorization: Basic "+form+"\n", 5)
			assert.Contains(t, out, Marker)
			// Every character that depends only on the secret is masked.
			assert.NotContains(t, out, form[8:14])
		})
	}
}

func TestWriter_MasksLogRedactionPatterns(t *testing.T) {
	s := NewSet(nil, 4)
	token := fakeGitHubToken()
	input := "export GITHUB_TOKEN " + token + "\nnext line\n"
	want := "export GITHUB_TOKEN " + Marker + "\nnext line\n"
	for _, chunk := range []int{1, 5, 13, len(input)} {
		assert.Equal(t, want, mask(t, s, input, chunk), "chunk %d", chunk)
	}
}

func TestWriter_OverlappingValuesMaskTheUnion(t *testing.T) {
	s := NewSet([]string{"abcdef", "defghi"}, 4)
	assert.Equal(t, "x "+Marker+" y", mask(t, s, "x abcdefghi y", 2))
}

func TestWriter_LongerValueWinsOverItsPrefix(t *testing.T) {
	s := NewSet([]string{"abcd1234", "abcd1234efgh"}, 4)
	for split := 1; split < 16; split++ {
		assert.Equal(t, "<"+Marker+">", mask(t, s, "<abcd1234efgh>", split), "split %d", split)
	}
	assert.Equal(t, "<"+Marker+"xy>", mask(t, s, "<abcd1234xy>", 9))
}

func TestWriter_ShortAndEmptyValuesAreSkipped(t *testing.T) {
	s := NewSet([]string{"", "abc", "true"}, 5)
	assert.Equal(t, "abc true\n", mask(t, s, "abc true\n"))
	assert.Equal(t, 0, s.Len())

	// minLen below one selects the log redactor's minimum.
	s = NewSet([]string{"abc", "abcd"}, 0)
	require.Equal(t, 4, logging.MinRedactedValueLen)
	assert.Equal(t, "abc "+Marker+"\n", mask(t, s, "abc abcd\n"))

	s = NewSet([]string{"abc"}, 1)
	assert.Equal(t, Marker+"\n", mask(t, s, "abc\n"))
}

func TestWriter_MasksQuotedForm(t *testing.T) {
	const v = `pa"ss\word`
	s := NewSet([]string{v}, 4)
	out := mask(t, s, fmt.Sprintf("error: secret %q rejected\n", v), 3)
	assert.Equal(t, `error: secret "`+Marker+`" rejected`+"\n", out)
}

func TestWriter_FlushesOnNewlineWithoutClose(t *testing.T) {
	s := NewSet([]string{fakeSecret}, 4)
	var dst bytes.Buffer
	w := s.NewWriter(&dst)

	_, err := w.Write([]byte("first line\nsecond "))
	require.NoError(t, err)
	assert.Equal(t, "first line\nsecond ", dst.String())

	// A possible secret prefix is held back until it is disproved...
	_, err = w.Write([]byte(fakeSecret[:5]))
	require.NoError(t, err)
	assert.Equal(t, "first line\nsecond ", dst.String())

	// ...and released, byte-exact, as soon as a newline disproves it.
	_, err = w.Write([]byte("\n"))
	require.NoError(t, err)
	assert.Equal(t, "first line\nsecond "+fakeSecret[:5]+"\n", dst.String())
	require.NoError(t, w.Close())
	require.NoError(t, w.Close()) // idempotent
	assert.Equal(t, "first line\nsecond "+fakeSecret[:5]+"\n", dst.String())
}

func TestWriter_HoldBackIsBounded(t *testing.T) {
	s := NewSet([]string{fakeSecret}, 4)
	var dst bytes.Buffer
	w := s.NewWriter(&dst)

	long := strings.Repeat(".", maxHeld+10)
	_, err := w.Write([]byte(long))
	require.NoError(t, err)
	assert.Equal(t, long, dst.String(), "a whitespace-free run longer than maxHeld is flushed")
	assert.LessOrEqual(t, len(w.pending), len(fakeSecret)-1)
}

// The bound applies to the whitespace-free tail, not to everything held: a
// long run followed by a newline must not force out a token that is still
// arriving after it.
func TestWriter_HoldBackBoundsOnlyTheTail(t *testing.T) {
	s := NewSet(nil, 4)
	var dst bytes.Buffer
	w := s.NewWriter(&dst)
	token := fakeGitHubToken()
	run := strings.Repeat(".", 40<<10)
	filler := strings.Repeat(".", 30<<10)

	for _, chunk := range []string{run, "\n" + filler + " " + token[:20], token[20:] + "\n"} {
		_, err := w.Write([]byte(chunk))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	out, clean := dst.String(), run+"\n"+filler
	require.True(t, strings.HasPrefix(out, clean), "clean text passes through unchanged")
	assert.Equal(t, " "+Marker+"\n", out[len(clean):])
}

func TestWriter_CloseFlushesTrailingPartialMatch(t *testing.T) {
	s := NewSet([]string{fakeSecret}, 4)
	assert.Equal(t, "tail "+fakeSecret[:6], mask(t, s, "tail "+fakeSecret[:6]))
	assert.Equal(t, "tail "+Marker, mask(t, s, "tail "+fakeSecret, 4))
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

func TestWriter_PropagatesDestinationErrors(t *testing.T) {
	boom := errors.New("boom")
	s := NewSet([]string{fakeSecret}, 4)

	w := s.NewWriter(failingWriter{boom})
	n, err := w.Write([]byte("line\n"))
	assert.Equal(t, 0, n)
	require.ErrorIs(t, err, boom)
	_, err = w.Write([]byte("more\n"))
	require.ErrorIs(t, err, boom, "the error is sticky")
	require.ErrorIs(t, w.Close(), boom)

	w = s.NewWriter(failingWriter{boom})
	_, err = w.Write([]byte("nowhitespaceyet"))
	require.NoError(t, err)
	require.ErrorIs(t, w.Close(), boom)
}

func TestSet_DeduplicatesNeedles(t *testing.T) {
	a := NewSet([]string{fakeSecret}, 4)
	b := NewSet([]string{fakeSecret, fakeSecret}, 4)
	assert.Equal(t, a.Len(), b.Len())
	assert.Positive(t, a.Len())
}

func TestWriter_ShortLinesOfMultilineValueAreNotMaskedAlone(t *testing.T) {
	s := NewSet([]string{"ab\nlong-line-value"}, 4)
	assert.Equal(t, "ab "+Marker+"\n", mask(t, s, "ab long-line-value\n"))
	assert.Equal(t, "x "+Marker+" y", mask(t, s, "x ab\nlong-line-value y"))
}
