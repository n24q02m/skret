package logging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactStringExportsPatternRedaction(t *testing.T) {
	assert.Equal(t, "token=[REDACTED] rest", RedactString("token=abc123xyz rest"))
	assert.Equal(t, "plain text", RedactString("plain text"))
}

func TestRedactorRedactsKnownValues(t *testing.T) {
	r := NewRedactor()
	r.Add("s3cr3t-value", "")
	assert.Equal(t, "failed: [REDACTED] here", r.Redact("failed: s3cr3t-value here"))
	assert.Equal(t, "nothing to hide", r.Redact("nothing to hide"))
}

// A known value that is a prefix of another must not leave the longer
// value's tail behind.
func TestRedactorReplacesLongestValueFirst(t *testing.T) {
	r := NewRedactor()
	r.Add("abcd")
	r.Add("abcdefgh")
	assert.Equal(t, "x [REDACTED] y [REDACTED]", r.Redact("x abcdefgh y abcd"))
}

// Values shorter than the minimum length collide with ordinary words and
// numbers, so they are not redacted by value.
func TestRedactorSkipsShortValues(t *testing.T) {
	r := NewRedactor()
	r.Add("abc", "1")
	assert.Equal(t, "abc 1", r.Redact("abc 1"))
}

// A value rendered with %q (escaped quotes and backslashes) is redacted too.
func TestRedactorRedactsQuotedForm(t *testing.T) {
	r := NewRedactor()
	v := `pa"ss\word`
	r.Add(v)
	out := r.Redact(fmt.Sprintf("secret %q not found", v))
	assert.NotContains(t, out, `pa\"ss`)
	assert.Contains(t, out, "[REDACTED]")
}

// Pattern redaction still applies after the known values.
func TestRedactorAppliesPatterns(t *testing.T) {
	r := NewRedactor()
	assert.Equal(t, "key [REDACTED]", r.Redact("key sk-abcdefghijklmnopqrstuvwxyz"))
}

// A nil Redactor still applies the patterns, so a zero-configured caller
// cannot skip redaction by accident.
func TestRedactorNilAppliesPatterns(t *testing.T) {
	var r *Redactor
	assert.Equal(t, "password=[REDACTED]", r.Redact("password=hunter22"))
}

func TestRedactorConcurrentUse(t *testing.T) {
	r := NewRedactor()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.Add(fmt.Sprintf("value-%04d", i))
		}()
		go func() {
			defer wg.Done()
			_ = r.Redact("value-0001 value-0002")
		}()
	}
	wg.Wait()
	out := r.Redact("value-0001 value-0019")
	assert.Equal(t, "[REDACTED] [REDACTED]", out)
}

// newValueTestLogger builds a logger whose records pass through a
// ValueRedactingHandler into a text buffer.
func newValueTestLogger(r *Redactor) (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewValueRedactingHandler(inner, r)), buf
}

type stringerValue struct{ s string }

func (v stringerValue) String() string { return v.s }

type valuerAttr struct{ s string }

func (v valuerAttr) LogValue() slog.Value { return slog.StringValue(v.s) }

// Every known value is scrubbed from the message, string attributes,
// errors, Stringers, LogValuers, nested groups, pre-bound attributes and
// group names before the record reaches the inner handler.
func TestValueRedactingHandlerScrubsKnownValues(t *testing.T) {
	const v = "known-value-77"
	r := NewRedactor()
	r.Add(v)
	logger, buf := newValueTestLogger(r)

	logger.With("bound", "pre "+v).WithGroup("g-"+v).Info("msg "+v,
		"key", v,
		"err", errors.New("failed: "+v),
		"str", stringerValue{"s " + v},
		"lv", valuerAttr{"lv " + v},
		slog.Group("nested", "inner", v),
		"count", 3,
		"token", "token=abcdef123456",
	)
	out := buf.String()
	assert.NotContains(t, out, v)
	assert.NotContains(t, out, "abcdef123456", "patterns apply too")
	assert.Contains(t, out, "[REDACTED]")
	assert.Contains(t, out, "count=3", "non-string values pass through")
}

func TestValueRedactingHandlerHonoursInnerLevel(t *testing.T) {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewValueRedactingHandler(inner, NewRedactor())
	assert.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, h.Enabled(context.Background(), slog.LevelError))
}

// Values added after the handler was built are scrubbed too: the handler
// reads the live Redactor, not a snapshot.
func TestValueRedactingHandlerSeesLaterValues(t *testing.T) {
	r := NewRedactor()
	logger, buf := newValueTestLogger(r)
	r.Add("late-value-1")
	logger.Debug("saw late-value-1")
	assert.NotContains(t, buf.String(), "late-value-1")
}

func TestMask(t *testing.T) {
	assert.Equal(t, "***", Mask(""))
	assert.Equal(t, "***", Mask("API_KEY"))
	assert.Equal(t, "***", Mask("12345678"))
	assert.Equal(t, "DATA..._URL", Mask("DATABASE_URL"))
	// Multi-byte runes are never split.
	assert.Equal(t, "ÄÖÜß...ÖÜßÄ", Mask("ÄÖÜßÄÖÜßÄ"))
}
