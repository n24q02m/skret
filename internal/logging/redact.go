package logging

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

type pattern struct {
	re   *regexp.Regexp
	repl string
}

var secretPatterns = []pattern{
	{regexp.MustCompile(`(?i)((password|secret|token|key|api_key|auth)=)[^\s&]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`dp\.st\.[a-zA-Z0-9]+`), "[REDACTED]"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`), "[REDACTED]"},
	{regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "[REDACTED]"},
	{regexp.MustCompile(`(?i)[a-z0-9+/]{40,}={0,2}`), "[REDACTED]"}, // Base64-like
}

var sensitiveKeyParts = []string{
	"password", "secret", "token", "api_key", "auth_key", "credential", "private_key",
}

const redacted = "[REDACTED]"

// RedactingHandler wraps a slog.Handler and redacts sensitive values.
type RedactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler creates a handler that redacts secret-like values.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, redactAttr(a))
		return true
	})

	newRecord := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	newRecord.AddAttrs(attrs...)
	return h.inner.Handle(ctx, newRecord)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	if isSensitiveKey(name) {
		name = redacted
	} else {
		name = redactString(name)
	}
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func isSensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func redactAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}

	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redactString(a.Value.String()))
	case slog.KindGroup:
		attrs := a.Value.Group()
		redactedAttrs := make([]slog.Attr, len(attrs))
		for i, attr := range attrs {
			redactedAttrs[i] = redactAttr(attr)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redactedAttrs...)}
	}
	return a
}

func redactString(val string) string {
	if len(val) < 5 {
		return val
	}

	// Pattern 1: key=val (case-insensitive)
	// We check for '=' as a fast path.
	if strings.Contains(val, "=") {
		if secretPatterns[0].re.MatchString(val) {
			val = secretPatterns[0].re.ReplaceAllString(val, secretPatterns[0].repl)
		}
	}

	// Patterns with fixed prefixes
	if strings.Contains(val, "sk-") {
		if secretPatterns[1].re.MatchString(val) {
			val = secretPatterns[1].re.ReplaceAllString(val, secretPatterns[1].repl)
		}
	}
	if strings.Contains(val, "dp.st.") {
		if secretPatterns[2].re.MatchString(val) {
			val = secretPatterns[2].re.ReplaceAllString(val, secretPatterns[2].repl)
		}
	}
	if strings.Contains(val, "ghp_") {
		if secretPatterns[3].re.MatchString(val) {
			val = secretPatterns[3].re.ReplaceAllString(val, secretPatterns[3].repl)
		}
	}
	if strings.Contains(val, "AKIA") {
		if secretPatterns[4].re.MatchString(val) {
			val = secretPatterns[4].re.ReplaceAllString(val, secretPatterns[4].repl)
		}
	}

	// Pattern 6: Base64-like (length 40+)
	// No fixed prefix, but must be at least 40 characters long.
	if len(val) >= 40 {
		if secretPatterns[5].re.MatchString(val) {
			val = secretPatterns[5].re.ReplaceAllString(val, secretPatterns[5].repl)
		}
	}

	return val
}
