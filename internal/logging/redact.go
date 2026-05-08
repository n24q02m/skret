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
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, redactAttr(a))
		return true
	})

	newRecord := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	for _, a := range attrs {
		newRecord.AddAttrs(a)
	}
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
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func isSensitiveKey(key string) bool {
	hasUpper := false
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}

	if !hasUpper {
		for _, part := range sensitiveKeyParts {
			if strings.Contains(key, part) {
				return true
			}
		}
		return false
	}

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
	for _, p := range secretPatterns {
		val = p.re.ReplaceAllString(val, p.repl)
	}
	return val
}
