package logging

import (
	"context"
	"log/slog"
	"regexp"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[a-z0-9+/]{40,}={0,2}`),           // Base64
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),                 // OpenAI-style
	regexp.MustCompile(`dp\.st\.[a-zA-Z0-9]+`),                // Doppler service token
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`),                // GitHub PAT
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),                    // AWS access key
	regexp.MustCompile(`(?i)((password|secret|token|key)=)[^\s&]+`), // Key-value secrets
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

	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
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

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		val := a.Value.String()
		redactedVal := redactString(val)
		if redactedVal != val {
			return slog.String(a.Key, redactedVal)
		}
	}
	return a
}

func redactString(val string) string {
	if len(val) < 5 {
		return val
	}
	for i, p := range secretPatterns {
		if i == 5 { // Key-value secrets pattern is at index 5
			val = p.ReplaceAllString(val, "${1}"+redacted)
		} else {
			val = p.ReplaceAllString(val, redacted)
		}
	}
	return val
}
