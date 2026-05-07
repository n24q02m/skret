package logging

import (
	"context"
	"log/slog"
	"regexp"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[a-z0-9+/]{40,}={0,2}`),                 // Base64
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),                       // OpenAI-style
	regexp.MustCompile(`dp\.st\.[a-zA-Z0-9]+`),                      // Doppler service token
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`),                      // GitHub PAT
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),                          // AWS access key
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

	newRecord := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	for _, a := range attrs {
		newRecord.AddAttrs(a)
	}
	return h.inner.Handle(ctx, newRecord)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redactedAttrs := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redactedAttrs[i] = redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redactedAttrs)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		val := a.Value.String()
		// Redact embedded secrets in strings
		if redactedVal := redactString(val); redactedVal != val {
			return slog.String(a.Key, redactedVal)
		}
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

func redactString(s string) string {
	if len(s) < 5 {
		return s
	}

	for _, p := range secretPatterns {
		if p.NumSubexp() > 0 {
			s = p.ReplaceAllString(s, "${1}"+redacted)
		} else {
			s = p.ReplaceAllString(s, redacted)
		}
	}
	return s
}
