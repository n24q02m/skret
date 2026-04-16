package logging

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^sk-[a-zA-Z0-9]{20,}$`),               // OpenAI-style
	regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36,}$`),              // GitHub PAT
	regexp.MustCompile(`^dp\.st\.[a-zA-Z0-9]+$`),              // Doppler service token
	regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`),                  // AWS access key
	regexp.MustCompile(`(?i)^(password|secret|token|key)=.+`), // Key-value secrets
	regexp.MustCompile(`(?i)^[a-z0-9+/]{40,}={0,2}$`),         // Base64 (Generic)
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
		if shouldRedact(val) {
			return slog.String(a.Key, redacted)
		}
	}
	return a
}

// shouldRedact returns true if the value matches any secret pattern.
// It is optimized with fast-path checks (length, prefix, and basic string operations)
// to avoid expensive regex matching on every log attribute.
func shouldRedact(val string) bool {
	// Fast path: most log strings are short and won't match any secret pattern.
	// The shortest tracked secret is "key=v" (5 chars).
	if len(val) < 5 {
		return false
	}

	// Fast path: check specific prefixes.
	if strings.HasPrefix(val, "sk-") {
		return secretPatterns[0].MatchString(val)
	}
	if strings.HasPrefix(val, "ghp_") {
		return secretPatterns[1].MatchString(val)
	}
	if strings.HasPrefix(val, "AKIA") {
		return secretPatterns[3].MatchString(val)
	}
	if strings.HasPrefix(val, "dp.st.") {
		return secretPatterns[2].MatchString(val)
	}

	// Key-value secrets MUST contain '='.
	if strings.Contains(val, "=") {
		if secretPatterns[4].MatchString(val) {
			return true
		}
	}

	// Generic Base64 strings are at least 40 chars in our pattern.
	if len(val) >= 40 {
		return secretPatterns[5].MatchString(val)
	}

	return false
}
