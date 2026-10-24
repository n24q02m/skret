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
	fast string
}

var secretPatterns = []pattern{
	{regexp.MustCompile(`(?i)((password|secret|token|key|api_key|auth)=)[^\s&]+`), "${1}[REDACTED]", "="},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "[REDACTED]", "sk-"},
	{regexp.MustCompile(`dp\.st\.[a-zA-Z0-9]+`), "[REDACTED]", "dp.st."},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`), "[REDACTED]", "ghp_"},
	{regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "[REDACTED]", "AKIA"},
	{regexp.MustCompile(`(?i)[a-z0-9+/]{40,}={0,2}`), "[REDACTED]", ""}, // Base64-like
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
	for _, part := range sensitiveKeyParts {
		if containsCaseInsensitive(key, part) {
			return true
		}
	}
	return false
}

func containsCaseInsensitive(s, substr string) bool {
	n := len(substr)
	if n == 0 {
		return true
	}
	c0 := substr[0]
	c0Upper := c0
	if c0 >= 'a' && c0 <= 'z' {
		c0Upper = c0 - 32
	}

	for i := 0; i <= len(s)-n; {
		idxLower := strings.IndexByte(s[i:], c0)
		idxUpper := -1
		if c0 != c0Upper {
			idxUpper = strings.IndexByte(s[i:], c0Upper)
		}

		idx := idxLower
		if idxUpper != -1 && (idx == -1 || idxUpper < idx) {
			idx = idxUpper
		}

		if idx == -1 {
			return false
		}

		i += idx
		if i > len(s)-n {
			return false
		}

		match := true
		for j := 1; j < n; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
		i++
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
		if p.fast != "" && !strings.Contains(val, p.fast) {
			continue
		}
		val = p.re.ReplaceAllString(val, p.repl)
	}
	return val
}
