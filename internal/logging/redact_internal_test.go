package logging

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockHandler struct {
	err    error
	record slog.Record
}

func (m *mockHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (m *mockHandler) Handle(ctx context.Context, r slog.Record) error {
	m.record = r
	return m.err
}

func (m *mockHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(name string) slog.Handler {
	return m
}

func TestRedactingHandler_Handle(t *testing.T) {
	t.Run("redacts message and attributes", func(t *testing.T) {
		mock := &mockHandler{}
		h := NewRedactingHandler(mock)

		// We use clearly fake data and #nosec to avoid security scanner alerts.
		// #nosec G101
		token := "sk-" + "abcdefghijklmnopqrstuvwxyz"
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "failed with "+token, 0)
		r.AddAttrs(slog.String("secret_key", token), slog.String("normal", "value"))

		err := h.Handle(context.Background(), r)
		assert.NoError(t, err)

		assert.Equal(t, "failed with [REDACTED]", mock.record.Message)

		attrs := make(map[string]slog.Value)
		mock.record.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value
			return true
		})

		assert.Equal(t, "[REDACTED]", attrs["secret_key"].String())
		assert.Equal(t, "value", attrs["normal"].String())
	})

	t.Run("propagates error", func(t *testing.T) {
		expectedErr := errors.New("handler error")
		mock := &mockHandler{err: expectedErr}
		h := NewRedactingHandler(mock)

		r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
		err := h.Handle(context.Background(), r)
		assert.ErrorIs(t, err, expectedErr)
	})
}

func TestRedactString_Coverage(t *testing.T) {
	// We use clearly fake data and #nosec to avoid security scanner alerts.
	// #nosec G101
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Short", "123", "123"},
		{"NoMatch", "hello world", "hello world"},
		{"EqMatch", "password" + "=fake_pass", "password=[REDACTED]"},
		{"EqNoMatch", "other=val", "other=val"},
		{"SkMatch", "sk-" + strings.Repeat("x", 20), "[REDACTED]"},
		{"SkNoMatch", "sk-123", "sk-123"},
		{"DpMatch", "dp.st." + strings.Repeat("d", 10), "[REDACTED]"},
		{"DpNoMatch", "dp.st.", "dp.st."},
		{"GhpMatch", "ghp_" + strings.Repeat("y", 36), "[REDACTED]"},
		{"GhpNoMatch", "ghp_123", "ghp_123"},
		{"AkiaMatch", "AKIA" + "1234567890ABCDEF", "[REDACTED]"},
		{"AkiaNoMatch", "AKIA123", "AKIA123"},
		{"B64Match", strings.Repeat("z", 40), "[REDACTED]"},
		{"B64NoMatch", "short_b64", "short_b64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactString(tt.input))
		})
	}
}
