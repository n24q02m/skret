package logging

import (
	"context"
	"errors"
	"log/slog"
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

		token := "sk-" + "TEST" + "1234567890" + "1234567890"
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
