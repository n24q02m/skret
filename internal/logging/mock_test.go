package logging_test

import (
	"context"
	"log/slog"
)

type mockHandler struct {
	slog.Handler
	enabledFunc func(context.Context, slog.Level) bool
}

func (m *mockHandler) Enabled(ctx context.Context, l slog.Level) bool {
	if m.enabledFunc != nil {
		return m.enabledFunc(ctx, l)
	}
	return false
}

func (m *mockHandler) Handle(ctx context.Context, r slog.Record) error {
	return nil
}

func (m *mockHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(name string) slog.Handler {
	return m
}
