package logging

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		level    string
		format   string
		expected slog.Level
	}{
		{"debug", "text", slog.LevelDebug},
		{"DEBUG", "text", slog.LevelDebug},
		{"warn", "text", slog.LevelWarn},
		{"warning", "json", slog.LevelWarn},
		{"error", "text", slog.LevelError},
		{"info", "text", slog.LevelInfo},
		{"unknown", "text", slog.LevelInfo},
		{"", "json", slog.LevelInfo},
	}

	for _, tt := range tests {
		name := tt.level
		if name == "" {
			name = "empty"
		}
		t.Run(name+"_"+tt.format, func(t *testing.T) {
			Setup(tt.level, tt.format)
			handler := slog.Default().Handler()

			// Verify it's a RedactingHandler
			assert.IsType(t, &RedactingHandler{}, handler)

			// Verify level
			assert.True(t, handler.Enabled(context.Background(), tt.expected))
			if tt.expected > slog.LevelDebug {
				assert.False(t, handler.Enabled(context.Background(), tt.expected-1))
			}
		})
	}
}
