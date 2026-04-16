package logging_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		level    string
		format   string
		expected slog.Level
	}{
		{"debug", "text", slog.LevelDebug},
		{"INFO", "json", slog.LevelInfo},
		{"warn", "text", slog.LevelWarn},
		{"warning", "text", slog.LevelWarn},
		{"error", "text", slog.LevelError},
		{"unknown", "text", slog.LevelInfo},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("Level_%s_Format_%s", tt.level, tt.format)
		t.Run(name, func(t *testing.T) {
			logging.Setup(tt.level, tt.format)
			h := slog.Default().Handler()

			assert.True(t, h.Enabled(context.Background(), tt.expected), "Level %s should be enabled", tt.expected)
			if tt.expected > slog.LevelDebug {
				assert.False(t, h.Enabled(context.Background(), tt.expected-1), "Level %s should not be enabled", tt.expected-1)
			}
		})
	}
}
