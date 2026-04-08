package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/stretchr/testify/assert"
)

func TestRedactingHandler_RedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("test",
		"api_key", "sk-abc123def456ghi789jkl012mno",
		"normal", "hello world",
	)

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
	assert.Contains(t, output, "hello world")
	assert.NotContains(t, output, "sk-abc123def456ghi789jkl012mno")
}

func TestRedactingHandler_RedactsGitHubPAT(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("test", "token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
}

func TestRedactingHandler_PassesNonSecrets(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("test", "name", "John", "count", 42)

	output := buf.String()
	assert.Contains(t, output, "John")
	assert.NotContains(t, output, "[REDACTED]")
}

func TestRedactingHandler_Enabled(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	handler := logging.NewRedactingHandler(inner)

	assert.False(t, handler.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, handler.Enabled(context.Background(), slog.LevelWarn))
}

func TestSetup(t *testing.T) {
	// Just verify it doesn't panic
	logging.Setup("debug", "text")
	logging.Setup("info", "json")
	logging.Setup("error", "")
}
