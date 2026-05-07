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

func TestRedactingHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)

	h2 := handler.WithAttrs([]slog.Attr{
		slog.String("static_key", "sk-abc123def456ghi789jkl012mno"),
		slog.String("static_normal", "value"),
	})
	logger := slog.New(h2)

	logger.Info("test")

	output := buf.String()
	assert.Contains(t, output, "static_key=[REDACTED]")
	assert.Contains(t, output, "static_normal=value")
	assert.NotContains(t, output, "sk-abc123def456ghi789jkl012mno")
}

func TestRedactingHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)

	h2 := handler.WithGroup("mygroup")
	logger := slog.New(h2)

	logger.Info("test", "key", "sk-abc123def456ghi789jkl012mno")

	output := buf.String()
	assert.Contains(t, output, "mygroup.key=[REDACTED]")
	assert.NotContains(t, output, "sk-abc123def456ghi789jkl012mno")
}

func TestRedactingHandler_KeyBasedRedaction(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	tests := []struct {
		key   string
		value string
	}{
		{"password", "p4ssw0rd"},
		{"user_token", "abc-123"},
		{"API_KEY", "secret-value"},
		{"db_secret", "my-secret"},
		{"access_token", "tok-123"},
	}

	for _, tt := range tests {
		buf.Reset()
		logger.Info("test", tt.key, tt.value)
		output := buf.String()
		assert.Contains(t, output, tt.key+"=[REDACTED]", "Key %s should be redacted", tt.key)
		assert.NotContains(t, output, tt.value)
	}
}

func TestRedactingHandler_EmbeddedRedaction(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	tests := []struct {
		msg      string
		expected string
	}{
		{"failed to auth with password=secret123", "failed to auth with password=[REDACTED]"},
		{"token is ghp_123456789012345678901234567890123456", "token is [REDACTED]"},
		{"key=val1&secret=val2&other=val3", "key=[REDACTED]&secret=[REDACTED]&other=val3"},
		{"OpenAI key sk-123456789012345678901234", "OpenAI key [REDACTED]"},
	}

	for _, tt := range tests {
		buf.Reset()
		logger.Info(tt.msg)
		output := buf.String()
		assert.Contains(t, output, "msg=\""+tt.expected+"\"")
	}
}

func TestSetup(t *testing.T) {
	logging.Setup("debug", "text")
	logging.Setup("info", "json")
	logging.Setup("error", "")
}
