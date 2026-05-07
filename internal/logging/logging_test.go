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

	token := "sk-TESTINGTESTINGTESTING"
	logger.Info("test",
		"api_key", token,
		"normal", "hello world",
	)

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
	assert.Contains(t, output, "hello world")
	assert.NotContains(t, output, token)
}

func TestRedactingHandler_RedactsGitHubPAT(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	token := "ghp_TESTINGTESTINGTESTINGTESTINGTESTINGTEST"
	logger.Info("test", "token", token)

	output := buf.String()
	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, token)
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

	token := "sk-TESTINGTESTINGTESTING"
	h2 := handler.WithAttrs([]slog.Attr{
		slog.String("static_key", token),
		slog.String("static_normal", "value"),
	})
	logger := slog.New(h2)

	logger.Info("test")

	output := buf.String()
	assert.Contains(t, output, "static_key=[REDACTED]")
	assert.Contains(t, output, "static_normal=value")
	assert.NotContains(t, output, token)
}

func TestRedactingHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)

	token := "sk-TESTINGTESTINGTESTING"
	h2 := handler.WithGroup("mygroup")
	logger := slog.New(h2)

	logger.Info("test", "key", token)

	output := buf.String()
	assert.Contains(t, output, "mygroup.key=[REDACTED]")
	assert.NotContains(t, output, token)
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
		{"password", "my-test-password"},
		{"user_token", "test-token-value"},
		{"API_KEY", "test-api-key-value"},
		{"db_secret", "test-db-secret-value"},
		{"access_token", "test-access-token-value"},
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

	token := "ghp_TESTINGTESTINGTESTINGTESTINGTESTINGTEST"
	tests := []struct {
		msg      string
		expected string
	}{
		{"failed to auth with password=my-secret-val", "failed to auth with password=[REDACTED]"},
		{"token is " + token, "token is [REDACTED]"},
		{"key=valA&secret=valB&other=valC", "key=[REDACTED]&secret=[REDACTED]&other=valC"},
		{"OpenAI key sk-TESTINGTESTINGTESTING", "OpenAI key [REDACTED]"},
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
