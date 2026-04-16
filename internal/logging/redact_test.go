package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldRedact(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"OpenAI Key", "sk-abc123def456ghi789jkl012mno", true},
		{"GitHub PAT", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true},
		{"Base64", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Cg==", true},
		{"Doppler Token", "dp.st.test123abc", true},
		{"AWS Key", "AKIA1234567890ABCDEF", true},
		{"Password KV", "password=secret", true},
		{"Secret KV", "secret=my-secret", true},
		{"Token KV", "token=my-token", true},
		{"Key KV", "key=my-key", true},
		{"Normal String", "hello world", false},
		{"Short Base64", "SGVsbG8=", false},
		{"Random ID", "123-456-789", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, shouldRedact(tt.input))
		})
	}
}

func TestRedactingHandler_RedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := NewRedactingHandler(inner)
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

func TestRedactingHandler_PassesNonSecrets(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("test", "name", "John", "count", 42)

	output := buf.String()
	assert.Contains(t, output, "John")
	assert.NotContains(t, output, "[REDACTED]")
}

func TestRedactingHandler_Enabled(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	handler := NewRedactingHandler(inner)

	assert.False(t, handler.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, handler.Enabled(context.Background(), slog.LevelWarn))
}

func TestRedactingHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := NewRedactingHandler(inner)

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
	handler := NewRedactingHandler(inner)

	h2 := handler.WithGroup("mygroup")
	logger := slog.New(h2)

	logger.Info("test", "key", "sk-abc123def456ghi789jkl012mno")

	output := buf.String()
	assert.Contains(t, output, "mygroup.key=[REDACTED]")
	assert.NotContains(t, output, "sk-abc123def456ghi789jkl012mno")
}
