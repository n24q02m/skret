package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/logging"
	"github.com/stretchr/testify/assert"
)

func TestRedactingHandler_RedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	// #nosec G101
	token := "sk-" + strings.Repeat("0", 20)
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

	// #nosec G101
	token := "ghp_" + strings.Repeat("A", 36)
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

func TestRedactingHandler_Enabled_Delegation(t *testing.T) {
	type ctxKey string
	key := ctxKey("test")
	ctx := context.WithValue(context.Background(), key, "value")
	level := slog.LevelError

	called := false
	mock := &mockHandler{
		enabledFunc: func(c context.Context, l slog.Level) bool {
			called = true
			assert.Equal(t, ctx, c)
			assert.Equal(t, level, l)
			return true
		},
	}

	handler := logging.NewRedactingHandler(mock)
	assert.True(t, handler.Enabled(ctx, level))
	assert.True(t, called)
}

func TestRedactingHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)

	// #nosec G101
	token := "sk-" + strings.Repeat("0", 20)
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

	// #nosec G101
	token := "sk-" + strings.Repeat("0", 20)
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
		{"password", "my-test-val"},
		{"user_token", "test-token-val"},
		{"API_KEY", "test-api-val"},
		{"db_secret", "test-secret-val"},
		{"access_token", "test-access-val"},
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

	// #nosec G101
	ghpToken := "ghp_" + strings.Repeat("A", 36)
	// #nosec G101
	skToken := "sk-" + strings.Repeat("0", 20)
	tests := []struct {
		msg      string
		expected string
	}{
		{"failed to auth with password=my-secret-val", "failed to auth with password=[REDACTED]"},
		{"token is " + ghpToken, "token is [REDACTED]"},
		{"key=valA&secret=valB&other=valC", "key=[REDACTED]&secret=[REDACTED]&other=valC"},
		{"OpenAI key " + skToken, "OpenAI key [REDACTED]"},
	}

	for _, tt := range tests {
		buf.Reset()
		logger.Info(tt.msg)
		output := buf.String()
		assert.Contains(t, output, "msg=\""+tt.expected+"\"")
	}
}

func TestRedactingHandler_RedactsNestedGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	// #nosec G101
	token := "ghp_" + strings.Repeat("A", 36)
	logger.Info(
		"test",
		slog.Group("user",
			slog.String("token", token),
			slog.String("name", "alice"),
		),
	)

	output := buf.String()
	assert.Contains(t, output, "user.token=[REDACTED]")
	assert.Contains(t, output, "user.name=alice")
	assert.NotContains(t, output, token)
}

func TestSetup(t *testing.T) {
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)

	tests := []struct {
		name          string
		level         string
		format        string
		expectedLevel slog.Level
	}{
		{"Debug Text", "debug", "text", slog.LevelDebug},
		{"Info JSON", "info", "json", slog.LevelInfo},
		{"Warn Text", "warn", "text", slog.LevelWarn},
		{"Warning Text", "warning", "text", slog.LevelWarn},
		{"Error JSON", "error", "json", slog.LevelError},
		{"Default Level and Format", "", "", slog.LevelInfo},
		{"Case Insensitive Level", "DEBUG", "TEXT", slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logging.Setup(tt.level, tt.format)
			handler := slog.Default().Handler()

			// Check if the expected level is enabled
			assert.True(t, handler.Enabled(context.Background(), tt.expectedLevel))
			// Check if a lower level is disabled (if not debug)
			if tt.expectedLevel > slog.LevelDebug {
				assert.False(t, handler.Enabled(context.Background(), tt.expectedLevel-1))
			}
		})
	}
}

// TestRedactingHandler_ManyAttrs_PreservesOrder exercises the optimized
// Handle path (NumAttrs-preallocated slice + variadic AddAttrs) with many
// attributes to ensure ordering and redaction remain correct.
func TestRedactingHandler_ManyAttrs_PreservesOrder(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	// #nosec G101
	token := "ghp_" + strings.Repeat("A", 36)
	logger.Info("multi",
		"a", "alpha",
		"b", "beta",
		"token", token,
		"c", "gamma",
		"d", "delta",
		"e", "epsilon",
	)

	out := buf.String()
	assert.Contains(t, out, "a=alpha")
	assert.Contains(t, out, "b=beta")
	assert.Contains(t, out, "c=gamma")
	assert.Contains(t, out, "d=delta")
	assert.Contains(t, out, "e=epsilon")
	assert.Contains(t, out, "token=[REDACTED]")
	assert.NotContains(t, out, token)
}

// TestRedactingHandler_NoAttrs ensures the preallocated zero-cap branch is
// exercised and still emits the message body.
func TestRedactingHandler_NoAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("no-attrs-here")
	assert.Contains(t, buf.String(), "no-attrs-here")
}

func TestRedactingHandler_WithGroup_Type(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, nil)
	handler := logging.NewRedactingHandler(inner)

	h2 := handler.WithGroup("test")
	_, ok := h2.(*logging.RedactingHandler)
	assert.True(t, ok, "WithGroup should return a *RedactingHandler")
}

func TestRedactingHandler_WithGroup_RedactsSensitiveName(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	handler := logging.NewRedactingHandler(inner)

	// Test pattern matching in group name
	// #nosec G101
	secret := "sk-" + strings.Repeat("0", 20)
	h2 := handler.WithGroup(secret)
	logger := slog.New(h2)
	logger.Info("msg", "foo", "bar")

	output := buf.String()
	assert.NotContains(t, output, secret)
	assert.Contains(t, output, "[REDACTED].foo=bar")

	// Test sensitive key matching in group name
	buf.Reset()
	h3 := handler.WithGroup("password")
	logger3 := slog.New(h3)
	logger3.Info("msg", "foo", "bar")

	output3 := buf.String()
	assert.Contains(t, output3, "[REDACTED].foo=bar")
}
