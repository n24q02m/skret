package logging

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRedactingHandler(t *testing.T) {
	inner := slog.NewTextHandler(os.Stderr, nil)
	handler := NewRedactingHandler(inner)

	assert.NotNil(t, handler)
	assert.Equal(t, inner, handler.inner)
}

func TestIsSensitiveKey(t *testing.T) {
	assert.True(t, isSensitiveKey("password"))
	assert.True(t, isSensitiveKey("PASSWORD"))
	assert.True(t, isSensitiveKey("db_secret_key"))
	assert.True(t, isSensitiveKey("token"))
	assert.True(t, isSensitiveKey("api_key"))
	assert.False(t, isSensitiveKey("username"))
	assert.False(t, isSensitiveKey("id"))
}

func TestRedactString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Clean", "normal log message", "normal log message"},
		{"Short", "sk-1", "sk-1"}, // too short
		{"Password", "url?password=secret123&user=admin", "url?password=[REDACTED]&user=admin"},
		{"SK", "my key is sk-1234567890abcdefghij", "my key is [REDACTED]"},
		{"Doppler", "token dp.st.123456", "token [REDACTED]"},
		{"Github", "ghp_abcdefghijklmnopqrstuvwxyz1234567890", "[REDACTED]"},
		{"AWS", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"Base64", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[REDACTED].SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
        {"Base64Equal", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", "[REDACTED]"},
        {"Base64EqualEqual", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==", "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactString(tt.input))
		})
	}
}
