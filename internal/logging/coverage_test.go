package logging

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestRedactString_Coverage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Short", "123", "123"},
		{"NoMatch", "hello world", "hello world"},
		{"EqMatch", "password=secret", "password=[REDACTED]"},
		{"EqNoMatch", "other=val", "other=val"},
		{"SkMatch", "here is sk-12345678901234567890", "here is [REDACTED]"},
		{"SkNoMatch", "sk-123", "sk-123"},
		{"DpMatch", "prefix dp.st.123", "prefix [REDACTED]"},
		{"DpNoMatch", "dp.st.", "dp.st."},
		{"GhpMatch", "ghp_123456789012345678901234567890123456", "[REDACTED]"},
		{"GhpNoMatch", "ghp_123", "ghp_123"},
		{"AkiaMatch", "AKIA1234567890123456", "[REDACTED]"},
		{"AkiaNoMatch", "AKIA123", "AKIA123"},
		{"B64Match", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "[REDACTED]"},
		{"B64NoMatch", "short_b64", "short_b64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactString(tt.input))
		})
	}
}
