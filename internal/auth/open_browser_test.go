package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenBrowser_InsecureSchemes(t *testing.T) {
	// Unset the skip variable for this test
	t.Setenv("SKRET_NO_BROWSER", "")

	tests := []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,<html><body>hacked</body></html>"},
		{"flag injection", "--version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := OpenBrowser(context.Background(), tt.url)
			assert.Error(t, err, "expected error for insecure URL: %s", tt.url)
		})
	}
}

func TestOpenBrowser_ValidSchemes(t *testing.T) {
	// Keep the skip variable set for this test to avoid real browser launch
	t.Setenv("SKRET_NO_BROWSER", "1")

	tests := []struct {
		name string
		url  string
	}{
		{"http scheme", "http://example.com"},
		{"https scheme", "https://example.com/path?query=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := OpenBrowser(context.Background(), tt.url)
			assert.NoError(t, err)
		})
	}
}
