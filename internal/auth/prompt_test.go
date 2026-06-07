package auth_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirm_YesDefault(t *testing.T) {
	for _, in := range []string{"y\n", "Y\n", "yes\n", "\n"} {
		var out bytes.Buffer
		ok := auth.Confirm(strings.NewReader(in), &out, "proceed?")
		assert.True(t, ok, "input %q should confirm", in)
	}
}

func TestConfirm_No(t *testing.T) {
	var out bytes.Buffer
	ok := auth.Confirm(strings.NewReader("n\n"), &out, "proceed?")
	assert.False(t, ok)
}

func TestConfirm_NoResponse(t *testing.T) {
	var out bytes.Buffer
	ok := auth.Confirm(strings.NewReader("no\n"), &out, "proceed?")
	assert.False(t, ok)
}

func TestSelectMethod_PicksIndex(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{
		{Name: "sso", Description: "AWS SSO device flow"},
		{Name: "access-key", Description: "Access key + secret key"},
		{Name: "assume-role", Description: "Assume IAM role"},
	}
	m, err := auth.SelectMethod(strings.NewReader("2\n"), &out, methods)
	require.NoError(t, err)
	assert.Equal(t, "access-key", m.Name)
}

func TestSelectMethod_InvalidIndex(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	_, err := auth.SelectMethod(strings.NewReader("5\n"), &out, methods)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid choice")
}

func TestSelectMethod_NotANumber(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	_, err := auth.SelectMethod(strings.NewReader("abc\n"), &out, methods)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid choice")
}

func TestSelectMethod_EmptyDescription(t *testing.T) {
	var out bytes.Buffer
	methods := []auth.Method{{Name: "sso"}}
	m, err := auth.SelectMethod(strings.NewReader("1\n"), &out, methods)
	require.NoError(t, err)
	assert.Equal(t, "sso", m.Name)
	// When description is empty, should use name as fallback
	assert.Contains(t, out.String(), "sso")
}

func TestSelectMethod_ReadError(t *testing.T) {
	methods := []auth.Method{{Name: "test"}}
	_, err := auth.SelectMethod(iotest.ErrReader(errors.New("read failure")), io.Discard, methods)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read failure")
}

func TestSelectMethod_EOF(t *testing.T) {
	methods := []auth.Method{{Name: "test"}}
	// ReadString('\n') on "1" will return "1" and io.EOF
	_, err := auth.SelectMethod(strings.NewReader("1"), io.Discard, methods)
	assert.Error(t, err)
	assert.Equal(t, io.EOF, errors.Unwrap(err))
}

func TestOpenBrowser_InvalidScheme(t *testing.T) {
	t.Setenv("SKRET_NO_BROWSER", "")
	err := auth.OpenBrowser(context.Background(), "file:///etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid url scheme")
}

func TestOpenBrowser_InvalidURL(t *testing.T) {
	t.Setenv("SKRET_NO_BROWSER", "")
	err := auth.OpenBrowser(context.Background(), "http://%42:8080/")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid url")
}

func TestOpenBrowser_ValidScheme(t *testing.T) {
	t.Setenv("SKRET_NO_BROWSER", "")

	tests := []struct {
		name string
		goos string
	}{
		{"darwin", "darwin"},
		{"windows", "windows"},
		{"linux", "linux"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := auth.SetGoos(func() string { return tt.goos })
			defer restore()

			err := auth.OpenBrowser(context.Background(), "https://example.com")
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid url")
			}
		})
	}
}

func TestOpenBrowser_Injection(t *testing.T) {
	t.Setenv("SKRET_NO_BROWSER", "")

	tests := []struct {
		name string
		url  string
		msg  string
	}{
		{"leading dash", "https://-V/foo", "invalid url host"},
		{"shell metacharacter $", "https://example.com/$PATH", "dangerous characters"},
		{"shell metacharacter ;", "https://example.com/;id", "dangerous characters"},
		{"shell metacharacter `", "https://example.com/?`id`", "dangerous characters"},
		{"shell metacharacter |", "https://example.com/?|id", "dangerous characters"},
		{"valid query params", "https://example.com/?foo=bar&baz=qux", ""},
		{"valid query with quotes", "https://example.com/?q='value'", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.OpenBrowser(context.Background(), tt.url)
			if tt.msg == "" {
				assert.NoError(t, err)
			} else if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.msg)
			}
		})
	}
}
