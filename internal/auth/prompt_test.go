package auth_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.OpenBrowser(context.Background(), tt.url)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.msg)
			}
		})
	}
}

func TestIsInteractiveStdin(t *testing.T) {
	t.Run("terminal", func(t *testing.T) {
		nullFile := "/dev/null"
		// SetGoos returns the cleanup function, which we call via defer.
		// We can't easily check the return value of SetGoos because it's a function.
		// But we know we are in a unix-like environment or windows.
		// For the purpose of the test, /dev/null should work on most CI environments (Linux/macOS).
		f, err := os.Open(nullFile)
		if err != nil {
			// Fallback for Windows if /dev/null fails
			f, err = os.Open("NUL")
		}
		require.NoError(t, err)
		defer f.Close()

		restore := auth.SetStdin(f)
		defer restore()

		assert.True(t, auth.IsInteractiveStdin())
	})

	t.Run("regular file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-stdin")
		require.NoError(t, err)
		defer os.Remove(f.Name())
		defer f.Close()

		restore := auth.SetStdin(f)
		defer restore()

		assert.False(t, auth.IsInteractiveStdin())
	})

	t.Run("pipe", func(t *testing.T) {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		defer r.Close()
		defer w.Close()

		restore := auth.SetStdin(r)
		defer restore()

		assert.False(t, auth.IsInteractiveStdin())
	})

	t.Run("error (closed file)", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-stdin-closed")
		require.NoError(t, err)
		os.Remove(f.Name())
		f.Close()

		restore := auth.SetStdin(f)
		defer restore()

		assert.False(t, auth.IsInteractiveStdin())
	})
}
