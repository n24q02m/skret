package cli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrowseCmd_NonTTY_Errors(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"browse"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitValidationError, se.Code)
}

func TestBrowseCmd_Registered(t *testing.T) {
	cmd := NewRootCmd()
	found, _, err := cmd.Find([]string{"browse"})
	require.NoError(t, err)
	assert.Equal(t, "browse", found.Name())
}

// TestBrowseReveal covers the provider-backed reveal closure: it returns the
// decrypted value for an existing key and an error (no value) for a missing one.
func TestBrowseReveal(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	_, p, err := loadProvider(&GlobalOpts{})
	require.NoError(t, err)
	defer p.Close()

	reveal := browseReveal(p)

	val, err := reveal(context.Background(), "TOKEN")
	require.NoError(t, err)
	assert.Equal(t, "tok123", val)

	_, err = reveal(context.Background(), "NOPE")
	require.Error(t, err)
}

func TestBrowseCmd_EmptyState(t *testing.T) {
	dir := writeEmptyLocalConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	// Mock the TTY check so it doesn't fail early.
	origIsTerminal := isTerminal
	isTerminal = func() bool { return true }
	defer func() { isTerminal = origIsTerminal }()

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"browse"})

	// Capture stderr
	var out string
	oldStderr := cmd.ErrOrStderr()
	defer cmd.SetErr(oldStderr)

	var buf []byte
	writer := &mockWriter{buf: &buf}
	cmd.SetErr(writer)

	err := cmd.Execute()
	require.NoError(t, err)

	out = string(buf)
	assert.Contains(t, out, "No secrets found to browse. Use 'skret set' to add a secret.")
}

type mockWriter struct {
	buf *[]byte
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	*m.buf = append(*m.buf, p...)
	return len(p), nil
}
