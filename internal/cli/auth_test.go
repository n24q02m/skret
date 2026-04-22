package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCmd_SubcommandExists(t *testing.T) {
	root := NewRootCmd()
	// Verify auth command is registered
	found := false
	for _, cmd := range root.Commands() {
		if cmd.Use == "auth" {
			found = true
			break
		}
	}
	assert.True(t, found, "auth subcommand should be registered")
}

func TestAuthLoginCmd_UnknownProvider(t *testing.T) {
	cmd := newAuthLoginCmd()
	cmd.SetArgs([]string{"unknown-provider"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth login")
}

func TestAuthStatusCmd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	cmd := newAuthStatusCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "aws")
	assert.Contains(t, out, "doppler")
	assert.Contains(t, out, "infisical")
	assert.Contains(t, out, "not configured")
}

func TestAuthStatusCmd_WithCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	s := auth.NewStoreWithPath(filepath.Join(dir, ".skret", "credentials.yaml"))
	require.NoError(t, s.Save(&auth.Credential{
		Provider: "doppler",
		Method:   "oauth",
		Token:    "dp.test",
	}))

	cmd := newAuthStatusCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "doppler")
	assert.Contains(t, out, "oauth")
}

func TestAuthLogoutCmd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	s := auth.NewStoreWithPath(filepath.Join(dir, ".skret", "credentials.yaml"))
	require.NoError(t, s.Save(&auth.Credential{Provider: "doppler", Token: "x"}))

	cmd := newAuthLogoutCmd()
	cmd.SetArgs([]string{"doppler"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Logged out")

	// Verify credential is gone
	_, err = s.Load("doppler")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)
}

func TestAuthLogoutCmd_NonExisting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	cmd := newAuthLogoutCmd()
	cmd.SetArgs([]string{"nonexistent"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := cmd.Execute()
	require.NoError(t, err) // Delete missing is not an error
}

func TestAuthCmd_Help(t *testing.T) {
	cmd := newAuthCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "auth")
}

func TestNewStore_Default(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	s := auth.NewStore()
	require.NoError(t, s.Save(&auth.Credential{Provider: "test", Token: "t"}))

	// Verify file created
	info, err := os.Stat(filepath.Join(dir, ".skret", "credentials.yaml"))
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}
