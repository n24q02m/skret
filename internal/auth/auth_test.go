package auth_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_NotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	_, err := auth.Resolve(context.Background(), "doppler")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)
}

func TestResolve_Expired(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	// Pre-populate store with expired credential
	s := auth.NewStoreWithPath(filepath.Join(dir, ".skret", "credentials.yaml"))
	require.NoError(t, s.Save(&auth.Credential{
		Provider:  "doppler",
		Token:     "expired-tok",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	// Resolve should fail
	_, err := auth.Resolve(context.Background(), "doppler")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential expired")
}

func TestLogin_UnknownProvider(t *testing.T) {
	err := auth.Login(context.Background(), "unknown-provider", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}
