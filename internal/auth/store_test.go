package auth_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")

	s := auth.NewStoreWithPath(path)
	cred := &auth.Credential{
		Provider:  "doppler",
		Method:    "oauth",
		Token:     "dp.pt.test123",
		ExpiresAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		Metadata:  map[string]string{"email": "test@example.com"},
	}

	require.NoError(t, s.Save(cred))

	loaded, err := s.Load("doppler")
	require.NoError(t, err)
	assert.Equal(t, cred.Token, loaded.Token)
	assert.Equal(t, "test@example.com", loaded.Metadata["email"])
	assert.WithinDuration(t, cred.ExpiresAt, loaded.ExpiresAt, time.Second)
	assert.Equal(t, "doppler", loaded.Provider)
}

func TestStore_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode check is POSIX-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")

	s := auth.NewStoreWithPath(path)
	require.NoError(t, s.Save(&auth.Credential{Provider: "doppler", Token: "x"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestStore_LoadMissingReturnsErrNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")

	s := auth.NewStoreWithPath(path)
	_, err := s.Load("doppler")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)
}

func TestStore_MultipleProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	s := auth.NewStoreWithPath(path)

	require.NoError(t, s.Save(&auth.Credential{Provider: "aws", Method: "sso", Token: "aws-tok"}))
	require.NoError(t, s.Save(&auth.Credential{Provider: "doppler", Method: "oauth", Token: "dp-tok"}))

	aws, err := s.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "aws-tok", aws.Token)

	dp, err := s.Load("doppler")
	require.NoError(t, err)
	assert.Equal(t, "dp-tok", dp.Token)
}

func TestStore_Delete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	s := auth.NewStoreWithPath(path)

	require.NoError(t, s.Save(&auth.Credential{Provider: "doppler", Token: "x"}))
	require.NoError(t, s.Delete("doppler"))

	_, err := s.Load("doppler")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)
}

func TestStore_DeleteMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	s := auth.NewStoreWithPath(path)

	// Delete non-existing key should not error
	require.NoError(t, s.Delete("nonexistent"))
}

func TestStore_List(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	s := auth.NewStoreWithPath(path)

	require.NoError(t, s.Save(&auth.Credential{Provider: "aws", Token: "a"}))
	require.NoError(t, s.Save(&auth.Credential{Provider: "doppler", Token: "b"}))

	names, err := s.List()
	require.NoError(t, err)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "aws")
	assert.Contains(t, names, "doppler")
}

func TestStore_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	s := auth.NewStoreWithPath(path)

	require.NoError(t, s.Save(&auth.Credential{Provider: "aws", Token: "old"}))
	require.NoError(t, s.Save(&auth.Credential{Provider: "aws", Token: "new"}))

	cred, err := s.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "new", cred.Token)
}

func TestStore_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{not yaml"), 0o600))

	s := auth.NewStoreWithPath(path)
	_, err := s.Load("aws")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestCredential_IsExpired(t *testing.T) {
	t.Run("zero time = not expired", func(t *testing.T) {
		c := &auth.Credential{}
		assert.False(t, c.IsExpired())
	})

	t.Run("future = not expired", func(t *testing.T) {
		c := &auth.Credential{ExpiresAt: time.Now().Add(time.Hour)}
		assert.False(t, c.IsExpired())
	})

	t.Run("past = expired", func(t *testing.T) {
		c := &auth.Credential{ExpiresAt: time.Now().Add(-time.Hour)}
		assert.True(t, c.IsExpired())
	})
}
