package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".secrets.dev.yaml")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}

func newProvider(t *testing.T, filePath string) provider.SecretProvider {
	t.Helper()
	p, err := local.New(&config.ResolvedConfig{File: filePath})
	require.NoError(t, err)
	return p
}

func TestLocal_Name(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer p.Close()
	assert.Equal(t, "local", p.Name())
}

func TestLocal_Capabilities(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer p.Close()
	caps := p.Capabilities()
	assert.True(t, caps.Write)
	assert.False(t, caps.Versioning)
}

func TestLocal_Get(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  DATABASE_URL: \"postgres://dev:dev@localhost/db\"\n  API_KEY: secret123")
	p := newProvider(t, path)
	defer p.Close()

	ctx := context.Background()
	s, err := p.Get(ctx, "DATABASE_URL")
	require.NoError(t, err)
	assert.Equal(t, "DATABASE_URL", s.Key)
	assert.Equal(t, "postgres://dev:dev@localhost/db", s.Value)
}

func TestLocal_GetNotFound(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer p.Close()

	_, err := p.Get(context.Background(), "NONEXISTENT")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestLocal_List(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  DB_URL: db\n  API_KEY: key\n  REDIS_URL: redis")
	p := newProvider(t, path)
	defer p.Close()

	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, secrets, 3)
}

func TestLocal_List_Sorted(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  Z_KEY: z\n  A_KEY: a\n  M_KEY: m")
	p := newProvider(t, path)
	defer p.Close()

	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, secrets, 3)
	assert.Equal(t, "A_KEY", secrets[0].Key)
	assert.Equal(t, "M_KEY", secrets[1].Key)
	assert.Equal(t, "Z_KEY", secrets[2].Key)
}

func TestLocal_Set(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer p.Close()

	ctx := context.Background()
	err := p.Set(ctx, "NEW_KEY", "new_val", provider.SecretMeta{})
	require.NoError(t, err)

	s, err := p.Get(ctx, "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, "new_val", s.Value)

	// Verify persisted to file
	p2 := newProvider(t, path)
	defer p2.Close()
	s2, err := p2.Get(ctx, "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, "new_val", s2.Value)
}

func TestLocal_Set_InitializesMap(t *testing.T) {
	// File with no secrets map to exercise the nil map path
	path := setupFile(t, "version: \"1\"\n")
	p := newProvider(t, path)
	defer p.Close()

	err := p.Set(context.Background(), "KEY", "val", provider.SecretMeta{})
	require.NoError(t, err)

	s, err := p.Get(context.Background(), "KEY")
	require.NoError(t, err)
	assert.Equal(t, "val", s.Value)
}

func TestLocal_Delete(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1\n  KEY2: val2")
	p := newProvider(t, path)
	defer p.Close()

	ctx := context.Background()
	err := p.Delete(ctx, "KEY1")
	require.NoError(t, err)

	_, err = p.Get(ctx, "KEY1")
	assert.ErrorIs(t, err, provider.ErrNotFound)

	s, err := p.Get(ctx, "KEY2")
	require.NoError(t, err)
	assert.Equal(t, "val2", s.Value)
}

func TestLocal_DeleteNotFound(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY1: val1")
	p := newProvider(t, path)
	defer p.Close()

	err := p.Delete(context.Background(), "NONEXISTENT")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestLocal_NewFileMissing(t *testing.T) {
	_, err := local.New(&config.ResolvedConfig{File: filepath.Join(t.TempDir(), "nonexistent.yaml")})
	assert.Error(t, err)
}

func TestLocal_Set_CreateTempError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}"), 0o600))
	p := newProvider(t, path)
	defer p.Close()

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.RemoveAll(dir))

	err := p.Set(context.Background(), "K", "V", provider.SecretMeta{})
	assert.Error(t, err)
}

func TestLocal_Set_RenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir")
	require.NoError(t, os.MkdirAll(path, 0o700))
	seed := filepath.Join(path, ".secrets.yaml")
	require.NoError(t, os.WriteFile(seed, []byte("version: \"1\"\nsecrets: {}"), 0o600))

	p, err := local.New(&config.ResolvedConfig{File: seed})
	require.NoError(t, err)
	defer p.Close()

	require.NoError(t, os.Remove(seed))
	require.NoError(t, os.Mkdir(seed, 0o700))

	err = p.Set(context.Background(), "K", "V", provider.SecretMeta{})
	assert.Error(t, err)
}

func TestLocal_Concurrent(t *testing.T) {
	path := setupFile(t, "version: \"1\"\nsecrets:\n  KEY: initial")
	p := newProvider(t, path)
	defer p.Close()

	ctx := context.Background()
	done := make(chan struct{})
	errs := make(chan error, 10)

	for i := 0; i < 5; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			key := "KEY"
			if err := p.Set(ctx, key, "value", provider.SecretMeta{}); err != nil {
				errs <- err
			}
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}
