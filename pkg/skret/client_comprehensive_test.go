package skret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- New: error paths ---

func TestNew_NoConfig(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Options{WorkDir: dir})
	assert.Error(t, err)
	assert.Equal(t, ExitConfigError, ExitCode(err))
}

func TestNew_InvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`version: "invalid"`), 0o644))

	_, err := New(Options{WorkDir: dir})
	assert.Error(t, err)
	assert.Equal(t, ExitConfigError, ExitCode(err))
}

func TestNew_UnknownProvider(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: not-a-real-provider
    path: /foo
`), 0o644))

	_, err := New(Options{WorkDir: dir})
	assert.Error(t, err)
	assert.Equal(t, ExitConfigError, ExitCode(err))
}

// TestNew_LocalProviderMissingFileIsOK — quickstart flow creates config first,
// then `skret set` persists the secrets file. Missing file must not block.
func TestNew_LocalProviderMissingFileIsOK(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./nonexistent.yaml
`), 0o644))

	client, err := New(Options{WorkDir: dir})
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNew_DefaultWorkDir(t *testing.T) {
	// Test that New() without WorkDir uses os.Getwd()
	// This will likely fail to find a config file, which is fine
	_, err := New()
	// Just verify it doesn't panic and returns an appropriate error
	if err != nil {
		assert.Contains(t, err.Error(), "discover")
	}
}

func TestNew_LocalProviderSuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	secretsPath := filepath.Join(dir, "secrets.yaml")

	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: `+secretsPath+`
`), 0o644))
	require.NoError(t, os.WriteFile(secretsPath, []byte(`
version: "1"
secrets:
  DB_URL: "postgres://dev"
  API_KEY: "test-key"
`), 0o644))

	client, err := New(Options{WorkDir: dir})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()

	// Test Get
	s, err := client.Get(ctx, "DB_URL")
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev", s.Value)

	// Test List
	secrets, err := client.List(ctx)
	require.NoError(t, err)
	assert.Len(t, secrets, 2)

	// Test Set
	err = client.Set(ctx, "NEW_KEY", "new_val", provider.SecretMeta{})
	require.NoError(t, err)

	// Test Get after Set
	s, err = client.Get(ctx, "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, "new_val", s.Value)

	// Test Delete
	err = client.Delete(ctx, "NEW_KEY")
	require.NoError(t, err)

	// Test Get after Delete
	_, err = client.Get(ctx, "NEW_KEY")
	assert.Error(t, err)
	assert.Equal(t, ExitNotFoundError, ExitCode(err))

	// Test GetHistory (not supported by local)
	_, err = client.GetHistory(ctx, "DB_URL")
	assert.Error(t, err)
	assert.Equal(t, ExitProviderError, ExitCode(err))

	// Test Rollback (not supported by local)
	err = client.Rollback(ctx, "DB_URL", 1)
	assert.Error(t, err)
	assert.Equal(t, ExitProviderError, ExitCode(err))
}

// --- Client method error paths ---

func TestClientMethods_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{name: "mock"}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	t.Run("List error", func(t *testing.T) {
		mock.listFunc = func(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
			return nil, errors.New("list failed")
		}
		_, err := client.List(ctx)
		assert.Error(t, err)
		assert.Equal(t, ExitProviderError, ExitCode(err))
	})

	t.Run("Set error", func(t *testing.T) {
		mock.setFunc = func(ctx context.Context, key, value string, meta provider.SecretMeta) error {
			return errors.New("set failed")
		}
		err := client.Set(ctx, "k1", "v1", provider.SecretMeta{})
		assert.Error(t, err)
		assert.Equal(t, ExitProviderError, ExitCode(err))
	})

	t.Run("Delete error", func(t *testing.T) {
		mock.deleteFunc = func(ctx context.Context, key string) error {
			return errors.New("delete failed")
		}
		err := client.Delete(ctx, "k1")
		assert.Error(t, err)
		assert.Equal(t, ExitProviderError, ExitCode(err))
	})

	t.Run("GetHistory error", func(t *testing.T) {
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return nil, errors.New("history failed")
		}
		_, err := client.GetHistory(ctx, "k1")
		assert.Error(t, err)
		assert.Equal(t, ExitProviderError, ExitCode(err))
	})

	t.Run("Rollback error", func(t *testing.T) {
		mock.rollbackFunc = func(ctx context.Context, key string, version int64) error {
			return errors.New("rollback failed")
		}
		err := client.Rollback(ctx, "k1", 1)
		assert.Error(t, err)
		assert.Equal(t, ExitProviderError, ExitCode(err))
	})
}

// --- New with options override ---

func TestNew_WithEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	secretsPath := filepath.Join(dir, "staging.yaml")

	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: `+filepath.Join(dir, "dev.yaml")+`
  staging:
    provider: local
    file: `+secretsPath+`
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte(`
version: "1"
secrets:
  ENV: dev
`), 0o644))
	require.NoError(t, os.WriteFile(secretsPath, []byte(`
version: "1"
secrets:
  ENV: staging
`), 0o644))

	client, err := New(Options{WorkDir: dir, Env: "staging"})
	require.NoError(t, err)
	defer client.Close()

	s, err := client.Get(context.Background(), "ENV")
	require.NoError(t, err)
	assert.Equal(t, "staging", s.Value)
}

// --- Context cancellation ---

func TestClient_ContextCancellation(t *testing.T) {
	mock := &mockProvider{name: "mock"}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock.getFunc = func(ctx context.Context, key string) (*provider.Secret, error) {
		return nil, ctx.Err()
	}

	_, err := client.Get(ctx, "key")
	assert.Error(t, err)
}

// --- ErrNotFound propagation ---

func TestClient_ErrNotFound_Propagation(t *testing.T) {
	mock := &mockProvider{name: "mock"}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	mock.getFunc = func(ctx context.Context, key string) (*provider.Secret, error) {
		return nil, provider.ErrNotFound
	}

	_, err := client.Get(context.Background(), "missing")
	assert.Error(t, err)
	assert.Equal(t, ExitNotFoundError, ExitCode(err))
	// The inner error should be ErrNotFound
	var skretErr *Error
	require.True(t, errors.As(err, &skretErr))
	assert.ErrorIs(t, skretErr.Err, provider.ErrNotFound)
}

// --- New with resolve error ---

func TestNew_ResolveError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	// Config where resolve will fail: single env but asking for different env
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
environments:
  dev:
    provider: local
    file: ./secrets.yaml
`), 0o644))

	_, err := New(Options{WorkDir: dir, Env: "nonexistent"})
	assert.Error(t, err)
	assert.Equal(t, ExitConfigError, ExitCode(err))
	assert.Contains(t, err.Error(), "resolve")
}
