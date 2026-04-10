package skret

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProvider struct {
	name           string
	capabilities   provider.Capabilities
	getFunc        func(ctx context.Context, key string) (*provider.Secret, error)
	listFunc       func(ctx context.Context, pathPrefix string) ([]*provider.Secret, error)
	setFunc        func(ctx context.Context, key string, value string, meta provider.SecretMeta) error
	deleteFunc     func(ctx context.Context, key string) error
	getHistoryFunc func(ctx context.Context, key string) ([]*provider.Secret, error)
	rollbackFunc   func(ctx context.Context, key string, version int64) error
	closeFunc      func() error
}

func (m *mockProvider) Name() string                        { return m.name }
func (m *mockProvider) Capabilities() provider.Capabilities { return m.capabilities }
func (m *mockProvider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	return m.getFunc(ctx, key)
}
func (m *mockProvider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	return m.listFunc(ctx, pathPrefix)
}
func (m *mockProvider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	return m.setFunc(ctx, key, value, meta)
}
func (m *mockProvider) Delete(ctx context.Context, key string) error {
	return m.deleteFunc(ctx, key)
}
func (m *mockProvider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	return m.getHistoryFunc(ctx, key)
}
func (m *mockProvider) Rollback(ctx context.Context, key string, version int64) error {
	return m.rollbackFunc(ctx, key, version)
}
func (m *mockProvider) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestNew(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	secretsPath := filepath.Join(dir, "secrets.yaml")

	err := os.WriteFile(cfgPath, []byte(`
version: "1"
environments:
  dev:
    provider: local
    file: `+secretsPath+`
`), 0o644)
	require.NoError(t, err)

	// Create dummy secrets file for local provider
	err = os.WriteFile(secretsPath, []byte(`
version: "1"
secrets:
  test: value
`), 0o644)
	require.NoError(t, err)

	t.Run("Default", func(t *testing.T) {
		client, err := New(Options{WorkDir: dir})
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "local", client.Provider().Name())
	})

	t.Run("InvalidWorkDir", func(t *testing.T) {
		_, err := New(Options{WorkDir: "/nonexistent"})
		assert.Error(t, err)
	})
}

func TestClientMethods(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{
		name: "mock",
	}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	t.Run("Get", func(t *testing.T) {
		mock.getFunc = func(ctx context.Context, key string) (*provider.Secret, error) {
			assert.Equal(t, "foo", key)
			return &provider.Secret{Key: "foo", Value: "bar"}, nil
		}
		s, err := client.Get(ctx, "foo")
		require.NoError(t, err)
		assert.Equal(t, "bar", s.Value)

		mock.getFunc = func(ctx context.Context, key string) (*provider.Secret, error) {
			return nil, provider.ErrNotFound
		}
		_, err = client.Get(ctx, "missing")
		assert.Error(t, err)
		assert.Equal(t, ExitNotFoundError, ExitCode(err))
	})

	t.Run("List", func(t *testing.T) {
		mock.listFunc = func(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
			assert.Equal(t, "/test/", pathPrefix)
			return []*provider.Secret{{Key: "k1", Value: "v1"}}, nil
		}
		secrets, err := client.List(ctx)
		require.NoError(t, err)
		assert.Len(t, secrets, 1)
	})

	t.Run("Set", func(t *testing.T) {
		mock.setFunc = func(ctx context.Context, key, value string, meta provider.SecretMeta) error {
			assert.Equal(t, "k1", key)
			assert.Equal(t, "v1", value)
			return nil
		}
		err := client.Set(ctx, "k1", "v1", provider.SecretMeta{})
		assert.NoError(t, err)
	})

	t.Run("Delete", func(t *testing.T) {
		mock.deleteFunc = func(ctx context.Context, key string) error {
			assert.Equal(t, "k1", key)
			return nil
		}
		err := client.Delete(ctx, "k1")
		assert.NoError(t, err)
	})

	t.Run("GetHistory", func(t *testing.T) {
		mock.getHistoryFunc = func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return []*provider.Secret{{Key: "k1", Version: 1}}, nil
		}
		h, err := client.GetHistory(ctx, "k1")
		require.NoError(t, err)
		assert.Len(t, h, 1)
	})

	t.Run("Rollback", func(t *testing.T) {
		mock.rollbackFunc = func(ctx context.Context, key string, version int64) error {
			assert.Equal(t, int64(1), version)
			return nil
		}
		err := client.Rollback(ctx, "k1", 1)
		assert.NoError(t, err)
	})

	t.Run("Close", func(t *testing.T) {
		called := false
		mock.closeFunc = func() error {
			called = true
			return nil
		}
		err := client.Close()
		assert.NoError(t, err)
		assert.True(t, called)
	})
}

func TestConfigAndProvider(t *testing.T) {
	mock := &mockProvider{name: "mock"}
	cfg := &config.ResolvedConfig{EnvName: "dev"}
	client := &Client{
		provider: mock,
		config:   cfg,
	}

	assert.Equal(t, cfg, client.Config())
	assert.Equal(t, mock, client.Provider())
}
