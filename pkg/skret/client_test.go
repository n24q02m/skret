package skret

import (
	"context"
	"fmt"
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
	getBatchFunc   func(ctx context.Context, keys []string) ([]*provider.Secret, error)
	listFunc       func(ctx context.Context, pathPrefix string) ([]*provider.Secret, error)
	setFunc        func(ctx context.Context, key string, value string, meta provider.SecretMeta) error
	setBatchFunc   func(ctx context.Context, secrets []*provider.Secret) error
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

func (m *mockProvider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if m.getBatchFunc != nil {
		return m.getBatchFunc(ctx, keys)
	}
	return nil, nil
}

func (m *mockProvider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	return m.listFunc(ctx, pathPrefix)
}

func (m *mockProvider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	return m.setFunc(ctx, key, value, meta)
}

func (m *mockProvider) SetBatch(ctx context.Context, secrets []*provider.Secret) error {
	if m.setBatchFunc != nil {
		return m.setBatchFunc(ctx, secrets)
	}
	return nil
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

func TestNew_Success(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    path: ""
    file: .secrets.dev.yaml
providers:
  local:
    file: .secrets.dev.yaml
`), 0o644))

	client, err := New(Options{WorkDir: dir})
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "local", client.Config().Provider)
	assert.NotNil(t, client.Provider())
}

func TestClient_Get(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{
		getFunc: func(ctx context.Context, key string) (*provider.Secret, error) {
			assert.Equal(t, "API_KEY", key)
			return &provider.Secret{Key: "API_KEY", Value: "topsecret"}, nil
		},
	}
	client := &Client{provider: mock}

	s, err := client.Get(ctx, "API_KEY")
	require.NoError(t, err)
	assert.Equal(t, "topsecret", s.Value)
}

func TestClient_List(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{
		listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
			return []*provider.Secret{{Key: "K1", Value: "V1"}}, nil
		},
	}
	client := &Client{
		provider: mock,
		config:   &config.ResolvedConfig{Path: "/test/"},
	}

	secrets, err := client.List(ctx)
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
}

func TestClient_Set(t *testing.T) {
	ctx := context.Background()
	called := false
	mock := &mockProvider{
		setFunc: func(ctx context.Context, key, val string, meta provider.SecretMeta) error {
			called = true
			assert.Equal(t, "K", key)
			assert.Equal(t, "V", val)
			return nil
		},
	}
	client := &Client{provider: mock}

	err := client.Set(ctx, "K", "V", provider.SecretMeta{})
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestClient_Delete(t *testing.T) {
	ctx := context.Background()
	called := false
	mock := &mockProvider{
		deleteFunc: func(ctx context.Context, key string) error {
			called = true
			assert.Equal(t, "K", key)
			return nil
		},
	}
	client := &Client{provider: mock}

	err := client.Delete(ctx, "K")
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestClient_GetHistory(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{
		getHistoryFunc: func(ctx context.Context, key string) ([]*provider.Secret, error) {
			return []*provider.Secret{{Key: "K", Version: 1}}, nil
		},
	}
	client := &Client{provider: mock}

	history, err := client.GetHistory(ctx, "K")
	require.NoError(t, err)
	assert.Len(t, history, 1)
}

func TestClient_Rollback(t *testing.T) {
	ctx := context.Background()
	called := false
	mock := &mockProvider{
		rollbackFunc: func(ctx context.Context, key string, version int64) error {
			called = true
			assert.Equal(t, "K", key)
			assert.Equal(t, int64(1), version)
			return nil
		},
	}
	client := &Client{provider: mock}

	err := client.Rollback(ctx, "K", 1)
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestClient_Close(t *testing.T) {
	t.Run("nil provider", func(t *testing.T) {
		client := &Client{}
		assert.NoError(t, client.Close())
	})

	t.Run("success", func(t *testing.T) {
		called := false
		mock := &mockProvider{
			closeFunc: func() error {
				called = true
				return nil
			},
		}
		client := &Client{provider: mock}
		err := client.Close()
		assert.NoError(t, err)
		assert.True(t, called)
	})
}

func TestClient_SetBatch(t *testing.T) {
	ctx := context.Background()
	called := false
	mock := &mockProvider{
		setBatchFunc: func(ctx context.Context, secrets []*provider.Secret) error {
			called = true
			assert.Len(t, secrets, 1)
			return nil
		},
	}
	client := &Client{provider: mock}
	err := client.SetBatch(ctx, []*provider.Secret{{Key: "K", Value: "V"}})
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestClient_SetBatch_Error(t *testing.T) {
	ctx := context.Background()
	mock := &mockProvider{
		setBatchFunc: func(ctx context.Context, secrets []*provider.Secret) error {
			return fmt.Errorf("fail")
		},
	}
	client := &Client{provider: mock}
	err := client.SetBatch(ctx, []*provider.Secret{{Key: "K", Value: "V"}})
	assert.Error(t, err)
	assert.Equal(t, ExitProviderError, ExitCode(err))
}
