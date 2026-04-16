package provider_test

import (
	"context"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProvider struct{ name string }

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Capabilities() provider.Capabilities {
	return provider.Capabilities{}
}
func (m *mockProvider) Get(_ context.Context, _ string) (*provider.Secret, error) {
	return nil, nil
}
func (m *mockProvider) List(_ context.Context, _ string) ([]*provider.Secret, error) {
	return nil, nil
}
func (m *mockProvider) Set(_ context.Context, _, _ string, _ provider.SecretMeta) error {
	return nil
}
func (m *mockProvider) Delete(_ context.Context, _ string) error { return nil }
func (m *mockProvider) GetHistory(_ context.Context, _ string) ([]*provider.Secret, error) {
	return nil, nil
}
func (m *mockProvider) Rollback(_ context.Context, _ string, _ int64) error { return nil }
func (m *mockProvider) Close() error { return nil }

func TestRegistry_RegisterAndNew(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("mock", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "mock"}, nil
	})

	p, err := reg.New("mock", &config.ResolvedConfig{})
	require.NoError(t, err)
	assert.Equal(t, "mock", p.Name())
}

func TestRegistry_UnknownProvider(t *testing.T) {
	reg := provider.NewRegistry()
	_, err := reg.New("unknown", &config.ResolvedConfig{})
	assert.ErrorContains(t, err, "unknown")
}

func TestRegistry_ListProviders(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("aws", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "aws"}, nil
	})
	reg.Register("local", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "local"}, nil
	})

	names := reg.Providers()
	assert.Contains(t, names, "aws")
	assert.Contains(t, names, "local")
	assert.Len(t, names, 2)
}
