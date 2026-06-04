package provider_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProvider struct{ name string }

func (m *mockProvider) Name() string                        { return m.name }
func (m *mockProvider) Capabilities() provider.Capabilities { return provider.Capabilities{} }
func (m *mockProvider) Get(_ context.Context, _ string) (*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) GetBatch(_ context.Context, _ []string) ([]*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) List(_ context.Context, _ string) ([]*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) Set(_ context.Context, _ string, _ string, _ provider.SecretMeta) error {
	return nil
}

func (m *mockProvider) SetBatch(_ context.Context, _ []*provider.Secret) error {
	return nil
}
func (m *mockProvider) Delete(_ context.Context, _ string) error { return nil }
func (m *mockProvider) GetHistory(_ context.Context, _ string) ([]*provider.Secret, error) {
	return nil, nil
}
func (m *mockProvider) Rollback(_ context.Context, _ string, _ int64) error { return nil }
func (m *mockProvider) Close() error                                        { return nil }

func TestRegistry_RegisterAndNew(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("mock", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "mock"}, nil
	})

	p, err := reg.New("mock", &config.ResolvedConfig{})
	require.NoError(t, err)
	assert.Equal(t, "mock", p.Name())
}

func TestRegistry_Overwrite(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("mock", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "v1"}, nil
	})
	reg.Register("mock", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "v2"}, nil
	})

	p, err := reg.New("mock", &config.ResolvedConfig{})
	require.NoError(t, err)
	assert.Equal(t, "v2", p.Name())
}

func TestRegistry_FactoryError(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("fail", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return nil, errors.New("factory failed")
	})

	_, err := reg.New("fail", &config.ResolvedConfig{})
	assert.ErrorContains(t, err, "factory failed")
}

func TestRegistry_UnknownProvider(t *testing.T) {
	reg := provider.NewRegistry()
	_, err := reg.New("unknown", &config.ResolvedConfig{})
	assert.ErrorContains(t, err, "unknown")
	assert.ErrorContains(t, err, "available: []")
}

func TestRegistry_ListProviders(t *testing.T) {
	reg := provider.NewRegistry()
	assert.Empty(t, reg.Providers())

	reg.Register("local", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "local"}, nil
	})
	reg.Register("aws", func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
		return &mockProvider{name: "aws"}, nil
	})

	names := reg.Providers()
	assert.Equal(t, []string{"aws", "local"}, names)
}

func TestRegistry_Concurrent(t *testing.T) {
	reg := provider.NewRegistry()
	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				name := fmt.Sprintf("p-%d-%d", workerID, j)
				reg.Register(name, func(_ *config.ResolvedConfig) (provider.SecretProvider, error) {
					return &mockProvider{name: name}, nil
				})
				_, _ = reg.New(name, &config.ResolvedConfig{})
				_ = reg.Providers()
			}
		}(i)
	}

	wg.Wait()
	assert.Len(t, reg.Providers(), workers*iterations)
}
