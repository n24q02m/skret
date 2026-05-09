package cli

import (
	"context"

	"github.com/n24q02m/skret/internal/provider"
)

type mockProvider struct {
	rollbackCalled bool
}

func (m *mockProvider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) GetBatch(ctx context.Context, keys []string) (map[string]*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) Set(ctx context.Context, key, value string, meta provider.SecretMeta) error {
	return nil
}

func (m *mockProvider) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockProvider) List(ctx context.Context, path string) ([]*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	return nil, nil
}

func (m *mockProvider) Rollback(ctx context.Context, key string, version int64) error {
	m.rollbackCalled = true
	return nil
}

func (m *mockProvider) Close() error { return nil }
