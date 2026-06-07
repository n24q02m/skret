package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/importer"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProvider struct {
	provider.SecretProvider
	listFunc     func(ctx context.Context, prefix string) ([]*provider.Secret, error)
	getBatchFunc func(ctx context.Context, keys []string) ([]*provider.Secret, error)
	getFunc      func(ctx context.Context, key string) (*provider.Secret, error)
	setFunc      func(ctx context.Context, key, value string, meta provider.SecretMeta) error
}

func (m *mockProvider) List(ctx context.Context, prefix string) ([]*provider.Secret, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, prefix)
	}
	return nil, nil
}

func (m *mockProvider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if m.getBatchFunc != nil {
		return m.getBatchFunc(ctx, keys)
	}
	return nil, nil
}

func (m *mockProvider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	return nil, provider.ErrNotFound
}

func (m *mockProvider) Set(ctx context.Context, key, value string, meta provider.SecretMeta) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, value, meta)
	}
	return nil
}

func (m *mockProvider) Close() error { return nil }

func TestLoadExisting_Coverage(t *testing.T) {
	ctx := context.Background()

	t.Run("dryRun returns empty and false", func(t *testing.T) {
		o := &importOptions{dryRun: true}
		existing, loaded := o.loadExisting(ctx, &mockProvider{}, "", nil)
		assert.Empty(t, existing)
		assert.False(t, loaded)
	})

	t.Run("overwrite returns empty and false", func(t *testing.T) {
		o := &importOptions{onConflict: "overwrite"}
		existing, loaded := o.loadExisting(ctx, &mockProvider{}, "", nil)
		assert.Empty(t, existing)
		assert.False(t, loaded)
	})

	t.Run("List failure, GetBatch success", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				return nil, errors.New("list failed")
			},
			getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
				return []*provider.Secret{{Key: "K1"}}, nil
			},
		}
		existing, loaded := o.loadExisting(ctx, m, "", []string{"K1"})
		assert.True(t, loaded)
		assert.Contains(t, existing, "K1")
	})

	t.Run("List failure, GetBatch failure", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				return nil, errors.New("list failed")
			},
			getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
				return nil, errors.New("batch failed")
			},
		}
		existing, loaded := o.loadExisting(ctx, m, "", []string{"K1"})
		assert.False(t, loaded)
		assert.Empty(t, existing)
	})

	t.Run("Prefix without slash", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				assert.Equal(t, "path/", prefix)
				return nil, nil
			},
		}
		o.loadExisting(ctx, m, "path", nil)
	})
}

func TestCreateImporter_UnknownSource(t *testing.T) {
	o := &importOptions{from: "unknown"}
	_, err := o.createImporter()
	assert.Error(t, err)
	var skErr *skret.Error
	require.True(t, errors.As(err, &skErr))
	assert.Equal(t, skret.ExitConfigError, skErr.Code)
}

func TestImportDeduplicate_Coverage(t *testing.T) {
	o := &importOptions{toPath: "path"} // path without slash
	cmd := &cobra.Command{}
	secrets := []importer.ImportedSecret{
		{Key: "K1", Value: "V1"},
	}
	keys, m, skipped := o.deduplicate(cmd, secrets)
	assert.Equal(t, []string{"path/K1"}, keys)
	assert.Equal(t, "V1", m["path/K1"])
	assert.Equal(t, 0, skipped)
}

type mockImporter struct {
	name    string
	secrets []importer.ImportedSecret
	err     error
}

func (m *mockImporter) Name() string { return m.name }
func (m *mockImporter) Import(ctx context.Context) ([]importer.ImportedSecret, error) {
	return m.secrets, m.err
}

func TestImport_NPlusOneFallback(t *testing.T) {
	cmd := &cobra.Command{}

	secrets := []importer.ImportedSecret{
		{Key: "K1", Value: "V1"},
		{Key: "K2", Value: "V2"},
	}
	imp := &mockImporter{name: "mock", secrets: secrets}

	var getCalls int
	m := &mockProvider{
		listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
			return nil, errors.New("list failed")
		},
		getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
			return nil, errors.New("batch failed")
		},
		getFunc: func(ctx context.Context, key string) (*provider.Secret, error) {
			getCalls++
			return nil, provider.ErrNotFound
		},
		setFunc: func(ctx context.Context, key, value string, meta provider.SecretMeta) error {
			return nil
		},
	}

	o := &importOptions{
		onConflict: "skip",
	}

	err := o.execute(cmd, m, imp)
	assert.Error(t, err)
	var skErr *skret.Error
	require.True(t, errors.As(err, &skErr))
	assert.Equal(t, skret.ExitProviderError, skErr.Code)
	assert.Contains(t, err.Error(), "could not efficiently check for existing secrets")
	assert.Equal(t, 0, getCalls, "Expected 0 Get calls (N+1 fallback removed)")
}
