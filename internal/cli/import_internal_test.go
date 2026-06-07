package cli

import (
	"context"
	"errors"
	"os"
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
	setBatchFunc func(ctx context.Context, secrets []*provider.Secret) error
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

func (m *mockProvider) SetBatch(ctx context.Context, secrets []*provider.Secret) error {
	if m.setBatchFunc != nil {
		return m.setBatchFunc(ctx, secrets)
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

func TestImport_Run_SetBatchError(t *testing.T) {
	tmpFile := ".env.test"
	os.WriteFile(tmpFile, []byte("K1=V1"), 0o644)
	defer os.Remove(tmpFile)

	m := &mockProvider{
		setBatchFunc: func(ctx context.Context, secrets []*provider.Secret) error {
			return errors.New("batch failed")
		},
	}

	o := &importOptions{
		from:     "dotenv",
		file:     tmpFile,
		provider: m,
	}

	err := o.run(&cobra.Command{})
	assert.Error(t, err)
	var skErr *skret.Error
	require.True(t, errors.As(err, &skErr))
	assert.Equal(t, skret.ExitProviderError, skErr.Code)
	assert.Contains(t, err.Error(), "import: set batch failed")
}

func TestImport_Run_ConflictFail(t *testing.T) {
	tmpFile := ".env.test"
	os.WriteFile(tmpFile, []byte("K1=V1"), 0o644)
	defer os.Remove(tmpFile)

	m := &mockProvider{
		listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
			return nil, errors.New("list failed")
		},
		getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
			return nil, errors.New("batch failed")
		},
		getFunc: func(ctx context.Context, key string) (*provider.Secret, error) {
			return &provider.Secret{Key: "K1", Value: "EX"}, nil
		},
	}

	o := &importOptions{
		from:       "dotenv",
		file:       tmpFile,
		provider:   m,
		onConflict: "fail",
	}

	err := o.run(&cobra.Command{})
	assert.Error(t, err)
	var skErr *skret.Error
	require.True(t, errors.As(err, &skErr))
	assert.Equal(t, skret.ExitConflictError, skErr.Code)
}

func TestCreateImporter_DotenvDefault(t *testing.T) {
	o := &importOptions{from: "dotenv"}
	imp, err := o.createImporter()
	assert.NoError(t, err)
	assert.Equal(t, "dotenv", imp.Name())
}

func TestCreateImporter_Doppler(t *testing.T) {
	os.Setenv("DOPPLER_TOKEN", "test-token")
	defer os.Unsetenv("DOPPLER_TOKEN")
	o := &importOptions{from: "doppler"}
	imp, err := o.createImporter()
	assert.NoError(t, err)
	assert.Equal(t, "doppler", imp.Name())
}

func TestCreateImporter_Infisical(t *testing.T) {
	os.Setenv("INFISICAL_TOKEN", "test-token")
	defer os.Unsetenv("INFISICAL_TOKEN")
	o := &importOptions{from: "infisical"}
	imp, err := o.createImporter()
	assert.NoError(t, err)
	assert.Equal(t, "infisical", imp.Name())
}

func TestCreateImporter_Doppler_NoToken(t *testing.T) {
	orig := os.Getenv("DOPPLER_TOKEN")
	os.Unsetenv("DOPPLER_TOKEN")
	defer os.Setenv("DOPPLER_TOKEN", orig)

	o := &importOptions{from: "doppler"}
	_, err := o.createImporter()
	assert.Error(t, err)
}

func TestCreateImporter_Infisical_NoToken(t *testing.T) {
	orig := os.Getenv("INFISICAL_TOKEN")
	os.Unsetenv("INFISICAL_TOKEN")
	defer os.Setenv("INFISICAL_TOKEN", orig)

	o := &importOptions{from: "infisical"}
	_, err := o.createImporter()
	assert.Error(t, err)
}

func TestImport_Run_LoadProviderError(t *testing.T) {
	// To trigger loadProvider error, we can run in a directory with no config and no --path.
	// But our run method uses o.global.
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(orig)

	o := &importOptions{
		global: &GlobalOpts{},
	}
	err := o.run(&cobra.Command{})
	assert.Error(t, err)
}

func TestCreateImporter_Doppler_AuthResolve(t *testing.T) {
	os.Unsetenv("DOPPLER_TOKEN")
	// We need to mock auth.Resolve.
	// auth.Resolve is not a package-level variable, it's a function.
	// But in this repo, auth.Resolve often relies on the backend store.
}

func TestImport_Run_ConflictSkip(t *testing.T) {
	tmpFile := ".env.test"
	os.WriteFile(tmpFile, []byte("K1=V1"), 0o644)
	defer os.Remove(tmpFile)

	m := &mockProvider{
		listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
			return nil, errors.New("list failed")
		},
		getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
			return nil, errors.New("batch failed")
		},
		getFunc: func(ctx context.Context, key string) (*provider.Secret, error) {
			return &provider.Secret{Key: "K1", Value: "EX"}, nil
		},
	}

	o := &importOptions{
		from:       "dotenv",
		file:       tmpFile,
		provider:   m,
		onConflict: "skip",
	}

	err := o.run(&cobra.Command{})
	assert.NoError(t, err)
}
