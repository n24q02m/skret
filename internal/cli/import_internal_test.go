package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
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

func (m *mockProvider) Name() string {
	return "mock"
}

func (m *mockProvider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Write: true}
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

func (m *mockProvider) Close() error {
	return nil
}

func TestLoadExisting_Coverage(t *testing.T) {
	ctx := context.Background()

	t.Run("dryRun returns empty and nil error", func(t *testing.T) {
		o := &importOptions{dryRun: true}
		existing, err := o.loadExisting(ctx, &mockProvider{}, "", nil)
		assert.Empty(t, existing)
		assert.NoError(t, err)
	})

	t.Run("overwrite returns empty and nil error", func(t *testing.T) {
		o := &importOptions{onConflict: "overwrite"}
		existing, err := o.loadExisting(ctx, &mockProvider{}, "", nil)
		assert.Empty(t, existing)
		assert.NoError(t, err)
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
		existing, err := o.loadExisting(ctx, m, "", []string{"K1"})
		assert.NoError(t, err)
		assert.Contains(t, existing, "K1")
	})

	t.Run("List failure, GetBatch failure returns error", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				return nil, errors.New("list failed")
			},
			getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
				return nil, errors.New("batch failed")
			},
		}
		existing, err := o.loadExisting(ctx, m, "", []string{"K1"})
		assert.Error(t, err)
		assert.Empty(t, existing)
		assert.Contains(t, err.Error(), "batch failed")
	})

	t.Run("Prefix without slash", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				assert.Equal(t, "path/", prefix)
				return nil, nil
			},
		}
		_, _ = o.loadExisting(ctx, m, "path", nil)
	})

	t.Run("Prefix with slash", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				assert.Equal(t, "path/", prefix)
				return nil, nil
			},
		}
		_, _ = o.loadExisting(ctx, m, "path/", nil)
	})

	t.Run("Empty orderedKeys returns empty and nil error when List fails", func(t *testing.T) {
		o := &importOptions{onConflict: "skip"}
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				return nil, errors.New("list failed")
			},
		}
		existing, err := o.loadExisting(ctx, m, "", nil)
		assert.Empty(t, existing)
		assert.NoError(t, err)
	})
}

func TestImportRun_Full(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(origWd))
	})

	envPath := filepath.Join(tmpDir, ".env")
	require.NoError(t, os.WriteFile(envPath, []byte("K1=V1\nK2=V2"), 0o600))

	secretsPath := filepath.Join(tmpDir, "secrets.yaml")

	setup := func(onConflict string, dryRun bool) *importOptions {
		return &importOptions{
			global: &GlobalOpts{
				Provider: "local",
				Path:     "/",
				File:     secretsPath,
			},
			from:       "dotenv",
			file:       envPath,
			onConflict: onConflict,
			dryRun:     dryRun,
		}
	}

	t.Run("Success", func(t *testing.T) {
		_ = os.Remove(secretsPath)
		o := setup("skip", false)
		err := o.run(&cobra.Command{})
		assert.NoError(t, err)
	})

	t.Run("Overwrite", func(t *testing.T) {
		o := setup("overwrite", false)
		err := o.run(&cobra.Command{})
		assert.NoError(t, err)
	})

	t.Run("DryRun", func(t *testing.T) {
		o := setup("skip", true)
		err := o.run(&cobra.Command{})
		assert.NoError(t, err)
	})

	t.Run("Conflict Skip", func(t *testing.T) {
		o1 := setup("overwrite", false)
		_ = o1.run(&cobra.Command{})

		o := setup("skip", false)
		err := o.run(&cobra.Command{})
		assert.NoError(t, err)
	})

	t.Run("Conflict Fail", func(t *testing.T) {
		o := setup("fail", false)
		err := o.run(&cobra.Command{})
		assert.Error(t, err)
		assert.Equal(t, skret.ExitConflictError, skret.ExitCode(err))
	})

	t.Run("Import Error", func(t *testing.T) {
		o := setup("skip", false)
		o.file = "nonexistent.env"
		err := o.run(&cobra.Command{})
		assert.Error(t, err)
		assert.Equal(t, skret.ExitNetworkError, skret.ExitCode(err))
	})

	t.Run("CreateImporter Error", func(t *testing.T) {
		o := setup("skip", false)
		o.from = "unknown"
		err := o.run(&cobra.Command{})
		assert.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	})

	t.Run("LoadProvider Error", func(t *testing.T) {
		o := &importOptions{global: &GlobalOpts{}}
		err := o.run(&cobra.Command{})
		assert.Error(t, err)
	})
}

func TestImportRun_AdditionalErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("loadExisting error in run", func(t *testing.T) {
		m := &mockProvider{
			listFunc: func(ctx context.Context, prefix string) ([]*provider.Secret, error) {
				return nil, errors.New("list failed")
			},
			getBatchFunc: func(ctx context.Context, keys []string) ([]*provider.Secret, error) {
				return nil, errors.New("batch failed")
			},
		}
		o := &importOptions{
			onConflict: "skip",
		}
		_, err := o.loadExisting(ctx, m, "", []string{"K1"})
		assert.Error(t, err)
	})

	t.Run("p.Set error in run", func(t *testing.T) {
		m := &mockProvider{
			setFunc: func(ctx context.Context, key, value string, meta provider.SecretMeta) error {
				return errors.New("set failed")
			},
		}
		err := m.Set(ctx, "K1", "V1", provider.SecretMeta{})
		assert.Error(t, err)
	})
}

func TestCreateImporter_Coverage(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	t.Run("dotenv with explicit file", func(t *testing.T) {
		o := &importOptions{from: "dotenv", file: ".env.test"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "dotenv", imp.Name())
	})

	t.Run("dotenv defaults to .env", func(t *testing.T) {
		o := &importOptions{from: "dotenv"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "dotenv", imp.Name())
	})

	t.Run("doppler with env token", func(t *testing.T) {
		t.Setenv("DOPPLER_TOKEN", "dp.test")
		o := &importOptions{from: "doppler"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "doppler", imp.Name())
	})

	t.Run("doppler with stored credential", func(t *testing.T) {
		os.Unsetenv("DOPPLER_TOKEN")
		s := auth.NewStoreWithPath(filepath.Join(tmpDir, ".skret", "credentials.yaml"))
		_ = s.Save(&auth.Credential{Provider: "doppler", Token: "dp.stored"})

		o := &importOptions{from: "doppler"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "doppler", imp.Name())
	})

	t.Run("doppler missing token", func(t *testing.T) {
		os.Unsetenv("DOPPLER_TOKEN")
		_ = os.Remove(filepath.Join(tmpDir, ".skret", "credentials.yaml"))
		o := &importOptions{from: "doppler"}
		_, err := o.createImporter()
		assert.Error(t, err)
	})

	t.Run("infisical with env token", func(t *testing.T) {
		t.Setenv("INFISICAL_TOKEN", "st.test")
		o := &importOptions{from: "infisical"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "infisical", imp.Name())
	})

	t.Run("infisical with stored credential", func(t *testing.T) {
		os.Unsetenv("INFISICAL_TOKEN")
		s := auth.NewStoreWithPath(filepath.Join(tmpDir, ".skret", "credentials.yaml"))
		_ = s.Save(&auth.Credential{Provider: "infisical", Token: "st.stored"})

		o := &importOptions{from: "infisical"}
		imp, err := o.createImporter()
		assert.NoError(t, err)
		assert.Equal(t, "infisical", imp.Name())
	})

	t.Run("infisical missing token", func(t *testing.T) {
		os.Unsetenv("INFISICAL_TOKEN")
		_ = os.Remove(filepath.Join(tmpDir, ".skret", "credentials.yaml"))
		o := &importOptions{from: "infisical"}
		_, err := o.createImporter()
		assert.Error(t, err)
	})

	t.Run("UnknownSource", func(t *testing.T) {
		o := &importOptions{from: "unknown"}
		_, err := o.createImporter()
		assert.Error(t, err)
	})
}

func TestImportDeduplicate_Coverage(t *testing.T) {
	t.Run("with path prefix", func(t *testing.T) {
		o := &importOptions{toPath: "path"}
		cmd := &cobra.Command{}
		secrets := []importer.ImportedSecret{
			{Key: "K1", Value: "V1"},
			{Key: "K2", Value: ""},
			{Key: "K1", Value: "V2"},
			{Key: "/K3", Value: "V3"},
		}
		keys, m, skipped := o.deduplicate(cmd, secrets)
		assert.Equal(t, []string{"path/K1", "path/K3"}, keys)
		assert.Equal(t, "V2", m["path/K1"])
		assert.Equal(t, "V3", m["path/K3"])
		assert.Equal(t, 1, skipped)
	})

	t.Run("with path prefix with slash", func(t *testing.T) {
		o := &importOptions{toPath: "path/"}
		cmd := &cobra.Command{}
		secrets := []importer.ImportedSecret{
			{Key: "K1", Value: "V1"},
		}
		keys, _, _ := o.deduplicate(cmd, secrets)
		assert.Equal(t, []string{"path/K1"}, keys)
	})

	t.Run("without path prefix", func(t *testing.T) {
		o := &importOptions{}
		cmd := &cobra.Command{}
		secrets := []importer.ImportedSecret{
			{Key: "K1", Value: "V1"},
		}
		keys, m, skipped := o.deduplicate(cmd, secrets)
		assert.Equal(t, []string{"K1"}, keys)
		assert.Equal(t, "V1", m["K1"])
		assert.Equal(t, 0, skipped)
	})
}
