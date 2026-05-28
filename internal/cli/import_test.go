package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockErrorProvider struct {
	provider.SecretProvider
}

func (m *mockErrorProvider) Name() string { return "mock-error" }

func (m *mockErrorProvider) List(ctx context.Context, prefix string) ([]*provider.Secret, error) {
	return nil, errors.New("list error")
}

func (m *mockErrorProvider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	return nil, errors.New("getbatch error")
}

func (m *mockErrorProvider) Set(ctx context.Context, key, value string, meta provider.SecretMeta) error {
	return nil
}

func (m *mockErrorProvider) Close() error { return nil }

func TestImportOptions_Run_BulkConflictFails(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.test")
	require.NoError(t, os.WriteFile(envFile, []byte("KEY1=VAL1\nKEY2=VAL2\n"), 0o644))

	var errBuf bytes.Buffer
	var outBuf bytes.Buffer

	cmd := newImportCmd(&GlobalOpts{})
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)

	o := &importOptions{
		global:     &GlobalOpts{},
		from:       "dotenv",
		file:       envFile,
		onConflict: "skip",
		p:          &mockErrorProvider{},
	}

	err := o.run(cmd)
	require.NoError(t, err)

	assert.Contains(t, errBuf.String(), "warning: could not list existing secrets; conflict detection may be incomplete")
	assert.Contains(t, errBuf.String(), "Imported: 2")
}
