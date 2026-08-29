package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapProviderMutationErrorSurfacesPartialStateForSetAndImport(t *testing.T) {
	partial := &provider.PartialCommitError{
		Provider:        "aws",
		Key:             "/fixture/PARTIAL",
		Version:         7,
		ObservedVersion: 7,
		TagState:        provider.TagReconciliationRequired,
	}
	for _, operation := range []string{"set", "import"} {
		t.Run(operation, func(t *testing.T) {
			err := wrapProviderMutationError(operation, partial.Key, partial)
			require.Error(t, err)
			assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
			assert.ErrorIs(t, err, provider.ErrPartialCommit)
			assert.Contains(t, err.Error(), "value committed")
			assert.Contains(t, err.Error(), "tag reconciliation required")
			assert.Contains(t, err.Error(), "observed version 7")
			assert.NotContains(t, err.Error(), "fixture-secret-value")
			var got *provider.PartialCommitError
			assert.True(t, errors.As(err, &got))
		})
	}
}

func TestImportRunWithProviderSurfacesPartialCommit(t *testing.T) {
	source := filepath.Join(t.TempDir(), "fixture.env")
	require.NoError(t, os.WriteFile(source, []byte("FIXTURE_KEY=fixture-secret-value\n"), 0o600))
	partial := &provider.PartialCommitError{
		Provider:        "aws",
		Key:             "FIXTURE_KEY",
		Version:         3,
		ObservedVersion: 2,
		TagState:        provider.TagReconciliationUnknown,
	}
	o := &importOptions{
		from:       "dotenv",
		file:       source,
		onConflict: "overwrite",
	}
	err := o.runWithProvider(context.Background(), &cobra.Command{}, &mockProvider{
		setFunc: func(context.Context, string, string, provider.SecretMeta) error {
			return partial
		},
	})
	require.Error(t, err)
	assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
	assert.ErrorIs(t, err, provider.ErrPartialCommit)
	assert.Contains(t, err.Error(), "partially committed")
	assert.Contains(t, err.Error(), "tag_reconciliation_unknown")
	assert.NotContains(t, err.Error(), "fixture-secret-value")
}
