package cli

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripCompletionPrefix(t *testing.T) {
	got := stripCompletionPrefix([]string{"/app/prod/DB_URL", "/app/prod/TOKEN"}, "/app/prod")
	assert.Equal(t, []string{"DB_URL", "TOKEN"}, got)
}

func TestFilterByPrefix(t *testing.T) {
	got := filterByPrefix([]string{"DB_URL", "DB_NAME", "TOKEN"}, "DB")
	assert.Equal(t, []string{"DB_URL", "DB_NAME"}, got)
}

func TestCompletion_SecondArgNoComplete(t *testing.T) {
	fn := completionFromNames(func() ([]string, string, error) {
		return []string{"DB_URL"}, "/app/prod", nil
	})
	out, directive := fn(&cobra.Command{}, []string{"already"}, "")
	assert.Nil(t, out)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestCompletion_ErrorYieldsNoCandidates(t *testing.T) {
	fn := completionFromNames(func() ([]string, string, error) {
		return nil, "", assert.AnError
	})
	out, directive := fn(&cobra.Command{}, nil, "")
	assert.Nil(t, out)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestCompletion_HappyPath(t *testing.T) {
	fn := completionFromNames(func() ([]string, string, error) {
		return []string{"/app/prod/DB_URL", "/app/prod/DB_NAME", "/app/prod/TOKEN"}, "/app/prod", nil
	})
	out, directive := fn(&cobra.Command{}, nil, "DB")
	assert.Equal(t, []string{"DB_URL", "DB_NAME"}, out)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestFilterByPrefix_EmptyToComplete_ReturnsAll(t *testing.T) {
	assert.Equal(t, []string{"A", "B"}, filterByPrefix([]string{"A", "B"}, ""))
}

func TestSecretKeyCompletion_LocalProvider(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	fn := secretKeyCompletion(&GlobalOpts{})

	// Empty toComplete returns all local key names (exercises the provider path
	// and the empty-prefix branch of filterByPrefix).
	out, directive := fn(&cobra.Command{}, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	assert.Equal(t, []string{"DB_URL", "TOKEN"}, out)

	// A prefix narrows the candidates to matching key names only.
	out, directive = fn(&cobra.Command{}, nil, "DB")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	assert.Equal(t, []string{"DB_URL"}, out)
}

func TestSecretKeyCompletion_LoadProviderError_NoCandidates(t *testing.T) {
	dir := t.TempDir() // no .skret.yaml and no --path => loadProvider fails
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	fn := secretKeyCompletion(&GlobalOpts{})
	out, directive := fn(&cobra.Command{}, nil, "")
	assert.Nil(t, out)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}
