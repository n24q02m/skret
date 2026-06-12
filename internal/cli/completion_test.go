package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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
