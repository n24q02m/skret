package cli

import (
	"bytes"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestFilterSecrets_NonRecursive(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "/app/DB"},          // 2 slashes
		{Key: "/app/nested/KEY"}, // 3 slashes
	}

	// listPath="/app/" -> strings.Count = 2, ends with "/" so level stays 2
	// "/app/DB" -> strings.Count = 2 -> matches level 2
	// "/app/nested/KEY" -> strings.Count = 3 -> skip
	filtered := filterSecrets(secrets, "/app/", false)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "/app/DB", filtered[0].Key)

	// Test with path that does NOT end with "/"
	// listPath="/app" -> strings.Count = 1, no trailing slash -> level = 1+1 = 2
	// Same result since level is 2 either way for this case
	filtered2 := filterSecrets(secrets, "/app", false)
	assert.Len(t, filtered2, 1)
	assert.Equal(t, "/app/DB", filtered2[0].Key)

	// Verify deeper filtering
	deepSecrets := []*provider.Secret{
		{Key: "/a/b/c"},     // 3 slashes
		{Key: "/a/b/c/d"},   // 4 slashes
		{Key: "/a/b"},       // 2 slashes
	}
	// listPath="/a/b/" -> strings.Count = 3, ends with "/" -> level stays 3
	filtered3 := filterSecrets(deepSecrets, "/a/b/", false)
	assert.Len(t, filtered3, 1)
	assert.Equal(t, "/a/b/c", filtered3[0].Key)
}

func TestFilterSecrets_NoPath(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "A"},
		{Key: "B"},
	}
	// Empty path returns all regardless of recursive setting
	filtered := filterSecrets(secrets, "", false)
	assert.Len(t, filtered, 2)
}

func TestPrintSecrets_JSONWithValues(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 1},
		{Key: "B", Value: "val_b", Version: 2},
	}

	printSecrets(cmd, secrets, "json", true)
	out := buf.String()
	assert.Contains(t, out, `"value": "val_a"`)
	assert.Contains(t, out, `"value": "val_b"`)
}

func TestPrintSecrets_JSONWithoutValues(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 1},
	}

	printSecrets(cmd, secrets, "json", false)
	out := buf.String()
	assert.Contains(t, out, `"key": "A"`)
	assert.NotContains(t, out, `"value"`)
}

func TestPrintSecrets_Table(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 3},
	}

	printSecrets(cmd, secrets, "table", false)
	out := buf.String()
	assert.Contains(t, out, "KEY")
	assert.Contains(t, out, "VERSION")
	assert.Contains(t, out, "A")
	assert.Contains(t, out, "3")
}

func TestNewListCmd(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newListCmd(opts)

	assert.Equal(t, "list", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("values"))
	assert.NotNil(t, cmd.Flags().Lookup("path"))
	assert.NotNil(t, cmd.Flags().Lookup("recursive"))

	format, _ := cmd.Flags().GetString("format")
	assert.Equal(t, "table", format)

	values, _ := cmd.Flags().GetBool("values")
	assert.False(t, values)

	recursive, _ := cmd.Flags().GetBool("recursive")
	assert.True(t, recursive)
}
