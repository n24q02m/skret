package cli

import (
	"bytes"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPrintSecrets_JSONWithValues(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 1},
		{Key: "B", Value: "val_b", Version: 2},
	}

	_ = printSecrets(cmd, secrets, "json", true)
	out := buf.String()
	assert.Contains(t, out, "\"value\": \"val_a\"")
	assert.Contains(t, out, "\"value\": \"val_b\"")
}

func TestPrintSecrets_JSONWithoutValues(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 1},
	}

	_ = printSecrets(cmd, secrets, "json", false)
	out := buf.String()
	assert.Contains(t, out, "\"key\": \"A\"")
	assert.NotContains(t, out, "\"value\"")
}

func TestPrintSecrets_Table(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	secrets := []*provider.Secret{
		{Key: "A", Value: "val_a", Version: 3},
	}

	_ = printSecrets(cmd, secrets, "table", false)
	out := buf.String()
	assert.Contains(t, out, "KEY")
	assert.Contains(t, out, "VERSION")
	assert.Contains(t, out, "A")
	assert.Contains(t, out, "3")
}

func TestFilterSecrets(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "/A"},
		{Key: "/A/B"},
		{Key: "/A/B/C"},
		{Key: "/X"},
		{Key: "Y"},
	}

	tests := []struct {
		name      string
		listPath  string
		recursive bool
		wantCount int
	}{
		{
			name:      "recursive all",
			listPath:  "",
			recursive: true,
			wantCount: 5,
		},
		{
			name:      "non-recursive /",
			listPath:  "/",
			recursive: false,
			wantCount: 2, // /A, /X (Y has 0 slashes, / has 1, /A has 1)
		},
		{
			name:      "non-recursive /A",
			listPath:  "/A",
			recursive: false,
			wantCount: 1, // /A/B (level of /A is 1, level++ makes it 2, /A/B has 2)
		},
		{
			name:      "non-recursive /A/",
			listPath:  "/A/",
			recursive: false,
			wantCount: 1, // /A/B (level of /A/ is 2, /A/B has 2)
		},
		{
			name:      "non-recursive /A/B",
			listPath:  "/A/B",
			recursive: false,
			wantCount: 1, // /A/B/C
		},
		{
			name:      "recursive /A",
			listPath:  "/A",
			recursive: true,
			wantCount: 5, // recursive returns all
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterSecrets(secrets, tt.listPath, tt.recursive)
			assert.Equal(t, tt.wantCount, len(got))
		})
	}
}

func TestNewListCmd_Flags(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newListCmd(opts)

	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("values"))
	assert.NotNil(t, cmd.Flags().Lookup("path"))
	assert.NotNil(t, cmd.Flags().Lookup("recursive"))
}
