package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintSecret(t *testing.T) {
	secret := &provider.Secret{
		Key:     "TEST_KEY",
		Value:   "test-value",
		Version: 1,
		Meta: provider.SecretMeta{
			Description: "test description",
		},
	}

	tests := []struct {
		name         string
		outputJSON   bool
		withMetadata bool
		plain        bool
		want         string
	}{
		{
			name: "default output",
			want: "test-value\n",
		},
		{
			name:  "plain output",
			plain: true,
			want:  "test-value",
		},
		{
			name:       "json output",
			outputJSON: true,
			want:       "{\n  \"key\": \"TEST_KEY\",\n  \"value\": \"test-value\"\n}\n",
		},
		{
			name:         "with metadata output",
			withMetadata: true,
			want:         "{\n  \"key\": \"TEST_KEY\",\n  \"meta\": {\n    \"Description\": \"test description\",\n    \"Tags\": null,\n    \"CreatedAt\": \"0001-01-01T00:00:00Z\",\n    \"UpdatedAt\": \"0001-01-01T00:00:00Z\",\n    \"CreatedBy\": \"\"\n  },\n  \"value\": \"test-value\",\n  \"version\": 1\n}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			cmd := newGetCmd(&GlobalOpts{})
			cmd.SetOut(buf)

			err := printSecret(cmd, secret, tt.outputJSON, tt.withMetadata, tt.plain)
			require.NoError(t, err)

			if tt.outputJSON || tt.withMetadata {
				var gotMap, wantMap map[string]any
				err := json.Unmarshal(buf.Bytes(), &gotMap)
				require.NoError(t, err)
				err = json.Unmarshal([]byte(tt.want), &wantMap)
				require.NoError(t, err)
				assert.Equal(t, wantMap, gotMap)
			} else {
				assert.Equal(t, tt.want, buf.String())
			}
		})
	}
}

func TestNewGetCmd_Flags(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newGetCmd(opts)

	assert.NotNil(t, cmd.Flags().Lookup("json"))
	assert.NotNil(t, cmd.Flags().Lookup("with-metadata"))
	assert.NotNil(t, cmd.Flags().Lookup("plain"))
}

func TestGetCmd_Args(t *testing.T) {
	opts := &GlobalOpts{}
	cmd := newGetCmd(opts)

	err := cmd.Args(cmd, []string{})
	assert.Error(t, err)

	err = cmd.Args(cmd, []string{"key1", "key2"})
	assert.Error(t, err)

	err = cmd.Args(cmd, []string{"key1"})
	assert.NoError(t, err)
}

func setupGetTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644)

	os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets:
  TEST_KEY: "test-value"
  SECRET_KEY: "secret-value"
`), 0o600)

	return dir
}

func TestGetCmd_Run(t *testing.T) {
	dir := setupGetTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	tests := []struct {
		name           string
		args           []string
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "basic get",
			args:           []string{"TEST_KEY"},
			expectedOutput: "test-value\n",
		},
		{
			name:           "plain output",
			args:           []string{"TEST_KEY", "--plain"},
			expectedOutput: "test-value",
		},
		{
			name: "json output",
			args: []string{"TEST_KEY", "--json"},
			expectedOutput: `{
  "key": "TEST_KEY",
  "value": "test-value"
}
`,
		},
		{
			name:           "with metadata",
			args:           []string{"TEST_KEY", "--with-metadata"},
			expectedOutput: `"key": "TEST_KEY"`,
		},
		{
			name:        "not found",
			args:        []string{"NONEXISTENT"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts := &GlobalOpts{}
			cmd := newGetCmd(opts)
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				switch tt.name {
				case "json output":
					var m map[string]string
					err := json.Unmarshal(buf.Bytes(), &m)
					require.NoError(t, err)
					assert.Equal(t, "TEST_KEY", m["key"])
					assert.Equal(t, "test-value", m["value"])
				case "with metadata":
					assert.Contains(t, buf.String(), tt.expectedOutput)
					assert.Contains(t, buf.String(), "version")
				default:
					assert.Equal(t, tt.expectedOutput, buf.String())
				}
			}
		})
	}
}

func TestGetCmd_NotFoundSuggestsSet(t *testing.T) {
	dir := setupGetTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	cmd := newGetCmd(&GlobalOpts{})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"NONEXISTENT"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skret set NONEXISTENT")
}
