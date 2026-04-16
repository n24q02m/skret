package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppendGitignore_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.gitignore"
	err := appendGitignore(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), ".secrets.*.yaml")
	assert.Contains(t, string(data), ".secrets.*.yml")
}

func TestAppendGitignore_ExistingWithoutNewline(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.gitignore"
	// Write without trailing newline
	require.NoError(t, os.WriteFile(path, []byte("node_modules/"), 0o644))
	err := appendGitignore(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "node_modules/")
	assert.Contains(t, content, ".secrets.*.yaml")
}

func TestInitOptions_Run_MarshalCheck(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	o := &initOptions{
		provider: "aws",
		path:     "/myapp/staging",
		region:   "ap-southeast-1",
		file:     "",
		force:    false,
	}

	err := o.run(cmd)
	require.NoError(t, err)

	data, err := os.ReadFile(dir + "/.skret.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(data), "ap-southeast-1")
	assert.Contains(t, string(data), "/myapp/staging")
}

func TestInitOptions_Run_WithFileFlag(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	o := &initOptions{
		provider: "local",
		file:     ".my-secrets.yaml",
	}

	err := o.run(cmd)
	require.NoError(t, err)

	data, err := os.ReadFile(dir + "/.skret.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(data), ".my-secrets.yaml")
}

func TestInitOptions_Run_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/.git", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("existing"), 0o600))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir)

	cmd := &cobra.Command{}
	o := &initOptions{force: false}

	err := o.run(cmd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestAppendGitignore_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	content := "# skret local provider files\n.secrets.*.yaml\n.secrets.*.yml\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	err := appendGitignore(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestNewInitCmd(t *testing.T) {
	cmd := newInitCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "init", cmd.Use)

	// Check flags
	assert.NotNil(t, cmd.Flags().Lookup("provider"))
	assert.NotNil(t, cmd.Flags().Lookup("path"))
	assert.NotNil(t, cmd.Flags().Lookup("region"))
	assert.NotNil(t, cmd.Flags().Lookup("file"))
	assert.NotNil(t, cmd.Flags().Lookup("force"))
}
