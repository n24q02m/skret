package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCmd_DefaultOutput(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"get", "DATABASE_URL"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db\n", buf.String())
}

func TestGetCmd_NotFound(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	cmd := cli.NewRootCmd()
	cmd.SetArgs([]string{"get", "NONEXISTENT"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetCmd_PlainFlag(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"get", "DATABASE_URL", "--plain"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db", buf.String())
}

func TestGetCmd_JSON(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"get", "DATABASE_URL", "--json"})

	err := cmd.Execute()
	require.NoError(t, err)

	var out map[string]string
	err = json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)
	assert.Equal(t, "DATABASE_URL", out["key"])
	assert.Equal(t, "postgres://dev:dev@localhost/db", out["value"])
	assert.NotContains(t, out, "version")
}

func TestGetCmd_WithMetadata(t *testing.T) {
	dir := setupTestRepo(t)
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	var buf bytes.Buffer
	cmd := cli.NewRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"get", "DATABASE_URL", "--with-metadata"})

	err := cmd.Execute()
	require.NoError(t, err)

	var out map[string]any
	err = json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)
	assert.Equal(t, "DATABASE_URL", out["key"])
	assert.Equal(t, "postgres://dev:dev@localhost/db", out["value"])
	assert.Contains(t, out, "version")
	assert.Contains(t, out, "meta")
}
