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

func TestSetCmd_JSONFormat_Created(t *testing.T) {
	dir := setupTestRepo(t)
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	out, err := runCLI(t, "set", "NEW_JSON_KEY", "s3cr3t", "--format", "json")
	require.NoError(t, err)
	assert.NotContains(t, out, "s3cr3t", "the secret value must never appear in output")

	var got cli.SetResult
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "NEW_JSON_KEY", got.Key)
	assert.True(t, got.Created, "a brand-new key must report created: true")
}

func TestSetCmd_JSONFormat_Updated(t *testing.T) {
	dir := setupTestRepo(t) // seeds DATABASE_URL, API_KEY, REDIS_URL
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	out, err := runCLI(t, "set", "API_KEY", "rotated-value", "--format", "json")
	require.NoError(t, err)
	assert.NotContains(t, out, "rotated-value")

	var got cli.SetResult
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "API_KEY", got.Key)
	assert.False(t, got.Created, "overwriting an existing key must report created: false")
}

func TestSetCmd_TableFormatUnchanged(t *testing.T) {
	dir := setupTestRepo(t)
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	cmd := cli.NewRootCmd()
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"set", "PLAIN_KEY", "value"})
	require.NoError(t, cmd.Execute())
	assert.Equal(t, "Set PLAIN_KEY\n", stderr.String(), "default (table) output must stay byte-identical")
}
