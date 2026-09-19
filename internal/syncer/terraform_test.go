package syncer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformSyncer_WritesSortedTFVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skret.auto.tfvars")

	secrets := []*provider.Secret{
		{Key: "DB_URL", Value: "postgres://host"},
		{Key: "/app/prod/API_KEY", Value: "sk-123"}, // nested key -> last segment
		{Key: "ALPHA", Value: "first"},
	}

	require.NoError(t, NewTerraform(path).Sync(context.Background(), secrets))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	// Assignments are sorted by variable name; names come from SecretName.
	assert.Equal(t, []string{
		`ALPHA = "first"`,
		`API_KEY = "sk-123"`,
		`DB_URL = "postgres://host"`,
	}, lines)
	assert.NotContains(t, content, "/app/prod", "raw nested key must not leak into the tfvars line")
}

func TestTerraformSyncer_HCLQuoting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terraform.tfvars")

	secrets := []*provider.Secret{
		{Key: "BCRYPT", Value: "$2a$14$N9qo8uLOickgx2ZMRZoMye"},
		{Key: "BACKSLASH", Value: `a\b`},
		{Key: "QUOTE", Value: `a"b`},
		{Key: "MULTILINE", Value: "line1\nline2"},
		{Key: "CRLF", Value: "a\rb"},
		{Key: "TABVAL", Value: "a\tb"},
		{Key: "CTRL", Value: "a\x01b"},
	}
	require.NoError(t, NewTerraform(path).Sync(context.Background(), secrets))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, `BCRYPT = "$2a$14$N9qo8uLOickgx2ZMRZoMye"`) // byte-exact, no $-expansion
	assert.Contains(t, content, `BACKSLASH = "a\\b"`)
	assert.Contains(t, content, `QUOTE = "a\"b"`)
	assert.Contains(t, content, `MULTILINE = "line1\nline2"`)
	assert.Contains(t, content, `CRLF = "a\rb"`)
	assert.Contains(t, content, `TABVAL = "a\tb"`)
	assert.Contains(t, content, `CTRL = "a\u0001b"`)
}

func TestTerraformSyncer_CollisionFailsWithoutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terraform.tfvars")

	err := NewTerraform(path).Sync(context.Background(), []*provider.Secret{
		{Key: "/app/prod/db/HOST", Value: "db.internal"},
		{Key: "/app/prod/cache/HOST", Value: "cache.internal"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "HOST")
	assert.ErrorContains(t, err, "/app/prod/db/HOST")
	assert.ErrorContains(t, err, "/app/prod/cache/HOST")
	assert.NotContains(t, err.Error(), "db.internal", "secret values must never appear in errors")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "no file must be written when a collision is detected")
}

func TestTerraformSyncer_InvalidVariableNameRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terraform.tfvars")

	for _, key := range []string{"9STARTS-DIGIT", "HAS.SPACE", "/a/b/HAS DOT"} {
		err := NewTerraform(path).Sync(context.Background(), []*provider.Secret{
			{Key: key, Value: "v"},
		})
		require.Error(t, err, "key %q must be rejected", key)
		assert.ErrorContains(t, err, "not a valid terraform variable name")
	}
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestTerraformSyncer_EmptySecretsWriteEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "terraform.tfvars")
	require.NoError(t, NewTerraform(path).Sync(context.Background(), nil))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, string(data))
}

func TestTerraformSyncer_DefaultFile(t *testing.T) {
	assert.Equal(t, "terraform.tfvars", NewTerraform("").(*TerraformSyncer).filePath)
	assert.Equal(t, "custom.tfvars", NewTerraform("custom.tfvars").(*TerraformSyncer).filePath)
	assert.Equal(t, "terraform", NewTerraform("").Name())
}

func TestTerraformFactoryFromConfig(t *testing.T) {
	s, err := newTerraformFromConfig(TargetConfig{Fields: map[string]string{"file": "skret.auto.tfvars"}})
	require.NoError(t, err)
	assert.Equal(t, "skret.auto.tfvars", s.(*TerraformSyncer).filePath)

	s, err = newTerraformFromConfig(TargetConfig{Fields: map[string]string{}})
	require.NoError(t, err)
	assert.Equal(t, "terraform.tfvars", s.(*TerraformSyncer).filePath)
}
