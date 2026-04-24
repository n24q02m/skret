package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSave_WriteError tests the write error path in save()
// by removing the temp directory after the provider is created.
func TestSave_WriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets:\n  K: v"), 0o600))

	p := &Provider{filePath: path}
	require.NoError(t, p.load())

	// Make the directory non-writable by removing it and creating a file in its place
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.RemoveAll(dir))

	err := p.save()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "local: create temp")
}

// TestSave_RenameError tests the rename error path in save()
func TestSave_RenameError(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0o700))
	path := filepath.Join(subdir, ".secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets:\n  K: v"), 0o600))

	p := &Provider{filePath: path}
	require.NoError(t, p.load())

	// Replace the target file with a directory so rename fails
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Mkdir(path, 0o700))

	err := p.save()
	assert.Error(t, err)
}

// TestSave_Success tests the full save path succeeds
func TestSave_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets:\n  K: v"), 0o600))

	p := &Provider{filePath: path}
	require.NoError(t, p.load())

	// Modify data and save
	p.data.Secrets["NEW"] = "value"
	require.NoError(t, p.save())

	// Verify file was written
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "NEW")
	assert.Contains(t, string(raw), "value")
}

// TestLoad_MissingFile — missing file is treated as empty (quickstart path).
func TestLoad_MissingFile(t *testing.T) {
	p := &Provider{filePath: filepath.Join(t.TempDir(), "does-not-exist.yaml")}
	require.NoError(t, p.load())
	assert.NotNil(t, p.data.Secrets)
	assert.Empty(t, p.data.Secrets)
}

// TestLoad_ReadError — genuine read error (directory passed as file).
func TestLoad_ReadError(t *testing.T) {
	p := &Provider{filePath: t.TempDir()} // directory, not a file
	err := p.load()
	assert.Error(t, err)
}

// TestLoad_UnmarshalError tests load() with invalid YAML
func TestLoad_UnmarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{{invalid"), 0o600))

	p := &Provider{filePath: path}
	err := p.load()
	assert.Error(t, err)
}

// TestNew_LoadErrorDirectoryAsFile tests load() when filePath points to a
// directory (genuine read error, not just missing file).
func TestNew_LoadErrorDirectoryAsFile(t *testing.T) {
	p := &Provider{filePath: t.TempDir()}
	err := p.load()
	assert.Error(t, err)
}

// TestProvider_Concurrent_Internal tests concurrent access to save()
func TestProvider_Concurrent_Internal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secrets.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\nsecrets: {}"), 0o600))

	p := &Provider{filePath: path}
	require.NoError(t, p.load())

	ctx := context.Background()
	errs := make(chan error, 10)

	for i := 0; i < 5; i++ {
		go func(n int) {
			key := "KEY"
			err := p.Set(ctx, key, "value", provider.SecretMeta{})
			if err != nil {
				errs <- err
			} else {
				errs <- nil
			}
		}(i)
	}

	for i := 0; i < 5; i++ {
		err := <-errs
		assert.NoError(t, err)
	}
}
