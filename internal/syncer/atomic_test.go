package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAtomicWrite_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")

	err := atomicWrite(target, dir, ".test-*", func(f *os.File) error {
		_, err := f.WriteString("hello world")
		return err
	})
	require.NoError(t, err)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))
}

func TestAtomicWrite_CreateTempError(t *testing.T) {
	err := atomicWrite("/nonexistent/path/file.txt", "/nonexistent/path", ".test-*", func(f *os.File) error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create temp")
}

func TestAtomicWrite_WriteError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	writeErr := errors.New("simulated write failure")

	err := atomicWrite(target, dir, ".test-*", func(f *os.File) error {
		return writeErr
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write")
	assert.ErrorIs(t, err, writeErr)

	// Temp file should be cleaned up
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		assert.False(t, e.Name() == "out.txt", "target should not exist after write error")
	}
}

func TestAtomicWrite_RenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(target, 0o700))

	err := atomicWrite(target, dir, ".test-*", func(f *os.File) error {
		_, err := f.WriteString("data")
		return err
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rename")
}

func TestAtomicWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	err := atomicWrite(target, dir, ".test-*", func(f *os.File) error {
		_, err := f.WriteString("new content")
		return err
	})
	require.NoError(t, err)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "new content", string(data))
}
