//go:build !windows

package syncer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanStateManifestRootPortable_RejectsUnsupportedEntries(t *testing.T) {
	t.Run("root is a regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		require.NoError(t, os.WriteFile(path, []byte("state"), 0o600))
		files, err := scanStateManifestRoot(path)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: invalid source root", err.Error())
	})

	t.Run("unreadable subdirectory", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte("state"), 0o600))
		locked := filepath.Join(root, "locked")
		require.NoError(t, os.Mkdir(locked, 0o700))
		faultChmod(t, locked, 0o000, 0o700)
		files, err := scanStateManifestRoot(root)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: source root scan failed", err.Error())
	})

	t.Run("named pipe", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte("state"), 0o600))
		require.NoError(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600))
		files, err := scanStateManifestRoot(root)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: non-regular entries are not allowed", err.Error())
	})

	t.Run("file name outside the manifest path grammar", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "a:b"), []byte("state"), 0o600))
		files, err := scanStateManifestRoot(root)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: invalid file path", err.Error())
	})

	t.Run("unreadable file", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "state.json")
		require.NoError(t, os.WriteFile(path, []byte("state"), 0o600))
		faultBlockRead(t, path)
		files, err := scanStateManifestRoot(root)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: file read failed", err.Error())
	})
}

func TestDurableReplacePortable_ReportsMissingParentDirectoryBarrier(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.tmp")
	target := filepath.Join(dir, "target.env")
	require.NoError(t, os.WriteFile(source, []byte("K=v\n"), 0o600))

	err := durableReplace(source, target, filepath.Join(dir, "missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open parent directory")
	assert.NoFileExists(t, source)
	assert.Equal(t, []byte("K=v\n"), mustReadFile(t, target))
}
