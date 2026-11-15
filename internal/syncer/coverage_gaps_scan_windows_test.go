//go:build windows

package syncer

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// coverageUnusedDriveRoot returns a drive root such as `Q:\` that is not
// mounted on this machine.
func coverageUnusedDriveRoot(t *testing.T) string {
	t.Helper()
	mounted, err := windows.GetLogicalDrives()
	require.NoError(t, err)
	for letter := 'Z'; letter >= 'D'; letter-- {
		if mounted&(1<<uint(letter-'A')) == 0 {
			return string(letter) + `:\`
		}
	}
	t.Skip("every drive letter is mounted")
	return ""
}

func coverageLstat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	return info
}

func TestWindowsScanner_RejectsInvalidRoots(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		files, err := scanStateManifestRoot(filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: invalid source root", err.Error())
	})

	t.Run("relative root has no volume", func(t *testing.T) {
		t.Chdir(t.TempDir())
		require.NoError(t, os.Mkdir("state", 0o700))
		require.NoError(t, os.WriteFile(filepath.Join("state", "file"), []byte("state"), 0o600))

		volumeRoot, components, err := windowsStateManifestPathComponents("state")
		assert.ErrorIs(t, err, os.ErrInvalid)
		assert.Empty(t, volumeRoot)
		assert.Nil(t, components)

		files, err := scanStateManifestRoot("state")
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: invalid source root", err.Error())
	})

	t.Run("missing expected root info", func(t *testing.T) {
		stable, err := openWindowsStateManifestRoot(t.TempDir(), nil)
		require.Error(t, err)
		assert.Nil(t, stable)
		assert.Equal(t, "state manifest: invalid source root", err.Error())
	})

	t.Run("unmounted volume", func(t *testing.T) {
		expected := coverageLstat(t, t.TempDir())
		stable, err := openWindowsStateManifestRoot(coverageUnusedDriveRoot(t)+"state", expected)
		require.Error(t, err)
		assert.Nil(t, stable)
		assert.Equal(t, "state manifest: source root scan failed", err.Error())
	})

	t.Run("missing component", func(t *testing.T) {
		dir := t.TempDir()
		stable, err := openWindowsStateManifestRoot(filepath.Join(dir, "missing"), coverageLstat(t, dir))
		require.Error(t, err)
		assert.Nil(t, stable)
		assert.Equal(t, "state manifest: source root scan failed", err.Error())
	})

	t.Run("opened root is not the expected directory", func(t *testing.T) {
		root := t.TempDir()
		other := t.TempDir()
		stable, err := openWindowsStateManifestRoot(root, coverageLstat(t, other))
		require.Error(t, err)
		assert.Nil(t, stable)
		assert.Equal(t, "state manifest: source root changed during scan", err.Error())
	})
}

func TestWindowsScanner_PathComponentBoundaries(t *testing.T) {
	_, _, err := windowsStateManifestPathComponents(`\\?\UNC\server`)
	assert.ErrorIs(t, err, os.ErrInvalid)

	volumeRoot, components, err := windowsStateManifestPathComponents(`C:\`)
	require.NoError(t, err)
	assert.Equal(t, `C:\`, volumeRoot)
	assert.Nil(t, components)

	assert.False(t, windowsStateManifestPathWithinRoot("", `C:\state`))
	assert.False(t, windowsStateManifestPathWithinRoot(`C:\state`, ""))
}

func TestWindowsScanner_RootCloseReportsFirstHandleError(t *testing.T) {
	handle, err := os.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, handle.Close())

	root := &windowsStateManifestRoot{root: handle, handles: []*os.File{handle}}
	err = root.Close()
	assert.ErrorIs(t, err, os.ErrClosed)
	assert.Nil(t, root.handles)
	assert.Nil(t, root.root)
}

func TestWindowsScanner_OpenHandleFailures(t *testing.T) {
	file, err := openWindowsStateManifestHandle("bad\x00path")
	require.Error(t, err)
	assert.Nil(t, file)

	file, err = openWindowsStateManifestHandle(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	assert.Nil(t, file)
}

func TestWindowsScanner_DirectoryScanFailures(t *testing.T) {
	t.Run("handle is not a directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		require.NoError(t, os.WriteFile(path, []byte("state"), 0o600))
		handle, err := os.Open(path)
		require.NoError(t, err)
		defer handle.Close()

		var files []StateManifestFile
		err = scanWindowsStateManifestDirectory(handle, path, "", path, &files)
		require.Error(t, err)
		assert.Equal(t, "state manifest: source root scan failed", err.Error())
		assert.Empty(t, files)
	})

	// The scanner below is driven with inconsistent final paths to exercise
	// the guards that protect against a root that moved after it was opened.
	scanDir := func(t *testing.T, relativeRoot, rootFinalPath string) error {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte("state"), 0o600))
		handle, err := openWindowsStateManifestHandle(dir)
		require.NoError(t, err)
		defer handle.Close()
		dirFinalPath, err := windowsStateManifestFinalPath(handle)
		require.NoError(t, err)
		if rootFinalPath == "" {
			rootFinalPath = dirFinalPath
		}
		var files []StateManifestFile
		err = scanWindowsStateManifestDirectory(handle, dirFinalPath, relativeRoot, rootFinalPath, &files)
		assert.Empty(t, files)
		return err
	}

	t.Run("relative root cannot be resolved", func(t *testing.T) {
		err := scanDir(t, "", "relative-root")
		require.Error(t, err)
		assert.Equal(t, "state manifest: source path resolution failed", err.Error())
	})

	t.Run("relative path leaves the manifest grammar", func(t *testing.T) {
		err := scanDir(t, "..", "")
		require.Error(t, err)
		assert.Equal(t, "state manifest: invalid file path", err.Error())
	})

	t.Run("entry escapes the scanned root", func(t *testing.T) {
		other, err := openWindowsStateManifestHandle(t.TempDir())
		require.NoError(t, err)
		otherFinalPath, err := windowsStateManifestFinalPath(other)
		require.NoError(t, other.Close())
		require.NoError(t, err)

		err = scanDir(t, "sub", otherFinalPath)
		require.Error(t, err)
		assert.Equal(t, "state manifest: source entry escaped root", err.Error())
	})

	t.Run("locked nested file cannot be opened", func(t *testing.T) {
		root := t.TempDir()
		nested := filepath.Join(root, "nested")
		require.NoError(t, os.Mkdir(nested, 0o700))
		locked := filepath.Join(nested, "state.json")
		require.NoError(t, os.WriteFile(locked, []byte("state"), 0o600))
		faultBlockRead(t, locked)

		files, err := scanStateManifestRoot(root)
		require.Error(t, err)
		assert.Nil(t, files)
		assert.Equal(t, "state manifest: source root scan failed", err.Error())
	})
}

func TestWindowsScanner_HashFileFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	other := filepath.Join(dir, "other.json")
	require.NoError(t, os.WriteFile(path, []byte("state"), 0o600))
	require.NoError(t, os.WriteFile(other, []byte("other"), 0o600))
	info := coverageLstat(t, path)

	size, digest, err := hashWindowsStateManifestFile(nil, info)
	require.Error(t, err)
	assert.Zero(t, size)
	assert.Empty(t, digest)
	assert.Equal(t, "state manifest: file changed during scan", err.Error())

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()
	_, _, err = hashWindowsStateManifestFile(handle, coverageLstat(t, other))
	require.Error(t, err)
	assert.Equal(t, "state manifest: file changed during scan", err.Error())

	writeOnly, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer writeOnly.Close()
	_, _, err = hashWindowsStateManifestFile(writeOnly, info)
	require.Error(t, err)
	assert.Equal(t, "state manifest: file read failed", err.Error())
}

func TestWindowsScanner_FinalPathFailures(t *testing.T) {
	finalPath, err := windowsStateManifestFinalPath(nil)
	assert.ErrorIs(t, err, os.ErrInvalid)
	assert.Empty(t, finalPath)

	handle, err := os.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, handle.Close())
	finalPath, err = windowsStateManifestFinalPath(handle)
	require.Error(t, err)
	assert.Empty(t, finalPath)
}

// A root whose final path exceeds the initial buffer forces the scanner to
// grow its GetFinalPathNameByHandle buffer for every nested component.
func TestWindowsScanner_ScansRootBeyondInitialFinalPathBuffer(t *testing.T) {
	root := t.TempDir()
	for i := range 5 {
		root = filepath.Join(root, strings.Repeat(string(rune('a'+i)), 60))
	}
	require.NoError(t, os.MkdirAll(root, 0o700))
	content := []byte("deep state")
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), content, 0o600))

	handle, err := openWindowsStateManifestHandle(`\\?\` + root)
	require.NoError(t, err)
	finalPath, err := windowsStateManifestFinalPath(handle)
	require.NoError(t, handle.Close())
	require.NoError(t, err)
	assert.Greater(t, len(finalPath), windowsStateManifestFinalPathInitialSize)
	assert.True(t, strings.HasSuffix(strings.ToLower(finalPath), strings.ToLower(filepath.Base(root))))

	files, err := scanStateManifestRoot(root)
	require.NoError(t, err)
	sum := sha256.Sum256(content)
	assert.Equal(t, []StateManifestFile{{Path: "state.json", Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}}, files)
}
