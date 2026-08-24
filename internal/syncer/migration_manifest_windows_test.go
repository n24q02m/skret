//go:build windows

package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildStateManifest_RejectsWindowsJunctionRootsAndEntries(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	root := t.TempDir()
	target := filepath.Join(root, "target")
	junction := filepath.Join(root, "junction")
	require.NoError(t, os.MkdirAll(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "state"), []byte("state"), 0o600))
	createWindowsJunction(t, junction, target)

	_, err = BuildStateManifest(junction, "operator", "hub", "nonce", now.Add(time.Minute), privateKey, now)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), target)

	_, err = BuildStateManifest(root, "operator", "hub", "nonce", now.Add(time.Minute), privateKey, now)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), target)
}

func TestWindowsFinalPathContainmentUsesCaseInsensitiveComponentBoundary(t *testing.T) {
	root := `\\?\C:\State`
	assert.True(t, windowsStateManifestPathWithinRoot(root, `\\?\c:\state\child\file`))
	assert.True(t, windowsStateManifestPathWithinRoot(root, root))
	assert.False(t, windowsStateManifestPathWithinRoot(root, `\\?\C:\State-escape\file`))
	assert.False(t, windowsStateManifestPathWithinRoot(root, `\\?\C:\State2\file`))
}

func TestWindowsStateManifestPathComponentsHandlesExtendedUNC(t *testing.T) {
	tests := []struct {
		name       string
		root       string
		volumeRoot string
		components []string
	}{
		{
			name:       "extended UNC",
			root:       `\\?\UNC\server\share\state`,
			volumeRoot: `\\?\UNC\server\share\`,
			components: []string{"state"},
		},
		{
			name:       "device UNC",
			root:       `\\.\UNC\server\share\state`,
			volumeRoot: `\\.\UNC\server\share\`,
			components: []string{"state"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			volumeRoot, components, err := windowsStateManifestPathComponents(test.root)
			require.NoError(t, err)
			assert.Equal(t, test.volumeRoot, volumeRoot)
			assert.Equal(t, test.components, components)
		})
	}
}

func TestWindowsScannerRejectsJunctionEntryBeforeEnumeration(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "outside")
	junction := filepath.Join(root, "child")
	require.NoError(t, os.MkdirAll(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "outside-state"), []byte("outside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "inside-state"), []byte("inside"), 0o600))
	createWindowsJunction(t, junction, target)

	_, err := scanStateManifestRoot(root)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), target)
}

func TestWindowsScannerUsesOpenedDirectoryHandle(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	require.NoError(t, os.MkdirAll(child, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(child, "state"), []byte("state"), 0o600))

	files, err := scanStateManifestRoot(root)
	require.NoError(t, err)
	require.Equal(t, []StateManifestFile{{
		Path:   filepath.ToSlash(filepath.Join("child", "state")),
		Size:   int64(len("state")),
		SHA256: "4ba69735ca53765ed6a709edb56c6ea236b7193a3b29a6b390c346f0f4340e4e",
	}}, files)
}

func TestWindowsOpenedDirectoryHandleDoesNotFollowPathReplacement(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	moved := filepath.Join(root, "child-moved")
	outside := filepath.Join(root, "outside")
	require.NoError(t, os.MkdirAll(child, 0o700))
	require.NoError(t, os.MkdirAll(outside, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(child, "inside-state"), []byte("inside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "outside-state"), []byte("outside"), 0o600))

	opened, err := openWindowsStateManifestHandle(child)
	require.NoError(t, err)
	defer opened.Close()
	require.NoError(t, os.Rename(child, moved))
	createWindowsJunction(t, child, outside)

	entries, err := opened.ReadDir(-1)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "inside-state", entries[0].Name())
}

func TestWindowsStableRootHandleRejectsAncestorJunctionSwap(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	movedParent := filepath.Join(base, "parent-moved")
	root := filepath.Join(parent, "state")
	require.NoError(t, os.MkdirAll(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("state"), 0o600))

	expectedRoot, err := os.Lstat(root)
	require.NoError(t, err)
	require.NoError(t, os.Rename(parent, movedParent))
	createWindowsJunction(t, parent, movedParent)

	_, err = openWindowsStateManifestRoot(root, expectedRoot)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), movedParent)
}

func createWindowsJunction(t *testing.T, junction, target string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "cmd.exe", "/d", "/c", "mklink", "/J", junction, target)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	require.NoError(t, command.Run())
	t.Cleanup(func() { _ = os.Remove(junction) })
}
