//go:build windows

package syncer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerRightsSID is the OWNER RIGHTS principal. A deny ACE for it removes the
// owner's implicit WRITE_DAC, which a plain Everyone deny does not.
const ownerRightsSID = "*S-1-3-4"

func TestDurableReplaceWindows_ReportsEncodingAndInstallFailures(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.tmp")
	target := filepath.Join(dir, "target.env")

	err := durableReplace("bad\x00source", target, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encode source path")

	err = durableReplace(source, "bad\x00target", dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encode target path")

	// MoveFileEx carries the read-only attribute to the installed file, so the
	// replace succeeds but reopening it for the flush barrier is refused.
	require.NoError(t, os.WriteFile(source, []byte("K=v\n"), 0o600))
	require.NoError(t, os.Chmod(source, 0o400))
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })

	err = durableReplace(source, target, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open installed file")
	assert.NoFileExists(t, source)
	assert.Equal(t, []byte("K=v\n"), mustReadFile(t, target))
}

func TestValidateMigrationPathWindows_RejectsDeviceDotComponent(t *testing.T) {
	path := `\\.\C:\state.json`
	require.Equal(t, path, filepath.Clean(path))
	require.True(t, filepath.IsAbs(path))

	err := validateMigrationPath(path)
	require.Error(t, err)
	assert.Equal(t, "state migration: path traversal rejected", err.Error())
}

func TestHardenMigrationFilePermissionsWindows_ReportsSecurityFailures(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		err := hardenMigrationFilePermissions(filepath.Join(t.TempDir(), "missing.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read owner security descriptor")
	})

	t.Run("owner cannot rewrite the DACL", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		require.NoError(t, os.WriteFile(path, []byte("state"), 0o600))
		out, err := exec.CommandContext(t.Context(), "icacls", path, "/deny", ownerRightsSID+":(WDAC)").CombinedOutput()
		require.NoError(t, err, string(out))
		faultRequireNoWriteDAC(t, path)

		err = secureMigrationFile(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "harden file permissions")
		assert.Contains(t, err.Error(), "set owner-only ACL")
		assert.Equal(t, []byte("state"), mustReadFile(t, path))
	})
}
