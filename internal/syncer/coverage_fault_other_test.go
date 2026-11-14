//go:build !windows

package syncer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func faultRequireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based fault injection is ineffective for root")
	}
}

func faultChmod(t *testing.T, path string, mode, restore os.FileMode) {
	t.Helper()
	faultRequireUnprivileged(t)
	require.NoError(t, os.Chmod(path, mode))
	t.Cleanup(func() { _ = os.Chmod(path, restore) })
}

// faultBlockRemoval makes os.Remove(path) fail by removing write permission
// from the parent directory; path itself stays readable.
func faultBlockRemoval(t *testing.T, path string) {
	t.Helper()
	faultChmod(t, filepath.Dir(path), 0o500, 0o700)
}

// faultBlockCreate makes creating files or links inside dir fail while
// existing entries stay readable.
func faultBlockCreate(t *testing.T, dir string) {
	t.Helper()
	faultChmod(t, dir, 0o500, 0o700)
}

// faultBlockRead keeps path visible to Lstat but makes reading it fail.
func faultBlockRead(t *testing.T, path string) {
	t.Helper()
	faultChmod(t, path, 0o000, 0o600)
}

// faultLstatErrorPath returns a path under dir whose Lstat fails with an
// error other than ErrNotExist (EACCES from an untraversable parent).
func faultLstatErrorPath(t *testing.T, dir string) string {
	t.Helper()
	locked := filepath.Join(dir, "locked")
	require.NoError(t, os.Mkdir(locked, 0o700))
	faultChmod(t, locked, 0o000, 0o700)
	return filepath.Join(locked, "child")
}

// faultDirLink creates link as a directory symlink pointing at target.
func faultDirLink(t *testing.T, link, target string) {
	t.Helper()
	require.NoError(t, os.Symlink(target, link))
	t.Cleanup(func() { _ = os.Remove(link) })
}
