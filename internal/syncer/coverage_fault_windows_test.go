//go:build windows

package syncer

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// everyoneSID is the well-known Everyone group; a deny ACE for it applies to
// the test process even when it owns the object.
const everyoneSID = "*S-1-1-0"

func faultOpenHandle(t *testing.T, path string, share uint32) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
}

// faultBlockRemoval keeps path readable but makes os.Remove(path) fail: an
// open handle without FILE_SHARE_DELETE causes a sharing violation.
func faultBlockRemoval(t *testing.T, path string) {
	t.Helper()
	faultOpenHandle(t, path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

// faultBlockCreate makes creating files or links inside dir fail while
// existing entries stay readable.
func faultBlockCreate(t *testing.T, dir string) {
	t.Helper()
	faultIcacls(t, dir, everyoneSID+":(WD,AD)")
}

// faultBlockRead keeps path visible to Lstat but makes reading it fail with a
// sharing violation.
func faultBlockRead(t *testing.T, path string) {
	t.Helper()
	faultOpenHandle(t, path, 0)
}

// faultLstatErrorPath returns a path under dir whose Lstat fails with an
// error other than ErrNotExist.
func faultLstatErrorPath(t *testing.T, dir string) string {
	t.Helper()
	return filepath.Join(dir, "invalid<name")
}

// faultBlockChmod makes os.Chmod(path) fail by denying FILE_WRITE_ATTRIBUTES.
func faultBlockChmod(t *testing.T, path string) {
	t.Helper()
	faultIcacls(t, path, everyoneSID+":(WA)")
}

func faultIcacls(t *testing.T, path, ace string) {
	t.Helper()
	out, err := exec.Command("icacls", path, "/deny", ace).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command("icacls", path, "/remove:d", everyoneSID).Run() })
}

// faultDirLink creates link as a directory junction pointing at target.
func faultDirLink(t *testing.T, link, target string) {
	t.Helper()
	createWindowsJunction(t, link, target)
}
