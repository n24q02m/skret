//go:build windows

package syncer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// everyoneSID is the well-known Everyone group; a deny ACE for it applies to
// the test process even when it owns the object.
const everyoneSID = "*S-1-1-0"

// faultRequireEffective skips the test when the injected fault does not hold
// for this process. An elevated token (the hosted Windows runner) can bypass
// deny ACEs and read locks, so a fault that the probe can still get through
// would only test the runner's privileges, not the code under test.
func faultRequireEffective(t *testing.T, fault string, probe func() error) {
	t.Helper()
	if probe() == nil {
		t.Skipf("fault injection ineffective for this process: %s still succeeds", fault)
	}
}

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
	faultRequireEffective(t, "creating a file in "+dir, func() error {
		probe := filepath.Join(dir, ".fault-probe")
		f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
		_ = os.Remove(probe)
		return nil
	})
	faultRequireEffective(t, "creating a directory in "+dir, func() error {
		probe := filepath.Join(dir, ".fault-probe-dir")
		if err := os.Mkdir(probe, 0o700); err != nil {
			return err
		}
		_ = os.Remove(probe)
		return nil
	})
}

// faultBlockRead keeps path visible to Lstat but makes reading it fail with a
// sharing violation.
func faultBlockRead(t *testing.T, path string) {
	t.Helper()
	faultOpenHandle(t, path, 0)
	faultRequireEffective(t, "reading "+path, func() error {
		_, err := os.ReadFile(path)
		return err
	})
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
	faultRequireEffective(t, "chmod of "+path, func() error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		return os.Chmod(path, info.Mode().Perm()) // same mode: no state change if it succeeds
	})
}

// faultRequireNoWriteDAC skips when this process can still open path for
// WRITE_DAC despite a deny ACE.
func faultRequireNoWriteDAC(t *testing.T, path string) {
	t.Helper()
	faultRequireEffective(t, "opening "+path+" for WRITE_DAC", func() error {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(name, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return err
		}
		return windows.CloseHandle(h)
	})
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
