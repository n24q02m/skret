//go:build linux

package secretlaunch

import "syscall"

const prSetDumpable = 4

func disablePlatformDumps() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fail(ErrChild)
	}
	return nil
}
