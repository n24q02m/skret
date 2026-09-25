//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package secretlaunch

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func configureProcessGroup(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func applyChildUser(command *exec.Cmd, value string) error {
	if value == "" || value == "current" {
		return nil
	}
	uid, gid, err := resolveUser(value)
	if err != nil {
		return fail(ErrChild)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	return nil
}

func resolveUser(value string) (uint32, uint32, error) {
	// bolt: Replace strings.Split with strings.Cut to avoid allocating a slice since we only need up to 2 segments (UID and optional GID).
	uidStr, gidStr, found := strings.Cut(value, ":")
	if found && strings.Contains(gidStr, ":") {
		return 0, 0, fail(ErrChild)
	}
	if value == "" {
		return 0, 0, fail(ErrChild)
	}

	if uid, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
		gid := uid
		if found {
			gid, err = strconv.ParseUint(gidStr, 10, 32)
			if err != nil {
				return 0, 0, fail(ErrChild)
			}
		}
		return uint32(uid), uint32(gid), nil
	}
	account, err := user.Lookup(uidStr)
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	gidValue := account.Gid
	if found {
		gidValue = gidStr
	}
	gid, err := strconv.ParseUint(gidValue, 10, 32)
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	return uint32(uid), uint32(gid), nil
}

func signalProcessTree(process *os.Process, signal os.Signal) error {
	if process == nil {
		return fail(ErrChild)
	}
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return process.Signal(signal)
	}
	if err := syscall.Kill(-process.Pid, sig); err == nil {
		return nil
	}
	return process.Signal(signal)
}

func killProcessTree(process *os.Process) error {
	if process == nil {
		return fail(ErrChild)
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return process.Kill()
}

func disableDumps() error {
	limit := &syscall.Rlimit{Cur: 0, Max: 0}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, limit); err != nil {
		return fail(ErrChild)
	}
	return disablePlatformDumps()
}
