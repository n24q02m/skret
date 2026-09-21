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
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	return nil
}

func resolveUser(value string) (int, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, 0, fail(ErrChild)
	}
	if uid, err := strconv.Atoi(parts[0]); err == nil {
		gid := uid
		if len(parts) == 2 {
			gid, err = strconv.Atoi(parts[1])
			if err != nil || gid < 0 {
				return 0, 0, fail(ErrChild)
			}
		}
		if uid < 0 {
			return 0, 0, fail(ErrChild)
		}
		return uid, gid, nil
	}
	account, err := user.Lookup(parts[0])
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	gid := account.Gid
	if len(parts) == 2 {
		gid = parts[1]
	}
	group, err := strconv.Atoi(gid)
	if err != nil {
		return 0, 0, fail(ErrChild)
	}
	return uid, group, nil
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
