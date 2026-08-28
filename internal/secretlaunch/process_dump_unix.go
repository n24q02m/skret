//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package secretlaunch

func disablePlatformDumps() error { return nil }
