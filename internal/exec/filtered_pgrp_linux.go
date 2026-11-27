package exec

import "golang.org/x/sys/unix"

// terminalProcessGroup returns the foreground process group of the terminal
// open on fd (tcgetpgrp).
func terminalProcessGroup(fd int) (int, error) {
	pgrp, err := unix.IoctlGetUint32(fd, unix.TIOCGPGRP)
	return int(pgrp), err
}
