//go:build !windows && !linux

package exec

import (
	"math"

	"golang.org/x/sys/unix"
)

// terminalProcessGroup returns the foreground process group of the terminal
// open on fd (tcgetpgrp).
func terminalProcessGroup(fd int) (int, error) {
	// TIOCGPGRP stores a 4-byte C int, which IoctlGetInt reads into a zeroed
	// Go int: exact on little-endian systems, but on a 64-bit big-endian one
	// the value lands in the upper half. A process group ID is positive and
	// fits in 32 bits, so a larger result can only be that shifted form.
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if uint64(pgrp) > math.MaxUint32 {
		pgrp = int(uint64(pgrp) >> 32)
	}
	return pgrp, err
}
