//go:build windows

package syncer

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// durableReplace uses MoveFileEx's write-through replacement semantics and
// flushes the installed file before returning. Windows does not provide the
// POSIX directory-fsync contract; WRITE_THROUGH plus FlushFileBuffers is the
// corresponding durable replace barrier before provider I/O.
func durableReplace(source, target, _ string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return fmt.Errorf("encode source path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("encode target path: %w", err)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace: %w", err)
	}

	installed, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open installed file: %w", err)
	}
	flushErr := windows.FlushFileBuffers(windows.Handle(installed.Fd()))
	closeErr := installed.Close()
	if flushErr != nil {
		return fmt.Errorf("flush installed file: %w", flushErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close installed file: %w", closeErr)
	}
	return nil
}
