//go:build !windows

package syncer

import (
	"fmt"
	"os"
)

// durableReplace atomically installs source at target and persists the
// containing directory entry. The directory barrier is required after the
// rename: syncing the temporary file alone does not make the new name survive
// a host crash.
func durableReplace(source, target, dir string) error {
	if err := os.Rename(source, target); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync parent directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close parent directory: %w", closeErr)
	}
	return nil
}
