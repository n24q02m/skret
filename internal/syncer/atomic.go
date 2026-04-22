package syncer

import (
	"fmt"
	"os"
)

// atomicWrite creates a temp file in the target's directory, calls writeFunc to
// write content, sets permissions to 0600, and atomically renames to target.
// If any step fails, cleanup is performed and an error is returned.
func atomicWrite(target string, dir string, prefix string, writeFunc func(f *os.File) error) error {
	tmp, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if err := writeFunc(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write: %w", err)
	}

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
