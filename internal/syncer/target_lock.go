package syncer

import (
	"fmt"
	"os"
	"path/filepath"
)

// AcquireTargetLock obtains an interprocess exclusive lock for one target
// journal. The caller must hold the returned release function from state load
// through provider calls and the terminal journal save. The lock file is
// intentionally retained so a crashed process cannot leave a stale pathname;
// the OS releases the advisory lock with the file descriptor.
func AcquireTargetLock(target, id string) (func() error, error) {
	statePath, err := StatePathFor(target, id)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, fmt.Errorf("create sync lock dir: %w", err)
	}
	lockPath := statePath + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open sync target lock: %w", err)
	}
	if err := lockTargetFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock sync target: %w", err)
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		unlockErr := unlockTargetFile(file)
		closeErr := file.Close()
		if unlockErr != nil {
			return fmt.Errorf("unlock sync target: %w", unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close sync target lock: %w", closeErr)
		}
		return nil
	}
	return release, nil
}
