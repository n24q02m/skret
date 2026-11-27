package exec

import "time"

// SetFilteredWaitDelay shortens RunFiltered's output drain bound for a test
// and returns a func that restores it.
func SetFilteredWaitDelay(d time.Duration) (restore func()) {
	saved := filteredWaitDelay
	filteredWaitDelay = d
	return func() { filteredWaitDelay = saved }
}
