//go:build !windows

package exec

// SetKeyboardSignalsReachChild replaces the foreground-terminal probe for a
// test and returns a func that restores it.
func SetKeyboardSignalsReachChild(f func() bool) (restore func()) {
	saved := keyboardSignalsReachChild
	keyboardSignalsReachChild = f
	return func() { keyboardSignalsReachChild = saved }
}
