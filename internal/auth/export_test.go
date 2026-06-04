package auth

import "os"

// Export goos for testing so we can hit the different OS branches in OpenBrowser
var SetGoos = func(mock func() string) func() {
	orig := goos
	goos = mock
	return func() { goos = orig }
}

// SetStdin allows mocking os.Stdin in tests.
func SetStdin(f *os.File) func() {
	orig := stdin
	stdin = f
	return func() { stdin = orig }
}
