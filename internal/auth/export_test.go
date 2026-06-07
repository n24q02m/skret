package auth

import "os"

// Export goos for testing so we can hit the different OS branches in OpenBrowser
var SetGoos = func(mock func() string) func() {
	orig := goos
	goos = mock
	return func() { goos = orig }
}

// SetStdinStat for testing so we can mock os.Stdin.Stat calls
var SetStdinStat = func(mock func() (os.FileInfo, error)) func() {
	orig := stdinStat
	stdinStat = mock
	return func() { stdinStat = orig }
}
