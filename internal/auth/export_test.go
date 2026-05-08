package auth

// Export goos for testing so we can hit the different OS branches in OpenBrowser
var SetGoos = func(mock func() string) func() {
	orig := goos
	goos = mock
	return func() { goos = orig }
}
