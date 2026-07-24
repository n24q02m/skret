package auth

import (
	"os"
	"os/exec"
)

// Export goos for testing so we can hit the different OS branches in OpenBrowser
var SetGoos = func(mock func() string) func() {
	orig := goos
	goos = mock
	return func() { goos = orig }
}

// SetStartCommand for testing so we can intercept OpenBrowser's cmd.Start
// call: it lets tests inspect the built *exec.Cmd (binary + args) without
// ever launching a real browser process.
var SetStartCommand = func(mock func(cmd *exec.Cmd) error) func() {
	orig := startCommand
	startCommand = mock
	return func() { startCommand = orig }
}

// SetStdinStat for testing so we can mock os.Stdin.Stat calls
var SetStdinStat = func(mock func() (os.FileInfo, error)) func() {
	orig := stdinStat
	stdinStat = mock
	return func() { stdinStat = orig }
}
