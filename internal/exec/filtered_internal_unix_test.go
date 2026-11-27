//go:build !windows

package exec

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsForegroundProcessGroup_NonTerminal(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-tty")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	assert.False(t, isForegroundProcessGroup(file), "a regular file has no foreground process group")
	assert.False(t, isForegroundProcessGroup(filepath.Join(t.TempDir(), "missing")))
}

// In the foreground the terminal already sends keyboard signals (INT, QUIT,
// HUP) to the child, so relaying them would deliver them twice; the cost is
// that the same signals sent with kill to skret's own pid are not relayed.
// TERM and the user signals are always relayed.
func TestShouldRelay(t *testing.T) {
	saved := keyboardSignalsReachChild
	t.Cleanup(func() { keyboardSignalsReachChild = saved })

	tests := []struct {
		foreground bool
		sig        os.Signal
		want       bool
	}{
		{true, syscall.SIGINT, false},
		{true, syscall.SIGQUIT, false},
		{true, syscall.SIGHUP, false},
		{true, syscall.SIGTERM, true},
		{true, syscall.SIGUSR1, true},
		{false, syscall.SIGINT, true},
		{false, syscall.SIGQUIT, true},
		{false, syscall.SIGHUP, true},
		{false, syscall.SIGTERM, true},
		{false, syscall.SIGUSR1, true},
	}
	for _, tt := range tests {
		keyboardSignalsReachChild = func() bool { return tt.foreground }
		assert.Equal(t, tt.want, shouldRelay(tt.sig), "foreground=%v signal=%v", tt.foreground, tt.sig)
	}
}
