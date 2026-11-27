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

func TestShouldRelay(t *testing.T) {
	saved := keyboardSignalsReachChild
	t.Cleanup(func() { keyboardSignalsReachChild = saved })

	keyboardSignalsReachChild = func() bool { return true }
	assert.True(t, shouldRelay(syscall.SIGTERM))
	assert.True(t, shouldRelay(syscall.SIGUSR1))
	for _, sig := range []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP} {
		assert.False(t, shouldRelay(sig), "%v", sig)
	}

	keyboardSignalsReachChild = func() bool { return false }
	assert.True(t, shouldRelay(syscall.SIGINT))
}
