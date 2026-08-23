//go:build windows

package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildStateManifest_RejectsWindowsJunctionRootsAndEntries(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	root := t.TempDir()
	target := filepath.Join(root, "target")
	junction := filepath.Join(root, "junction")
	require.NoError(t, os.MkdirAll(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "state"), []byte("state"), 0o600))
	createWindowsJunction(t, junction, target)

	_, err = BuildStateManifest(junction, "operator", "hub", "nonce", now.Add(time.Minute), privateKey, now)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), target)

	_, err = BuildStateManifest(root, "operator", "hub", "nonce", now.Add(time.Minute), privateKey, now)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), target)
}

func createWindowsJunction(t *testing.T, junction, target string) {
	t.Helper()
	command := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Skipf("junction creation unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
}
