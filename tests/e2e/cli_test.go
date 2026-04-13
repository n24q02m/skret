package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var skretBinary string

func TestMain(m *testing.M) {
	tmp, _ := os.MkdirTemp("", "skret-e2e")
	skretBinary = filepath.Join(tmp, "skret.exe")
	cmd := exec.Command("go", "build", "-o", skretBinary, "../../cmd/skret")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func TestE2E_InitGetSetDeleteListEnv(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	// Write local secrets file first
	_ = os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte("version: \"1\"\nsecrets:\n  ORIGINAL: \"original_val\""), 0o600)

	// Init
	run(t, dir, "init", "--provider=local", "--file=./.secrets.dev.yaml")

	// Get
	out := run(t, dir, "get", "ORIGINAL")
	assert.Equal(t, "original_val", strings.TrimSpace(out))

	// Set
	run(t, dir, "set", "NEW_KEY", "new_val")

	// Get new key
	out = run(t, dir, "get", "NEW_KEY")
	assert.Equal(t, "new_val", strings.TrimSpace(out))

	// List
	out = run(t, dir, "list")
	assert.Contains(t, out, "NEW_KEY")
	assert.Contains(t, out, "ORIGINAL")

	// Env
	out = run(t, dir, "env")
	assert.Contains(t, out, "ORIGINAL=")
	assert.Contains(t, out, "NEW_KEY=")

	// Delete
	run(t, dir, "delete", "ORIGINAL", "--confirm")
	out = run(t, dir, "list")
	assert.NotContains(t, out, "ORIGINAL")
}

func TestE2E_Version(t *testing.T) {
	out, err := exec.Command(skretBinary, "--version").CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(out), "skret")
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(skretBinary, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "skret %v failed: %s", args, string(out))
	return string(out)
}
