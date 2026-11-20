package local_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
)

// withNoFileGrowth runs fn while the process may not grow any regular file
// (RLIMIT_FSIZE = 0), so the next write to a file returns EFBIG. The Go
// runtime ignores SIGXFSZ, so the write fails instead of killing the test.
// The limit is process-wide: callers must not run in parallel.
func withNoFileGrowth(t *testing.T, fn func()) {
	t.Helper()
	var orig syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &orig))
	limited := orig
	limited.Cur = 0
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited))
	defer func() { require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &orig)) }()
	fn()
}

// A secrets file whose new content cannot be written (disk quota, size
// limit) keeps its previous content: save fails on the temp file, removes
// it, and never renames a truncated file over the real one.
func TestSetWriteFailureKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "dev.yaml")
	p, err := local.New(&config.ResolvedConfig{EnvName: "dev", Provider: "local", File: file})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	require.NoError(t, p.Set(context.Background(), "API_KEY", "v1", provider.SecretMeta{}))
	before, err := os.ReadFile(file)
	require.NoError(t, err)

	withNoFileGrowth(t, func() {
		err = p.Set(context.Background(), "API_KEY", "v2", provider.SecretMeta{})
	})

	require.ErrorContains(t, err, "local: write temp")
	require.ErrorIs(t, err, syscall.EFBIG)
	assert.NotContains(t, err.Error(), "v2", "the error must not echo the secret value")
	after, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	leftovers, err := filepath.Glob(filepath.Join(dir, ".skret-local-*"))
	require.NoError(t, err)
	assert.Empty(t, leftovers, "the failed temp file must be removed")
}

// An audit entry that cannot be appended fails the call with the trail
// path, so the caller learns the trail is incomplete.
func TestAppendAuditEntryWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), local.AuditFileName)

	var err error
	withNoFileGrowth(t, func() {
		err = local.AppendAuditEntry(path, local.AuditEntry{Op: local.AuditOpSet, KeyNames: []string{"API_KEY"}})
	})

	require.ErrorContains(t, err, "audit: append")
	require.ErrorIs(t, err, syscall.EFBIG)
	info, statErr := os.Stat(path)
	require.NoError(t, statErr)
	assert.Zero(t, info.Size(), "no partial entry may be left in the trail")
}
