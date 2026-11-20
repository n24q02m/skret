package local_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider/local"
)

// unresolvableRelPath returns a relative path that filepath.Abs cannot
// resolve on this platform. On Windows that is a name containing a NUL byte,
// which the Win32 path API rejects. Elsewhere the process working directory
// is removed (and made unsearchable) so it can no longer be determined.
func unresolvableRelPath(t *testing.T) string {
	t.Helper()
	rel := "secrets.yaml"
	if runtime.GOOS == "windows" {
		rel = "secrets\x00.yaml"
	} else {
		gone := filepath.Join(t.TempDir(), "gone")
		require.NoError(t, os.Mkdir(gone, 0o700))
		t.Chdir(gone)
		require.NoError(t, os.Chmod(gone, 0))
		require.NoError(t, os.Remove(gone))
	}
	_, err := filepath.Abs(rel)
	require.Error(t, err, "precondition: %q must not resolve to an absolute path", rel)
	return rel
}

// New refuses a secrets file path or audit_log path it cannot make absolute,
// naming the offending field and wrapping the resolution error.
func TestNewRejectsUnresolvablePaths(t *testing.T) {
	absFile := filepath.Join(t.TempDir(), "secrets.yaml")
	rel := unresolvableRelPath(t)
	_, absErr := filepath.Abs(rel)

	p, err := local.New(&config.ResolvedConfig{File: rel})
	assert.Nil(t, p)
	require.ErrorContains(t, err, fmt.Sprintf("local: resolve path %q: ", rel))
	assert.EqualError(t, errors.Unwrap(err), absErr.Error())

	p, err = local.New(&config.ResolvedConfig{File: absFile, AuditLog: rel})
	assert.Nil(t, p)
	require.ErrorContains(t, err, fmt.Sprintf("local: resolve audit path %q: ", rel))
	assert.EqualError(t, errors.Unwrap(err), absErr.Error())
}

// AppendAuditEntry reports a trail directory it cannot create instead of
// failing later on the open.
func TestAppendAuditEntryReportsUncreatableDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "trails")
	if runtime.GOOS == "windows" {
		// A regular file stands where a parent directory must be.
		blocker := filepath.Join(base, "blocker")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		dir = filepath.Join(blocker, "trails")
	} else {
		// A dangling symlink holds the directory name: the trail does not
		// exist (so there is nothing to rotate), yet mkdir cannot create it.
		require.NoError(t, os.Symlink(filepath.Join(base, "missing"), dir))
	}

	err := local.AppendAuditEntry(filepath.Join(dir, local.AuditFileName), local.AuditEntry{
		Op:       "set",
		KeyNames: []string{"API_KEY"},
	})
	require.ErrorContains(t, err, fmt.Sprintf("audit: create dir %q: ", dir))
	var pathErr *fs.PathError
	require.ErrorAs(t, err, &pathErr)
	assert.Equal(t, "mkdir", pathErr.Op)
}
