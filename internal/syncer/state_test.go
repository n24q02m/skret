package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFakeHome redirects os.UserHomeDir() to t.TempDir() for the duration of
// a test so SaveSyncState / LoadSyncState write to an isolated location.
func withFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	} else {
		t.Setenv("HOME", dir)
	}
	return dir
}

func TestStatePathFor_SanitizesID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		wantPart string
	}{
		{"slash", "n24q02m/skret", "n24q02m-skret"},
		{"colon", "github:owner:repo", "github-owner-repo"},
		{"space", "my file path", "my_file_path"},
		{"backslash", `windows\path`, "windows-path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeHome(t)
			path, err := StatePathFor("github", tt.id)
			require.NoError(t, err)
			assert.Contains(t, path, tt.wantPart)
			assert.True(t, strings.HasSuffix(path, ".json"))
		})
	}
}

func TestLoadSyncState_FirstRun_ReturnsEmpty(t *testing.T) {
	withFakeHome(t)
	state, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Equal(t, "github", state.Target)
	assert.Equal(t, "owner/repo", state.ID)
	assert.NotNil(t, state.Hashes)
	assert.Empty(t, state.Hashes)
}

func TestSaveAndLoadSyncState_Roundtrip(t *testing.T) {
	home := withFakeHome(t)
	state, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)

	state.Update([]*provider.Secret{
		{Key: "/myapp/prod/DB_URL", Value: "postgres://example"},
		{Key: "/myapp/prod/API_KEY", Value: "sk-abc"},
	})
	require.NoError(t, SaveSyncState(state))

	// Verify file written under fake home with 0600 permissions on POSIX
	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, home))

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	loaded, err := LoadSyncState("github", "owner/repo")
	require.NoError(t, err)
	assert.Len(t, loaded.Hashes, 2)
	assert.Equal(t, hashSecret("postgres://example"), loaded.Hashes["/myapp/prod/DB_URL"])
	assert.Equal(t, hashSecret("sk-abc"), loaded.Hashes["/myapp/prod/API_KEY"])
	assert.False(t, loaded.Updated.IsZero())
}

func TestFilterUnchanged_NewSecretIncluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"},
		{Key: "K2", Value: "v2"},
	}
	out := state.FilterUnchanged(secrets)
	assert.Equal(t, secrets, out)
}

func TestFilterUnchanged_UnchangedExcluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{
		"K1": hashSecret("v1"),
	}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "v1"}, // unchanged → excluded
		{Key: "K2", Value: "v2"}, // new → included
	}
	out := state.FilterUnchanged(secrets)
	require.Len(t, out, 1)
	assert.Equal(t, "K2", out[0].Key)
}

func TestFilterUnchanged_ChangedIncluded(t *testing.T) {
	state := &SyncState{Hashes: map[string]string{
		"K1": hashSecret("old-value"),
	}}
	secrets := []*provider.Secret{
		{Key: "K1", Value: "new-value"}, // hash differs → included
	}
	out := state.FilterUnchanged(secrets)
	require.Len(t, out, 1)
	assert.Equal(t, "K1", out[0].Key)
}

func TestUpdate_PopulatesHashes(t *testing.T) {
	state := &SyncState{}
	state.Update([]*provider.Secret{
		{Key: "K", Value: "v"},
	})
	require.NotNil(t, state.Hashes)
	assert.Equal(t, hashSecret("v"), state.Hashes["K"])
}

func TestSaveSyncState_CreatesDirWithSecureMode(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{}}
	require.NoError(t, SaveSyncState(state))

	dir := filepath.Join(home, ".skret", "sync-state")
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestLoadSyncState_CorruptFile_ReturnsError(t *testing.T) {
	home := withFakeHome(t)
	dir := filepath.Join(home, ".skret", "sync-state")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "github-owner-repo.json")
	require.NoError(t, os.WriteFile(path, []byte("not json {"), 0o600))

	_, err := LoadSyncState("github", "owner/repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse sync state")
}

func TestHashSecret_Stable(t *testing.T) {
	a := hashSecret("hello")
	b := hashSecret("hello")
	c := hashSecret("hello!")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 64) // sha256 hex = 64 chars
}

func TestStatePathFor_NoHomeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
		t.Setenv("HOMEDRIVE", "")
		t.Setenv("HOMEPATH", "")
	} else {
		t.Setenv("HOME", "")
	}
	_, err := StatePathFor("github", "owner/repo")
	if err == nil {
		t.Skip("UserHomeDir did not error in this environment; nothing to assert")
	}
	assert.Contains(t, err.Error(), "user home dir")
}

func TestSaveSyncState_UpdatedTimeStamp(t *testing.T) {
	withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{"K": hashSecret("v")}}
	require.NoError(t, SaveSyncState(state))
	first := state.Updated
	assert.False(t, first.IsZero())

	// Roundtrip preserves Updated; second SaveSyncState advances it.
	require.NoError(t, SaveSyncState(state))
	assert.False(t, state.Updated.Before(first))
}

func TestSaveSyncState_Atomic(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{Target: "github", ID: "owner/repo", Hashes: map[string]string{"K": hashSecret("v")}}
	require.NoError(t, SaveSyncState(state))

	path, err := StatePathFor("github", "owner/repo")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, home))

	// .tmp file should not survive a successful SaveSyncState.
	_, statErr := os.Stat(path + ".tmp")
	assert.True(t, errors.Is(statErr, os.ErrNotExist))
}

// TestStatePathFor_BlocksPathTraversal verifies neither target nor id can
// escape the ~/.skret/sync-state directory. This guards a HIGH severity
// path-traversal class of bugs where untrusted input (target/id) could
// otherwise be written outside the intended directory.
func TestStatePathFor_BlocksPathTraversal(t *testing.T) {
	cases := []struct {
		name   string
		target string
		id     string
	}{
		{"dotdot in id", "github", "../../etc/passwd"},
		{"dotdot in target", "../../etc", "owner-repo"},
		{"slash separator", "gh", "a/b/c/d"},
		{"backslash separator", "gh", `a\b\c`},
		{"null byte", "gh", "id\x00x"},
		{"only dots", "gh", ".."},
		{"empty id", "gh", ""},
		{"single dot", "gh", "."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := withFakeHome(t)
			path, err := StatePathFor(tc.target, tc.id)
			require.NoError(t, err)
			expectedDir := filepath.Join(home, ".skret", "sync-state")
			assert.True(t, strings.HasPrefix(path, expectedDir+string(filepath.Separator)),
				"path %q must live inside %q", path, expectedDir)
			rel, err := filepath.Rel(expectedDir, path)
			require.NoError(t, err)
			assert.NotContains(t, rel, "..", "rel %q must not contain ..", rel)
			assert.NotContains(t, rel, string(filepath.Separator),
				"sanitized filename must not include separators (got %q)", rel)
		})
	}
}

// TestSaveSyncState_PathTraversal verifies that even with a malicious id the
// file is written inside the sync-state directory and the attacker cannot land
// a file in a sibling directory.
func TestSaveSyncState_PathTraversal(t *testing.T) {
	home := withFakeHome(t)
	state := &SyncState{
		Target: "../../../evil-target",
		ID:     "../../etc/passwd",
		Hashes: map[string]string{"K": hashSecret("v")},
	}
	require.NoError(t, SaveSyncState(state))

	_, err := os.Stat(filepath.Join(home, ".skret", "evil-target"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "no escape above sync-state")

	stateDir := filepath.Join(home, ".skret", "sync-state")
	entries, err := os.ReadDir(stateDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasSuffix(entries[0].Name(), ".json"))
	assert.NotContains(t, entries[0].Name(), "..")
}
