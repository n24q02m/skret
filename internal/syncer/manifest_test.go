package syncer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_SaltedDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := Fingerprint(salt, "s3cr3t")
	b := Fingerprint(salt, "s3cr3t")
	assert.Equal(t, a, b)                                                     // deterministic within deployment
	assert.Len(t, a, 8)                                                       // 8 hex chars
	assert.NotEqual(t, a, Fingerprint([]byte("different-salt-16"), "s3cr3t")) // salt changes fp
}

func TestBuildManifest_NoValuesLeak(t *testing.T) {
	salt := []byte("0123456789abcdef")
	secrets := []*provider.Secret{{Key: "/a/prod/DB", Value: "$ecret=val"}}
	states := map[string]*SyncState{
		"github:o/r":            {Hashes: map[string]string{"/a/prod/DB": hashSecret("$ecret=val")}}, // in-sync
		"cloudflare:worker/api": {Hashes: map[string]string{}},                                       // never synced -> missing
	}
	m := BuildManifest("/a/prod", "prod", salt, secrets, states)
	raw, _ := json.Marshal(m)
	assert.NotContains(t, string(raw), "$ecret=val") // value never serialized
	require.Len(t, m.Keys, 1)
	assert.Equal(t, "DB", m.Keys[0].Name)
	assert.Equal(t, "in-sync", m.Keys[0].Targets["github:o/r"].Status)
	assert.Equal(t, "missing", m.Keys[0].Targets["cloudflare:worker/api"].Status)
}

func TestBuildManifest_Drift(t *testing.T) {
	salt := []byte("0123456789abcdef")
	secrets := []*provider.Secret{{Key: "/a/prod/DB", Value: "$ecret=val"}}
	states := map[string]*SyncState{
		"github:o/r": {Hashes: map[string]string{"/a/prod/DB": "deadbeef-not-matching"}}, // stale hash -> drift
	}
	m := BuildManifest("/a/prod", "prod", salt, secrets, states)
	require.Len(t, m.Keys, 1)
	assert.True(t, m.Keys[0].Targets["github:o/r"].Present)
	assert.Equal(t, "drift", m.Keys[0].Targets["github:o/r"].Status)
}

func TestBuildManifest_NilState_TreatedAsMissing(t *testing.T) {
	salt := []byte("0123456789abcdef")
	secrets := []*provider.Secret{{Key: "/a/prod/DB", Value: "$ecret=val"}}
	states := map[string]*SyncState{
		"github:o/r": nil, // defensive: nil *SyncState must not panic
	}
	m := BuildManifest("/a/prod", "prod", salt, secrets, states)
	require.Len(t, m.Keys, 1)
	assert.False(t, m.Keys[0].Targets["github:o/r"].Present)
	assert.Equal(t, "missing", m.Keys[0].Targets["github:o/r"].Status)
}

func TestLoadDeploySalt_FirstRun_CreatesSaltFile(t *testing.T) {
	home := withFakeHome(t)
	salt, err := LoadDeploySalt()
	require.NoError(t, err)
	assert.Len(t, salt, 16)

	path := filepath.Join(home, ".skret", "hub-salt")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}

func TestLoadDeploySalt_Roundtrip_Deterministic(t *testing.T) {
	withFakeHome(t)
	first, err := LoadDeploySalt()
	require.NoError(t, err)

	second, err := LoadDeploySalt()
	require.NoError(t, err)

	assert.Equal(t, first, second) // second call reads the same persisted salt
}

func TestLoadDeploySalt_FilePerms(t *testing.T) {
	home := withFakeHome(t)
	_, err := LoadDeploySalt()
	require.NoError(t, err)

	if runtime.GOOS == "windows" {
		t.Skip("POSIX file perms unreliable on windows")
	}

	path := filepath.Join(home, ".skret", "hub-salt")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestLoadDeploySalt_CorruptShortFile_SelfHeals(t *testing.T) {
	home := withFakeHome(t)
	dir := filepath.Join(home, ".skret")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "hub-salt")
	require.NoError(t, os.WriteFile(path, []byte("short"), 0o600)) // < 16 bytes

	salt, err := LoadDeploySalt()
	require.NoError(t, err)
	assert.Len(t, salt, 16)

	// The regenerated salt was also persisted, not just returned in-memory.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, salt, data)

	// No leftover .tmp file from the atomic write.
	_, statErr := os.Stat(path + ".tmp")
	assert.True(t, os.IsNotExist(statErr))
}
