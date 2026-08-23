package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateManifest_SignsDeterministicSortedMetadataOnly(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "nested"), 0o700))
	const secretValue = "migration-secret-value"
	require.NoError(t, os.WriteFile(filepath.Join(root, "z.txt"), []byte(secretValue), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("metadata-only"), 0o600))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	expiresAt := now.Add(5 * time.Minute)

	first, err := BuildStateManifest(root, "operator", "hub", "nonce-1", expiresAt, privateKey, now)
	require.NoError(t, err)
	second, err := BuildStateManifest(root, "operator", "hub", "nonce-1", expiresAt, privateKey, now)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, second)

	assert.Equal(t, StateManifestVersion, first.Version)
	assert.Equal(t, filepath.Clean(root), first.SourceRoot)
	require.Len(t, first.Files, 2)
	assert.Equal(t, filepath.ToSlash(filepath.Join("nested", "a.txt")), first.Files[0].Path)
	assert.Equal(t, "z.txt", first.Files[1].Path)
	assert.Equal(t, first.Files, second.Files)
	assert.Equal(t, first.Signature, second.Signature, "Ed25519 signatures must be deterministic for identical canonical bytes")
	require.NoError(t, VerifyStateManifest(first, root, "operator", "hub", publicKey, now.Add(time.Minute)))

	canonical, err := first.CanonicalSigningBytes()
	require.NoError(t, err)
	canonicalAgain, err := first.CanonicalSigningBytes()
	require.NoError(t, err)
	assert.Equal(t, canonical, canonicalAgain)
	assert.True(t, json.Valid(canonical))
	assert.Contains(t, string(canonical), `"sha256"`)
	assert.Contains(t, string(canonical), `"size"`)
	assert.NotContains(t, string(canonical), secretValue, "canonical manifest must never contain file contents")

	originalSignature := append([]byte(nil), first.Signature...)
	first.Signature[0] ^= 0xff
	canonicalAfterSignatureChange, err := first.CanonicalSigningBytes()
	require.NoError(t, err)
	assert.Equal(t, canonical, canonicalAfterSignatureChange, "detached signature must be excluded from signed bytes")
	first.Signature = originalSignature
}

func TestVerifyStateManifest_AcceptsHappyPathAndDetectsFileSetOrContentChanges(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	const original = "original-secret-value"
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(original), 0o600))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-2", now.Add(5*time.Minute), privateKey, now)
	require.NoError(t, err)
	require.NoError(t, VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now.Add(time.Minute)))

	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte("changed-secret-value"), 0o600))
	err = VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now.Add(time.Minute))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), original)
	assert.NotContains(t, err.Error(), "changed-secret-value")

	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(original), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "added.json"), []byte("another-secret"), 0o600))
	err = VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now.Add(time.Minute))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "another-secret")

	require.NoError(t, os.Remove(filepath.Join(root, "added.json")))
	require.NoError(t, os.Remove(filepath.Join(root, "state.json")))
	err = VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now.Add(time.Minute))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), original)
}

func TestBuildStateManifest_RejectsInvalidFieldsAndLifetime(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	const secretValue = "invalid-field-secret"
	require.NoError(t, os.WriteFile(filepath.Join(root, "state"), []byte(secretValue), 0o600))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		root      string
		role      string
		audience  string
		nonce     string
		expiresAt time.Time
		signer    ed25519.PrivateKey
	}{
		{name: "missing root", root: "", role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), signer: privateKey},
		{name: "missing role", root: root, role: "", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), signer: privateKey},
		{name: "missing audience", root: root, role: "operator", audience: "", nonce: "nonce", expiresAt: now.Add(time.Minute), signer: privateKey},
		{name: "missing nonce", root: root, role: "operator", audience: "hub", nonce: "", expiresAt: now.Add(time.Minute), signer: privateKey},
		{name: "zero expiry", root: root, role: "operator", audience: "hub", nonce: "nonce", expiresAt: time.Time{}, signer: privateKey},
		{name: "expired", root: root, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now, signer: privateKey},
		{name: "over maximum ttl", root: root, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(MaxStateManifestTTL + time.Nanosecond), signer: privateKey},
		{name: "invalid signer", root: root, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), signer: ed25519.PrivateKey("short")},
		{name: "missing root on disk", root: filepath.Join(root, "missing"), role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), signer: privateKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildStateManifest(tc.root, tc.role, tc.audience, tc.nonce, tc.expiresAt, tc.signer, now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secretValue)
		})
	}
}

func TestVerifyStateManifest_RejectsTamperingScopeAndMalformedRows(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "nested"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "one"), []byte("one"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "two"), []byte("two"), 0o600))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	build := func(t *testing.T) *StateManifest {
		t.Helper()
		manifest, buildErr := BuildStateManifest(root, "operator", "hub", "nonce-3", now.Add(5*time.Minute), privateKey, now)
		require.NoError(t, buildErr)
		return manifest
	}

	tests := []struct {
		name   string
		mutate func(*StateManifest)
		root   string
		role   string
		aud    string
		now    time.Time
	}{
		{name: "bad signature", mutate: func(m *StateManifest) { m.Signature[0] ^= 1 }, root: root, role: "operator", aud: "hub", now: now},
		{name: "tampered size", mutate: func(m *StateManifest) { m.Files[0].Size++ }, root: root, role: "operator", aud: "hub", now: now},
		{name: "tampered digest", mutate: func(m *StateManifest) { m.Files[0].SHA256 = strings.Repeat("a", 64) }, root: root, role: "operator", aud: "hub", now: now},
		{name: "wrong role", mutate: func(m *StateManifest) {}, root: root, role: "other-role", aud: "hub", now: now},
		{name: "wrong audience", mutate: func(m *StateManifest) {}, root: root, role: "operator", aud: "other-audience", now: now},
		{name: "wrong root", mutate: func(m *StateManifest) {}, root: t.TempDir(), role: "operator", aud: "hub", now: now},
		{name: "expired", mutate: func(m *StateManifest) { m.ExpiresAt = now }, root: root, role: "operator", aud: "hub", now: now},
		{name: "over maximum ttl", mutate: func(m *StateManifest) { m.ExpiresAt = now.Add(MaxStateManifestTTL + time.Nanosecond) }, root: root, role: "operator", aud: "hub", now: now},
		{name: "root traversal", mutate: func(m *StateManifest) { m.SourceRoot = root + string(filepath.Separator) + "." }, root: root, role: "operator", aud: "hub", now: now},
		{name: "path traversal", mutate: func(m *StateManifest) { m.Files[0].Path = "../outside" }, root: root, role: "operator", aud: "hub", now: now},
		{name: "backslash path", mutate: func(m *StateManifest) { m.Files[0].Path = `nested\\two` }, root: root, role: "operator", aud: "hub", now: now},
		{name: "duplicate path", mutate: func(m *StateManifest) { m.Files[1].Path = m.Files[0].Path }, root: root, role: "operator", aud: "hub", now: now},
		{name: "unsorted rows", mutate: func(m *StateManifest) { m.Files[0], m.Files[1] = m.Files[1], m.Files[0] }, root: root, role: "operator", aud: "hub", now: now},
		{name: "invalid digest", mutate: func(m *StateManifest) { m.Files[0].SHA256 = "not-a-digest" }, root: root, role: "operator", aud: "hub", now: now},
		{name: "negative size", mutate: func(m *StateManifest) { m.Files[0].Size = -1 }, root: root, role: "operator", aud: "hub", now: now},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := build(t)
			tc.mutate(manifest)
			verifyErr := VerifyStateManifest(manifest, tc.root, tc.role, tc.aud, publicKey, tc.now)
			require.Error(t, verifyErr)
			assert.NotContains(t, verifyErr.Error(), "one")
			assert.NotContains(t, verifyErr.Error(), "two")
		})
	}

	manifest := build(t)
	assert.Error(t, VerifyStateManifest(manifest, root, "operator", "hub", ed25519.PublicKey("short"), now))
	manifest = build(t)
	manifest.ExpiresAt = now.Add(time.Minute)
	assert.Error(t, VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now.Add(2*time.Minute)))
}

func TestBuildStateManifest_RejectsEmptyRootsAndSymlinkEntries(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	empty := t.TempDir()
	_, err = BuildStateManifest(empty, "operator", "hub", "nonce-4", now.Add(time.Minute), privateKey, now)
	require.Error(t, err)

	t.Run("symlink file", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "link")
		require.NoError(t, os.WriteFile(target, []byte("target"), 0o600))
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		_, err := BuildStateManifest(root, "operator", "hub", "nonce-4", now.Add(time.Minute), privateKey, now)
		require.Error(t, err)
	})

	t.Run("symlink directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "link")
		require.NoError(t, os.MkdirAll(target, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(target, "state"), []byte("state"), 0o600))
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("directory symlink creation unavailable: %v", err)
		}
		_, err := BuildStateManifest(root, "operator", "hub", "nonce-4", now.Add(time.Minute), privateKey, now)
		require.Error(t, err)
	})
}
func TestStateManifestUnsafeMode_RejectsSymlinkAndIrregular(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "symlink", mode: os.ModeSymlink},
		{name: "irregular", mode: os.ModeIrregular},
		{name: "combined", mode: os.ModeSymlink | os.ModeIrregular},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, unsafeStateManifestMode(tc.mode))
		})
	}
	assert.False(t, unsafeStateManifestMode(0o600))
	assert.False(t, unsafeStateManifestMode(os.ModeDir|0o700))
}

func TestHashStateManifestFile_RejectsReplacementIdentity(t *testing.T) {
	root := t.TempDir()
	originalPath := filepath.Join(root, "state.original")
	replacementPath := filepath.Join(root, "state")
	require.NoError(t, os.WriteFile(originalPath, []byte("original-secret"), 0o600))
	require.NoError(t, os.WriteFile(replacementPath, []byte("replacement-secret"), 0o600))
	expected, err := os.Lstat(originalPath)
	require.NoError(t, err)

	_, _, err = hashStateManifestFile(replacementPath, expected)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "original-secret")
	assert.NotContains(t, err.Error(), "replacement-secret")
}

func TestRevalidateStateManifestDirectories_RejectsReplacementIdentity(t *testing.T) {
	root := t.TempDir()
	originalPath := filepath.Join(root, "directory.original")
	replacementPath := filepath.Join(root, "directory")
	require.NoError(t, os.Mkdir(originalPath, 0o700))
	require.NoError(t, os.Mkdir(replacementPath, 0o700))
	expected, err := os.Lstat(originalPath)
	require.NoError(t, err)

	err = revalidateStateManifestDirectories(map[string]os.FileInfo{
		replacementPath: expected,
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), originalPath)
	assert.NotContains(t, err.Error(), replacementPath)
}