package syncer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func coverageManifestFixture(t *testing.T) (root string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, now time.Time) {
	t.Helper()
	var err error
	root = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte("state"), 0o600))
	publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now = time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	return
}

func TestStateManifest_CanonicalAliasesRejectNilAndPreserveAuthorityBytes(t *testing.T) {
	root, publicKey, privateKey, now := coverageManifestFixture(t)
	manifest, err := BuildStateManifest(root, "operator", "hub", "nonce-canonical", now.Add(time.Minute), privateKey, now)
	require.NoError(t, err)

	canonical, err := manifest.CanonicalSigningBytes()
	require.NoError(t, err)
	alias, err := manifest.CanonicalBytes()
	require.NoError(t, err)
	wrapper, err := CanonicalStateManifestBytes(manifest)
	require.NoError(t, err)
	assert.Equal(t, canonical, alias)
	assert.Equal(t, canonical, wrapper)
	require.NoError(t, VerifyStateManifest(manifest, root, "operator", "hub", publicKey, now))

	var missing *StateManifest
	_, err = missing.CanonicalSigningBytes()
	require.ErrorContains(t, err, "missing manifest")
	_, err = missing.CanonicalBytes()
	require.ErrorContains(t, err, "missing manifest")
	_, err = CanonicalStateManifestBytes(nil)
	require.ErrorContains(t, err, "missing manifest")
}

func TestStateManifest_CanonicalValidationRejectsMalformedAuthorityAndRows(t *testing.T) {
	root := t.TempDir()
	canonicalRoot, err := canonicalStateManifestRootPath(filepath.Clean(root))
	require.NoError(t, err)
	now := time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC)
	valid := func() *StateManifest {
		return &StateManifest{
			Version:    StateManifestVersion,
			Role:       "operator",
			Audience:   "hub",
			SourceRoot: canonicalRoot,
			Files: []StateManifestFile{{
				Path:   "state.json",
				Size:   5,
				SHA256: strings.Repeat("a", 64),
			}},
			Nonce:     "nonce",
			ExpiresAt: now.Add(time.Minute),
		}
	}

	tests := []struct {
		name   string
		mutate func(*StateManifest)
	}{
		{name: "unsupported version", mutate: func(value *StateManifest) { value.Version++ }},
		{name: "invalid role encoding", mutate: func(value *StateManifest) { value.Role = string([]byte{0xff}) }},
		{name: "nul audience", mutate: func(value *StateManifest) { value.Audience = "hub\x00" }},
		{name: "invalid source root", mutate: func(value *StateManifest) { value.SourceRoot = "relative/root" }},
		{name: "zero expiry", mutate: func(value *StateManifest) { value.ExpiresAt = time.Time{} }},
		{name: "empty file set", mutate: func(value *StateManifest) { value.Files = nil }},
		{name: "empty file path", mutate: func(value *StateManifest) { value.Files[0].Path = "" }},
		{name: "absolute file path", mutate: func(value *StateManifest) { value.Files[0].Path = "/outside" }},
		{name: "dot file path", mutate: func(value *StateManifest) { value.Files[0].Path = "./state.json" }},
		{name: "backslash file path", mutate: func(value *StateManifest) { value.Files[0].Path = `nested\\state.json` }},
		{name: "negative file size", mutate: func(value *StateManifest) { value.Files[0].Size = -1 }},
		{name: "uppercase digest", mutate: func(value *StateManifest) { value.Files[0].SHA256 = strings.Repeat("A", 64) }},
		{name: "invalid digest encoding", mutate: func(value *StateManifest) { value.Files[0].SHA256 = strings.Repeat("g", 64) }},
		{name: "nul nonce", mutate: func(value *StateManifest) { value.Nonce = "nonce\x00" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := valid()
			test.mutate(manifest)
			_, err := manifest.CanonicalSigningBytes()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "state.json")
		})
	}
}

func TestStateManifest_BuildRejectsFileRootsAndInvalidUTF8Inputs(t *testing.T) {
	root, _, privateKey, now := coverageManifestFixture(t)
	fileRoot := filepath.Join(root, "state.json")

	tests := []struct {
		name     string
		root     string
		role     string
		audience string
		nonce    string
	}{
		{name: "file root", root: fileRoot, role: "operator", audience: "hub", nonce: "nonce"},
		{name: "nul root", root: root + "\x00", role: "operator", audience: "hub", nonce: "nonce"},
		{name: "invalid role", root: root, role: string([]byte{0xff}), audience: "hub", nonce: "nonce"},
		{name: "invalid audience", root: root, role: "operator", audience: "hub\x00", nonce: "nonce"},
		{name: "invalid nonce", root: root, role: "operator", audience: "hub", nonce: string([]byte{0xff})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildStateManifest(test.root, test.role, test.audience, test.nonce, now.Add(time.Minute), privateKey, now)
			require.Error(t, err)
		})
	}
}

func TestStateManifest_HashAndDirectoryRevalidationRejectUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state")
	require.NoError(t, os.WriteFile(statePath, []byte("state"), 0o600))
	regularInfo, err := os.Lstat(statePath)
	require.NoError(t, err)

	t.Run("missing expected identity", func(t *testing.T) {
		_, _, err := hashStateManifestFile(statePath, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file changed during scan")
	})
	t.Run("directory expected identity", func(t *testing.T) {
		dirPath := filepath.Join(root, "directory")
		require.NoError(t, os.Mkdir(dirPath, 0o700))
		dirInfo, statErr := os.Lstat(dirPath)
		require.NoError(t, statErr)
		_, _, err := hashStateManifestFile(dirPath, dirInfo)
		require.Error(t, err)
	})
	t.Run("missing file read", func(t *testing.T) {
		_, _, err := hashStateManifestFile(filepath.Join(root, "missing"), regularInfo)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file read failed")
	})
	t.Run("symlink expected identity", func(t *testing.T) {
		linkPath := filepath.Join(root, "link")
		if err := os.Symlink(statePath, linkPath); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		linkInfo, statErr := os.Lstat(linkPath)
		require.NoError(t, statErr)
		_, _, err := hashStateManifestFile(linkPath, linkInfo)
		require.Error(t, err)
	})

	t.Run("nil directory expectation", func(t *testing.T) {
		err := revalidateStateManifestDirectories(map[string]os.FileInfo{root: nil})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directories changed")
	})
	t.Run("missing directory", func(t *testing.T) {
		err := revalidateStateManifestDirectories(map[string]os.FileInfo{filepath.Join(root, "missing-dir"): regularInfo})
		require.Error(t, err)
	})
	t.Run("regular path is not a directory", func(t *testing.T) {
		err := revalidateStateManifestDirectories(map[string]os.FileInfo{statePath: regularInfo})
		require.Error(t, err)
	})
	t.Run("symlink directory is unsafe", func(t *testing.T) {
		linkPath := filepath.Join(root, "directory-link")
		if err := os.Symlink(root, linkPath); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		linkInfo, statErr := os.Lstat(linkPath)
		require.NoError(t, statErr)
		err := revalidateStateManifestDirectories(map[string]os.FileInfo{linkPath: linkInfo})
		require.Error(t, err)
	})
}

func TestAtomicWriteCleansFailureArtifactsAndRenamesAtomically(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "state.json")
	require.NoError(t, atomicWrite(target, root, ".state-", func(file *os.File) error {
		_, err := file.WriteString("state")
		return err
	}))
	assert.Equal(t, "state", string(mustReadFile(t, target)))

	err := atomicWrite(filepath.Join(root, "failed.json"), root, ".failed-", func(*os.File) error {
		return errors.New("synthetic write failure")
	})
	require.ErrorContains(t, err, "write")
	assert.NotContains(t, strings.Join(migrationTempFiles(t, root), ","), ".failed-")

	err = atomicWrite(filepath.Join(root, "rename-target", "state.json"), root, ".rename-", func(file *os.File) error {
		_, writeErr := file.WriteString("state")
		return writeErr
	})
	require.ErrorContains(t, err, "rename")
}
