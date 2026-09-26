package local_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const encTestMaterial = "provider-test-material"

// encTestEnv seeds SKRET_AGE_KEY so provider key resolution never reaches
// the OS keyring (deterministic, no platform probe).
func encTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv(keystore.EnvKeyPrimary, encTestMaterial)
}

func encTestConfig(t *testing.T, file string, encrypted bool) *config.ResolvedConfig {
	t.Helper()
	return &config.ResolvedConfig{
		EnvName:   "dev",
		Provider:  "local",
		File:      file,
		Encrypted: encrypted,
	}
}

func TestLocalEncryptedRoundTrip(t *testing.T) {
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()

	// Fresh write under an encrypted config produces an envelope.
	require.NoError(t, p.Set(ctx, "DATABASE_URL", "postgres://u:p@h/db", provider.SecretMeta{}))
	require.NoError(t, p.Set(ctx, "API_KEY", "k-123", provider.SecretMeta{}))

	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw), "file must be an encrypted envelope after Set")
	assert.NotContains(t, string(raw), "postgres://u:p@h/db", "plaintext must not leak to disk")
	info, err := os.Stat(file)
	require.NoError(t, err)
	assertMode0600(t, info.Mode())

	// A new provider instance reads it back transparently.
	p2, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p2.Close()

	secret, err := p2.Get(ctx, "DATABASE_URL")
	require.NoError(t, err)
	assert.Equal(t, "postgres://u:p@h/db", secret.Value)

	names, err := p2.ListNames(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"API_KEY", "DATABASE_URL"}, names)

	// Delete persists the encrypted state without the deleted key.
	require.NoError(t, p2.Delete(ctx, "API_KEY"))
	p3, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p3.Close()
	_, err = p3.Get(ctx, "API_KEY")
	assert.Error(t, err, "deleted key must stay deleted across reload")
	secret, err = p3.Get(ctx, "DATABASE_URL")
	require.NoError(t, err)
	assert.Equal(t, "postgres://u:p@h/db", secret.Value)
}

func TestLocalPlaintextDefaultUnchanged(t *testing.T) {
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	p, err := local.New(encTestConfig(t, file, false))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	require.NoError(t, p.Set(ctx, "A", "b", provider.SecretMeta{}))

	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.False(t, keystore.Detect(raw), "default mode must stay plaintext")
	assert.Contains(t, string(raw), "version: \"1\"")
	assert.Contains(t, string(raw), "A: b")
}

func TestLocalAutoDetectDecryptsReads(t *testing.T) {
	// An encrypted file on disk decrypts even when the config flag is off
	// (e.g. pre-migration reads, or a peer without the flag enabled).
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	sealed, err := keystore.Seal(map[string]string{"EXISTING": "value-1"}, encTestMaterial)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, sealed, 0o600))

	p, err := local.New(encTestConfig(t, file, false))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	secret, err := p.Get(ctx, "EXISTING")
	require.NoError(t, err)
	assert.Equal(t, "value-1", secret.Value)

	// Encryption is sticky: a write to a decrypted-on-disk file re-seals,
	// even without the config flag.
	require.NoError(t, p.Set(ctx, "NEW", "value-2", provider.SecretMeta{}))
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw), "save on an encrypted file must stay encrypted")

	p2, err := local.New(encTestConfig(t, file, false))
	require.NoError(t, err)
	defer p2.Close()
	for key, want := range map[string]string{"EXISTING": "value-1", "NEW": "value-2"} {
		secret, err := p2.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, want, secret.Value)
	}
}

func TestLocalEncryptedCfgConvertsPlaintextOnWrite(t *testing.T) {
	// `encrypted: true` with a still-plaintext file: reads work untouched;
	// the next write converts the file to an envelope (migration path).
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")
	require.NoError(t, os.WriteFile(file, []byte("version: \"1\"\nsecrets:\n  OLD: value-0\n"), 0o600))

	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	secret, err := p.Get(ctx, "OLD")
	require.NoError(t, err)
	assert.Equal(t, "value-0", secret.Value)

	require.NoError(t, p.Set(ctx, "NEW", "value-1", provider.SecretMeta{}))

	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw), "first write under encrypted config must seal the file")
}

func TestLocalEncryptedMissingKeyFailsWithRemediation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")
	sealed, err := keystore.Seal(map[string]string{"A": "b"}, encTestMaterial)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, sealed, 0o600))

	// No env material; empty injected keyring; stdin is not a terminal in
	// tests, so the interactive prompt must not fire.
	t.Setenv(keystore.EnvKeyPrimary, "")
	t.Setenv(keystore.EnvKeyFallback, "")

	_, err = local.New(encTestConfig(t, file, false))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key material available")
	var coder interface{ ExitCode() int }
	require.True(t, errors.As(err, &coder))
	assert.Equal(t, 4, coder.ExitCode(), "missing key must map to exit code 4")
}

// Fingerprint must remain content-based over PLAINTEXT values even for
// encrypted files (watch-mode change detection semantics unchanged).
func TestLocalEncryptedFingerprintStable(t *testing.T) {
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	require.NoError(t, p.Set(ctx, "K", "v", provider.SecretMeta{}))
	fp1, err := p.Fingerprint(ctx, "")
	require.NoError(t, err)

	p2, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p2.Close()
	fp2, err := p2.Fingerprint(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, fp1, fp2, "same plaintext content must fingerprint identically across instances")

	require.NoError(t, p2.Set(ctx, "K", "v2", provider.SecretMeta{}))
	fp3, err := p2.Fingerprint(ctx, "")
	require.NoError(t, err)
	assert.NotEqual(t, fp1, fp3, "changed content must change the fingerprint")
}

func TestLocalLegacyEnvelopeReadsAndWritesStayLegacy(t *testing.T) {
	// A legacy skret-encrypted-v1 envelope on disk reads transparently and
	// keeps its format on write: migration to the age format is an explicit
	// `skret keys init --encrypt-existing` step, not an implicit rewrite.
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	sealed, err := keystore.SealLegacyWithMeta(map[string]string{"EXISTING": "value-1"},
		map[string]string{"EXISTING": expires.Format(time.RFC3339)}, encTestMaterial, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, sealed, 0o600))

	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	ctx := context.Background()
	secret, err := p.Get(ctx, "EXISTING")
	require.NoError(t, err)
	assert.Equal(t, "value-1", secret.Value)
	assert.Equal(t, expires, secret.Meta.ExpiresAt, "per-key expiry meta must survive the legacy read")

	// Write under an encrypted config: legacy stays legacy.
	require.NoError(t, p.Set(ctx, "NEW", "value-2", provider.SecretMeta{}))
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.True(t, keystore.DetectLegacy(raw), "legacy envelope must keep its format until migrated")
	assert.False(t, keystore.Detect(raw))
	assert.NotContains(t, string(raw), "value-2", "plaintext must not leak to disk")

	p2, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p2.Close()
	for key, want := range map[string]string{"EXISTING": "value-1", "NEW": "value-2"} {
		secret, err := p2.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, want, secret.Value)
	}
}

func TestLocalKeyCacheSwitchesWhenFormatMigratesOnDisk(t *testing.T) {
	// The key-material cache is per format: legacy files resolve raw
	// material, age files resolve an identity. When the on-disk format
	// changes under a live provider (another terminal migrated it), a
	// reload must re-resolve instead of failing the age open with legacy
	// material.
	encTestEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	sealed, err := keystore.SealLegacyWithMeta(map[string]string{"EXISTING": "value-1"}, nil, encTestMaterial, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, sealed, 0o600))

	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	// External migration to the age format with the same env material.
	migrated, err := keystore.Seal(map[string]string{"EXISTING": "value-1"}, encTestMaterial)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, migrated, 0o600))

	ctx := context.Background()
	_, err = p.Fingerprint(ctx, "")
	require.NoError(t, err, "reload after on-disk migration must re-resolve the key cache")
	secret, err := p.Get(ctx, "EXISTING")
	require.NoError(t, err)
	assert.Equal(t, "value-1", secret.Value)
}

func TestLocalNewAuditPathAndDirectoryFileError(t *testing.T) {
	encTestEnv(t)
	dir := t.TempDir()

	// A configured audit path is honored (absolute path stored, not probed).
	file := filepath.Join(dir, ".secrets.dev.yaml")
	cfg := encTestConfig(t, file, false)
	cfg.AuditLog = filepath.Join(dir, "custom-audit.log")
	p, err := local.New(cfg)
	require.NoError(t, err)
	defer p.Close()
	require.NoError(t, p.Set(context.Background(), "K", "v", provider.SecretMeta{}))
	_, err = os.Stat(cfg.AuditLog)
	require.NoError(t, err, "audit trail must be created at the configured path")

	// A directory at the file path is a raw read error, not NotExist.
	p2, err := local.New(encTestConfig(t, dir, false))
	assert.Error(t, err)
	assert.Nil(t, p2)
}

// TestLocalEncryptedLoadFailureBranches drives New into each encrypted-load
// failure mode through the public surface: a standard age envelope opened
// with the wrong identity, a legacy envelope opened with wrong material,
// and a legacy envelope with no material at all. Each must fail provider
// construction (never hand back a partial provider) and carry the
// remediation-oriented message callers act on.
func TestLocalEncryptedLoadFailureBranches(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	// Two distinct X25519 identities: an envelope sealed for idA cannot be
	// opened by idB — a fast, deterministic wrong-key failure (no scrypt).
	idA, err := keystore.GenerateIdentity()
	require.NoError(t, err)
	idB, err := keystore.GenerateIdentity()
	require.NoError(t, err)

	sealAge := func(material string) {
		t.Helper()
		sealed, err := keystore.Seal(map[string]string{"EXISTING": "value-1"}, material)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(file, sealed, 0o600))
	}
	sealLegacy := func(material string) {
		t.Helper()
		sealed, err := keystore.SealLegacyWithMeta(map[string]string{"EXISTING": "value-1"}, nil, material, nil)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(file, sealed, 0o600))
	}

	tests := []struct {
		name    string
		seal    func(string)
		sealMat string
		env     string
		wantErr string
	}{
		{
			name:    "age envelope wrong identity",
			seal:    sealAge,
			sealMat: idA,
			env:     idB,
			wantErr: "decrypt failed",
		},
		{
			name:    "age envelope missing material",
			seal:    sealAge,
			sealMat: encTestMaterial,
			env:     "",
			wantErr: "no key material available",
		},
		{
			name:    "legacy envelope wrong material",
			seal:    sealLegacy,
			sealMat: encTestMaterial,
			env:     "other-legacy-material",
			wantErr: "decrypt failed",
		},
		{
			name:    "legacy envelope missing material",
			seal:    sealLegacy,
			sealMat: encTestMaterial,
			env:     "",
			wantErr: "no key material available",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.seal(tt.sealMat)
			t.Setenv(keystore.EnvKeyPrimary, tt.env)
			t.Setenv(keystore.EnvKeyFallback, "")

			p, err := local.New(encTestConfig(t, file, false))
			require.Error(t, err)
			assert.Nil(t, p, "a failed load must not return a provider")
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestLocalEncryptedCfgWriteWithoutKeyFails: an `encrypted: true` config is
// a write-side intent; the first write must resolve a key and seal. With no
// resolvable material the write fails loudly (exit-4 contract) and the file
// stays untouched plaintext — never a silent plaintext write under an
// encrypted config.
func TestLocalEncryptedCfgWriteWithoutKeyFails(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".secrets.dev.yaml")

	// A still-plaintext file loads without a key; the key is only needed
	// when save() seals.
	p, err := local.New(encTestConfig(t, file, true))
	require.NoError(t, err)
	defer p.Close()

	t.Setenv(keystore.EnvKeyPrimary, "")
	t.Setenv(keystore.EnvKeyFallback, "")

	err = p.Set(context.Background(), "K", "v", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key material available")

	_, err = os.Stat(file)
	assert.True(t, os.IsNotExist(err), "failed write must not leave a file behind")
}

func assertMode0600(t *testing.T, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits; os.Stat reports synthetic
		// modes regardless of os.Chmod. The 0600 contract holds on unix.
		return
	}
	assert.Equal(t, os.FileMode(0o600), mode.Perm(), "encrypted file must be written 0600")
}
