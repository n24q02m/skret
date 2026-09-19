package local_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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

	sealed, err := keystore.Seal(map[string]string{"EXISTING": "value-1"}, encTestMaterial, nil)
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
	sealed, err := keystore.Seal(map[string]string{"A": "b"}, encTestMaterial, nil)
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

func assertMode0600(t *testing.T, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits; os.Stat reports synthetic
		// modes regardless of os.Chmod. The 0600 contract holds on unix.
		return
	}
	assert.Equal(t, os.FileMode(0o600), mode.Perm(), "encrypted file must be written 0600")
}
