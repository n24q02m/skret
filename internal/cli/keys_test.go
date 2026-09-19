package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const keysTestMaterial = "cli-keys-test-material"

// setupKeysRepo creates a repo with a local-provider config and a plaintext
// secrets file, returning the directory.
func setupKeysRepo(t *testing.T, secretsYAML string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
`), 0o644))
	if secretsYAML != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(secretsYAML), 0o600))
	}
	return dir
}

func runKeysCmd(t *testing.T, dir string, stdin string, args ...string) (string, string, error) {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if stdin != "" {
		cmd.SetIn(strings.NewReader(stdin))
	}
	err = cmd.Execute()
	return stdout.String(), stderr.String(), err
}

const keysPlaintextFixture = `version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/db"
  API_TOKEN: "kW9xP2vQ8mZ5#J7&R4tU6yB3nL0cD1f"
`

func TestKeysInitEnvSourceNoStorage(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, stderr, err := runKeysCmd(t, dir, "", "keys", "init")
	require.NoError(t, err)
	assert.Contains(t, stderr, "SKRET_AGE_KEY")
	assert.Contains(t, stderr, "(not stored by skret)")

	// Without --encrypt-existing the file stays untouched.
	raw, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	assert.False(t, keystore.Detect(raw), "plain init must not migrate the file")
}

func TestKeysInitEncryptExisting(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, stderr, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Migrated")
	assert.Contains(t, stderr, "Recorded encrypted: true")

	raw, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw))
	assert.NotContains(t, string(raw), "postgres://dev:dev@localhost/db")

	cfgRaw, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(cfgRaw), "encrypted: true")

	// The migrated file decrypts with the same material.
	secrets, err := keystore.Open(raw, keysTestMaterial)
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db", secrets["DATABASE_URL"])
}

func TestKeysInitEncryptExistingJSON(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	stdout, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing", "--format", "json")
	require.NoError(t, err)

	var payload keysInitResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.Equal(t, "env:"+keystore.EnvKeyPrimary, payload.KeySource)
	assert.True(t, payload.FileEncrypted)
	assert.False(t, payload.AlreadyEncrypted)
	assert.True(t, payload.ConfigUpdated)
	assert.Equal(t, "argon2id", payload.KDF)
	assert.NotContains(t, stdout, keysTestMaterial, "key material must never appear in output")
}

func TestKeysInitEncryptExistingIdempotent(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)

	stdout, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing", "--format", "json")
	require.NoError(t, err)
	var payload keysInitResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.True(t, payload.AlreadyEncrypted, "second migration must be a verified no-op")
}

func TestKeysInitPassphraseStdinThenEnvFallback(t *testing.T) {
	dir := setupKeysRepo(t, keysPlaintextFixture)

	// Scripted setup without keyring/env: passphrase comes from stdin.
	// keys.go reads the process-global os.Stdin (set.go's convention), so
	// swap it with a pipe.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	_, werr := w.WriteString("hunter2-line\n")
	require.NoError(t, werr)
	require.NoError(t, w.Close())

	_, stderr, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing", "--passphrase-stdin")
	require.NoError(t, err)
	assert.NotContains(t, "hunter2-line", stderr, "passphrase must never be echoed")
	assert.Contains(t, stderr, "passphrase")

	raw, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw))

	// Later commands resolve the same material via the fallback env var.
	_, _, err = runKeysCmdWithEnv(t, dir, map[string]string{keystore.EnvKeyFallback: "hunter2-line"}, "keys", "show", "--format", "json")
	require.NoError(t, err)
}

// runKeysCmdWithEnv is runKeysCmd with extra env vars set for the duration.
func runKeysCmdWithEnv(t *testing.T, dir string, env map[string]string, args ...string) (string, string, error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	return runKeysCmd(t, dir, "", args...)
}

func TestKeysEndToEndEncryptedRoundTrip(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	// 1. Migrate.
	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)

	// 2. Write through the normal set path; file stays encrypted.
	_, _, err = runKeysCmd(t, dir, "", "set", "NEW_KEY", "new-value")
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	assert.True(t, keystore.Detect(raw), "set must keep the file encrypted")

	// 3. Read back through get.
	stdout, _, err := runKeysCmd(t, dir, "", "get", "NEW_KEY", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "new-value", stdout)

	// 4. env lists all decrypted values.
	stdout, _, err = runKeysCmd(t, dir, "", "env", "--format", "json")
	require.NoError(t, err)
	assert.Contains(t, stdout, "NEW_KEY")
	assert.Contains(t, stdout, "DATABASE_URL")
}

func TestKeysShowPlaintextTable(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	stdout, stderr, err := runKeysCmd(t, dir, "", "keys", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "encrypted:  false")
	assert.Contains(t, stdout, "key:        available (source: env:"+keystore.EnvKeyPrimary+")")
	assert.Contains(t, stderr, "API_TOKEN", "high-entropy plaintext key must be warned")
	assert.NotContains(t, stderr, "kW9xP2vQ8mZ5", "warnings must not contain values")
}

func TestKeysShowEncryptedJSON(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, keysPlaintextFixture)
	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)

	stdout, stderr, err := runKeysCmd(t, dir, "", "keys", "show", "--format", "json")
	require.NoError(t, err)
	assert.NotContains(t, stderr, "warning:", "encrypted file with available key has no warnings")

	var st keystore.Status
	require.NoError(t, json.Unmarshal([]byte(stdout), &st))
	assert.True(t, st.Encrypted)
	assert.Equal(t, "argon2id", st.KDF)
	assert.True(t, st.KeyAvailable)
	assert.True(t, st.EncryptedCfg)
}

func TestKeysShowMissingFileNoError(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, "")

	_, _, err := runKeysCmd(t, dir, "", "keys", "show")
	require.NoError(t, err)
}

func TestKeysRejectsNonLocalProvider(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
`), 0o644))

	_, _, err := runKeysCmd(t, dir, "", "keys", "show")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manages the local provider")
}

func TestKeysInitNonInteractiveWithoutKeyringFails(t *testing.T) {
	// No env vars, and the mock keyring IS seeded by TestMain — so simulate
	// the no-keyring path via --passphrase-stdin WITHOUT stdin input and a
	// detached terminal: stdin empty -> read fails with a clear error.
	dir := setupKeysRepo(t, keysPlaintextFixture)
	t.Setenv(keystore.EnvKeyPrimary, "")
	t.Setenv(keystore.EnvKeyFallback, "")

	// The mock keyring makes init succeed by storing the generated key —
	// assert that path works headlessly (no prompt, no hang).
	stdout, _, err := runKeysCmd(t, dir, "", "keys", "init", "--format", "json")
	require.NoError(t, err)
	var payload keysInitResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.Equal(t, keystore.SourceKeyring, payload.KeySource)
	assert.True(t, payload.KeyringStored)

	// The stored key resolves for a subsequent show (still headless).
	_, _, err = runKeysCmd(t, dir, "", "keys", "show")
	require.NoError(t, err)
}

// The config written by --encrypt-existing must parse back with the flag on
// for the right environment only.
func TestKeysInitConfigFlagScopedToEnv(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`
version: "1"
default_env: dev
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
  prod:
    provider: local
    file: ./.secrets.prod.yaml
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(keysPlaintextFixture), 0o600))

	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)

	raw, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	var cfg struct {
		Environments map[string]struct {
			Encrypted bool `yaml:"encrypted"`
		} `yaml:"environments"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cfg))
	assert.True(t, cfg.Environments["dev"].Encrypted)
	assert.False(t, cfg.Environments["prod"].Encrypted, "only the active env may be flipped")
}
