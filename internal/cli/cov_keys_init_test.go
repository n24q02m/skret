package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/keystore"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// covCPipeStdin replaces the process-global os.Stdin with a pipe pre-filled
// with input (closed for writing, so a read past it sees EOF). keys and
// bootstrap read os.Stdin directly rather than cmd.InOrStdin().
func covCPipeStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
	if input != "" {
		_, err = w.WriteString(input)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
}

// covCNoKeyMaterial clears every key source keys init consults, so the
// keyring backend alone decides the outcome.
func covCNoKeyMaterial(t *testing.T) {
	t.Helper()
	t.Setenv(keystore.EnvKeyPrimary, "")
	t.Setenv(keystore.EnvKeyFallback, "")
	resetKeyringMock(t)
	t.Cleanup(keyring.MockInit)
}

// covCGitRepo returns an empty temp dir marked as a git root, so config
// discovery stops there instead of walking into the real filesystem.
func covCGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	return dir
}

// ---------------------------------------------------------------------------
// keys init / keys show
// ---------------------------------------------------------------------------

func TestCovCKeysInit_TableReportsGeneratedThenReusedKeyring(t *testing.T) {
	covCNoKeyMaterial(t)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, stderr, err := runKeysCmd(t, dir, "", "keys", "init")
	require.NoError(t, err)
	assert.Contains(t, stderr, "generated age X25519 identity stored in OS keyring")

	stored, ok := keystore.KeyringMaterial()
	require.True(t, ok, "the generated identity must be in the keyring")
	assert.NotContains(t, stderr, stored, "key material must never be printed")

	_, stderr, err = runKeysCmd(t, dir, "", "keys", "init")
	require.NoError(t, err)
	assert.Contains(t, stderr, "existing OS keyring material reused")
	again, _ := keystore.KeyringMaterial()
	assert.Equal(t, stored, again, "a second init must reuse, not regenerate")
}

func TestCovCKeysInit_TableReportsAlreadyEncrypted(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	resetKeyringMock(t)
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)
	_, stderr, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)
	assert.Contains(t, stderr, "already age-encrypted (verified with current key material)")
	assert.NotContains(t, stderr, "Recorded encrypted: true", "config already carries the flag")
}

func TestCovCKeysInit_KeyringStoreFailureNonInteractive(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, "")
	t.Setenv(keystore.EnvKeyFallback, "")
	keyring.MockInitWithError(errors.New("no keyring backend"))
	t.Cleanup(keyring.MockInit)
	covCPipeStdin(t, "") // not a terminal: the prompt fallback must not engage
	dir := setupKeysRepo(t, keysPlaintextFixture)

	_, _, err := runKeysCmd(t, dir, "", "keys", "init")
	require.Error(t, err)
	assert.Equal(t, skret.ExitAuthError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "could not store generated key in OS keyring")
	assert.Contains(t, skret.RemediationOf(err), "--passphrase-stdin")
}

func TestCovCKeysInit_PassphraseStdinErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		code  int
		msg   string
	}{
		{"eof", "", skret.ExitAuthError, "read passphrase from stdin"},
		{"blank line", "\r\n", skret.ExitValidationError, "passphrase must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			covCNoKeyMaterial(t)
			covCPipeStdin(t, tc.input)
			dir := setupKeysRepo(t, keysPlaintextFixture)

			_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--passphrase-stdin")
			require.Error(t, err)
			assert.Equal(t, tc.code, skret.ExitCode(err))
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestCovCKeysInit_EncryptExistingReadErrorIsConfigError(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, "")
	asDir := filepath.Join(dir, "secrets-dir")
	require.NoError(t, os.MkdirAll(asDir, 0o755))

	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing", "--file", asDir)
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "keys: read")
}

func TestCovCKeysInit_MalformedPlaintextFile(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, "secrets: [unclosed\n")

	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "parse plaintext file")

	raw, rerr := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, rerr)
	assert.Equal(t, "secrets: [unclosed\n", string(raw), "a failed parse must leave the file untouched")
}

func TestCovCKeysInit_FileFlagWithoutConfig(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := covCGitRepo(t)
	file := filepath.Join(dir, "standalone.yaml")
	require.NoError(t, os.WriteFile(file, []byte(keysPlaintextFixture), 0o600))

	stdout, _, err := runKeysCmd(t, dir, "", "keys", "init", "--file", file, "--encrypt-existing", "--format", "json")
	require.NoError(t, err)
	var payload keysInitResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &payload))
	assert.True(t, payload.FileEncrypted)
	assert.False(t, payload.ConfigUpdated, "no config is in play, so nothing to record")

	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	secrets, err := keystore.Open(raw, keysTestMaterial)
	require.NoError(t, err)
	assert.Equal(t, "postgres://dev:dev@localhost/db", secrets["DATABASE_URL"])
	assert.NoFileExists(t, filepath.Join(dir, ".skret.yaml"))
}

func TestCovCKeysTarget_ResolutionErrors(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)

	t.Run("no config and no file", func(t *testing.T) {
		dir := covCGitRepo(t)
		for _, sub := range []string{"init", "show"} {
			_, _, err := runKeysCmd(t, dir, "", "keys", sub)
			require.Error(t, err, sub)
			assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err), sub)
			assert.Contains(t, err.Error(), "no .skret.yaml found and no --file given", sub)
		}
	})

	t.Run("explicit config missing", func(t *testing.T) {
		dir := covCGitRepo(t)
		_, _, err := runKeysCmd(t, dir, "", "--config", filepath.Join(dir, "absent.yaml"), "keys", "show")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "keys: load config failed")
	})

	t.Run("invalid config", func(t *testing.T) {
		dir := covCGitRepo(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("version: \"9\"\n"), 0o600))
		_, _, err := runKeysCmd(t, dir, "", "keys", "show")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "keys: load config failed")
	})

	t.Run("unknown env", func(t *testing.T) {
		dir := setupKeysRepo(t, keysPlaintextFixture)
		_, _, err := runKeysCmd(t, dir, "", "--env", "nope", "keys", "show")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "keys: resolve config failed")
	})

	t.Run("local override without file", func(t *testing.T) {
		dir := covCGitRepo(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`version: "1"
default_env: prod
environments:
  prod:
    provider: aws
    path: /myapp/prod
`), 0o600))
		_, _, err := runKeysCmd(t, dir, "", "--provider", "local", "keys", "show")
		require.Error(t, err)
		assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), `environment "prod" has no local file configured`)
	})
}

func TestCovCKeysShow_EncryptedTableAndNoKey(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	resetKeyringMock(t)
	dir := setupKeysRepo(t, keysPlaintextFixture)
	_, _, err := runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.NoError(t, err)

	stdout, _, err := runKeysCmd(t, dir, "", "keys", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "encrypted:  true")
	assert.Contains(t, stdout, "format:     "+keystore.Format)
	assert.Contains(t, stdout, "kdf:        scrypt")
	assert.Contains(t, stdout, "config:     encrypted=true")

	// Without any key source the file is still reported, never decrypted.
	covCNoKeyMaterial(t)
	stdout, _, err = runKeysCmd(t, dir, "", "keys", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "key:        not available non-interactively")
	assert.NotContains(t, stdout, "postgres://", "values must never be printed")
}

func TestCovCKeysShow_UnreadableFileIsConfigError(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	dir := setupKeysRepo(t, "")
	// The configured local file path is a directory: show must surface the
	// read failure instead of reporting a missing (unencrypted) file.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".secrets.dev.yaml"), 0o755))

	stdout, _, err := runKeysCmd(t, dir, "", "keys", "show")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "keys: read")
	assert.Empty(t, stdout)
}

func TestCovCKeysInit_ConfigRewriteFailureSurfaces(t *testing.T) {
	t.Setenv(keystore.EnvKeyPrimary, keysTestMaterial)
	resetKeyringMock(t)
	dir := setupKeysRepo(t, keysPlaintextFixture)
	cfgPath := filepath.Join(dir, ".skret.yaml")
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	// Occupy the backup slot with a non-empty directory so recording
	// `encrypted: true` cannot complete.
	require.NoError(t, os.MkdirAll(filepath.Join(cfgPath+".bak", "keep"), 0o755))

	_, _, err = runKeysCmd(t, dir, "", "keys", "init", "--encrypt-existing")
	require.Error(t, err)
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "keys: write config")

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the config must not be half-rewritten")
}

func TestCovCUpdateConfigEncryptedFlag_Errors(t *testing.T) {
	cfg := func() *config.Config {
		return &config.Config{Version: "1", Environments: map[string]config.Environment{
			"dev": {Provider: "local", File: "dev.yaml"},
		}}
	}

	err := updateConfigEncryptedFlag(cfg(), filepath.Join(t.TempDir(), ".skret.yaml"), "prod")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), `environment "prod" not found`)

	err = updateConfigEncryptedFlag(cfg(), filepath.Join(t.TempDir(), "missing.yaml"), "dev")
	require.Error(t, err)
	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "keys: re-read config")

	// The backup slot is occupied by a non-empty directory: the rewrite must
	// fail and leave the original config bytes alone.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("original"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(cfgPath+".bak", "keep"), 0o755))
	err = updateConfigEncryptedFlag(cfg(), cfgPath, "dev")
	require.Error(t, err)
	assert.Equal(t, skret.ExitGenericError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "keys: write config")
	raw, rerr := os.ReadFile(cfgPath)
	require.NoError(t, rerr)
	assert.Equal(t, "original", string(raw))
}

func TestCovCWriteFileAtomically0600_Errors(t *testing.T) {
	err := writeFileAtomically0600(filepath.Join(t.TempDir(), "no-such-dir", "f.yaml"), []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temporary config")

	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "child"), 0o755))
	err = writeFileAtomically0600(target, []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace "+target)
	entries, rerr := os.ReadDir(dir)
	require.NoError(t, rerr)
	assert.Len(t, entries, 1, "the temp file must be cleaned up after a failed rename")
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func TestCovCInit_UnknownProvider(t *testing.T) {
	dir := covCGitRepo(t)
	_, _, err := runKeysCmd(t, dir, "", "init", "--provider", "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `init: unknown provider "bogus"`)
	assert.NoFileExists(t, filepath.Join(dir, ".skret.yaml"))
}

func TestCovCInit_ConfigPathIsDirectory(t *testing.T) {
	dir := covCGitRepo(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".skret.yaml"), 0o755))
	_, _, err := runKeysCmd(t, dir, "", "init")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "init: read existing config")
}

func TestCovCInit_DryRunUnchanged(t *testing.T) {
	dir := covCGitRepo(t)
	_, _, err := runKeysCmd(t, dir, "", "init")
	require.NoError(t, err)
	before, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)

	_, stderr, err := runKeysCmd(t, dir, "", "init", "--dry-run")
	require.NoError(t, err)
	assert.Contains(t, stderr, "dry-run: ")
	assert.Contains(t, stderr, "unchanged")
	assert.NotContains(t, stderr, "would be updated")

	after, err := os.ReadFile(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestCovCInit_NoDefaultEnvKeepsProdProvider(t *testing.T) {
	dir := covCGitRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte(`version: "1"
environments:
  prod:
    provider: local
    file: ./prod.yaml
`), 0o600))

	_, _, err := runKeysCmd(t, dir, "", "init", "--region", "eu-west-1")
	require.NoError(t, err)

	cfg, err := config.Load(filepath.Join(dir, ".skret.yaml"))
	require.NoError(t, err)
	prod := cfg.Environments["prod"]
	assert.Equal(t, "local", prod.Provider, "merge must keep the existing prod provider")
	assert.Equal(t, "./prod.yaml", prod.File)
	assert.Equal(t, "eu-west-1", prod.Region)
	assert.FileExists(t, filepath.Join(dir, ".skret.yaml.bak"))
}

func TestCovCInit_GitignoreIsDirectoryWarns(t *testing.T) {
	dir := covCGitRepo(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".gitignore"), 0o755))

	_, stderr, err := runKeysCmd(t, dir, "", "init")
	require.NoError(t, err, "a .gitignore problem is a warning, not a failure")
	assert.Contains(t, stderr, "Warning: could not update .gitignore")
	assert.FileExists(t, filepath.Join(dir, ".skret.yaml"))
}

func TestCovCInit_GetwdFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot remove the current working directory")
	}
	orig, err := os.Getwd()
	require.NoError(t, err)
	gone := filepath.Join(t.TempDir(), "gone")
	require.NoError(t, os.MkdirAll(gone, 0o755))
	require.NoError(t, os.Chdir(gone))
	t.Cleanup(func() { _ = os.Chdir(orig) })
	t.Setenv("PWD", "")
	require.NoError(t, os.Remove(gone))
	if _, err := os.Getwd(); err == nil {
		t.Skip("this platform still resolves a removed working directory (darwin)")
	}

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"init"})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "init: get working directory")
}

func TestCovCWriteBackupAtomically_ReplacesEmptyDirectorySlot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.MkdirAll(cfgPath+".bak", 0o755))

	require.NoError(t, writeBackupAtomically(cfgPath, []byte("old config")))
	raw, err := os.ReadFile(cfgPath + ".bak")
	require.NoError(t, err)
	assert.Equal(t, "old config", string(raw))
}

func TestCovCWriteBackupAtomically_NonEmptyDirectorySlotFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.MkdirAll(filepath.Join(cfgPath+".bak", "keep"), 0o755))

	err := writeBackupAtomically(cfgPath, []byte("old config"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace backup")
	assert.DirExists(t, filepath.Join(cfgPath+".bak", "keep"))
}

func TestCovCWriteBackupAtomically_TempCreateFails(t *testing.T) {
	err := writeBackupAtomically(filepath.Join(t.TempDir(), "missing", ".skret.yaml"), []byte("x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temporary config")
}

func TestCovCRejectBackupSymlink_LstatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows maps a file-as-directory lookup to not-exist")
	}
	file := filepath.Join(t.TempDir(), "plain")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	err := rejectBackupSymlink(filepath.Join(file, "child.bak"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inspect backup")
}

func TestCovCWriteConfigAtomically_Errors(t *testing.T) {
	err := writeConfigAtomically(filepath.Join(t.TempDir(), "missing", ".skret.yaml"), []byte("x"), nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temporary config")

	dir := t.TempDir()
	target := filepath.Join(dir, ".skret.yaml")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "keep"), 0o755))
	err = writeConfigAtomically(target, []byte("x"), nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace config")
	assert.DirExists(t, filepath.Join(target, "keep"))
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

// covCIsolateAWS points the AWS SDK at hermetic shared config/credential
// files and clears every ambient credential/profile variable, so the real
// newBootstrapClients only ever sees what the test wrote. Nothing here
// performs network I/O: LoadDefaultConfig resolves configuration lazily.
func covCIsolateAWS(t *testing.T, sharedConfig, sharedCreds string) {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config")
	credFile := filepath.Join(dir, "credentials")
	require.NoError(t, os.WriteFile(cfgFile, []byte(sharedConfig), 0o600))
	require.NoError(t, os.WriteFile(credFile, []byte(sharedCreds), 0o600))
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFile)
	for _, k := range []string{
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func covCStubInteractive(t *testing.T, interactive bool) {
	t.Helper()
	orig := isInteractiveStdin
	isInteractiveStdin = func() bool { return interactive }
	t.Cleanup(func() { isInteractiveStdin = orig })
}

func TestCovCNewBootstrapClients_InteractivePastedKeys(t *testing.T) {
	covCIsolateAWS(t, "", "")
	covCStubInteractive(t, true)
	covCPipeStdin(t, "AKIACOVCPASTED00001\ncovc-pasted-secret\ncovc-session\n")

	iamc, stsc, err := newBootstrapClients(context.Background(), "", "eu-central-1")
	require.NoError(t, err)

	ic, ok := iamc.(*iam.Client)
	require.True(t, ok)
	_, ok = stsc.(*sts.Client)
	require.True(t, ok)
	assert.Equal(t, "eu-central-1", ic.Options().Region)
	creds, err := ic.Options().Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIACOVCPASTED00001", creds.AccessKeyID)
	assert.Equal(t, "covc-pasted-secret", creds.SecretAccessKey)
	assert.Equal(t, "covc-session", creds.SessionToken)
}

func TestCovCNewBootstrapClients_InteractivePromptError(t *testing.T) {
	covCIsolateAWS(t, "", "")
	covCStubInteractive(t, true)
	covCPipeStdin(t, "\n")

	iamc, stsc, err := newBootstrapClients(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access key id required")
	assert.Nil(t, iamc)
	assert.Nil(t, stsc)
}

func TestCovCNewBootstrapClients_NamedProfile(t *testing.T) {
	covCIsolateAWS(t,
		"[profile covc]\nregion = ap-northeast-1\n",
		"[covc]\naws_access_key_id = AKIACOVCPROFILE0001\naws_secret_access_key = covc-profile-secret\n")
	covCStubInteractive(t, true) // a profile wins over the interactive prompt

	iamc, _, err := newBootstrapClients(context.Background(), "covc", "")
	require.NoError(t, err)
	ic := iamc.(*iam.Client)
	assert.Equal(t, "ap-northeast-1", ic.Options().Region, "region comes from the profile when not passed")
	creds, err := ic.Options().Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIACOVCPROFILE0001", creds.AccessKeyID)
}

func TestCovCNewBootstrapClients_MissingProfileFails(t *testing.T) {
	covCIsolateAWS(t, "", "")
	covCStubInteractive(t, false)

	_, _, err := newBootstrapClients(context.Background(), "covc-absent", "us-east-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "covc-absent")
}

func TestCovCNewBootstrapClients_NonInteractiveDefaultChain(t *testing.T) {
	covCIsolateAWS(t, "", "")
	covCStubInteractive(t, false)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIACOVCENVCHAIN001")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "covc-env-secret")

	iamc, stsc, err := newBootstrapClients(context.Background(), "", "sa-east-1")
	require.NoError(t, err)
	require.NotNil(t, stsc)
	ic := iamc.(*iam.Client)
	assert.Equal(t, "sa-east-1", ic.Options().Region)
	creds, err := ic.Options().Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIACOVCENVCHAIN001", creds.AccessKeyID, "CI falls back to the environment chain")
}

func TestCovCBootstrapCmd_InteractiveConfirmDeclined(t *testing.T) {
	iamFake := &bsFakeIAM{}
	store := withFakeBootstrap(t, iamFake, bsFakeSTS{})
	covCStubInteractive(t, true)
	covCPipeStdin(t, "n\n")

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, out.String(), `About to create IAM user "skret-myapp"`)
	assert.Equal(t, 0, iamFake.calls, "declining must not provision anything")
	_, err := store.Load("aws")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)
}

func TestCovCBootstrapCmd_InteractiveConfirmAccepted(t *testing.T) {
	iamFake := &bsFakeIAM{}
	store := withFakeBootstrap(t, iamFake, bsFakeSTS{})
	covCStubInteractive(t, true)
	covCPipeStdin(t, "yes\n")

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, 1, iamFake.calls)
	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, bsKeyID, cred.Metadata["access_key_id"])
}

// ---------------------------------------------------------------------------
// run --watch (runWatch wiring)
// ---------------------------------------------------------------------------

// TestCovCWatchSleeperHelper is not a test of its own: it is the long-running
// child that the runWatch restart tests supervise (the standard Go
// helper-process pattern). It only does anything when the parent injects
// COVC_WATCH_SLEEP=1 (as a secret, so it reaches the child's env only); it
// then blocks until the watch loop terminates it, and exits silently so its
// output can never mix into the parent's stdout.
func TestCovCWatchSleeperHelper(t *testing.T) {
	if os.Getenv("COVC_WATCH_SLEEP") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// covCWatchProvider is mockProvider plus a scripted Fingerprint.
type covCWatchProvider struct {
	mockProvider
	fingerprints []string
	fpErr        error
	calls        atomic.Int32
	listCalls    atomic.Int32
}

func (p *covCWatchProvider) Fingerprint(context.Context, string) (string, error) {
	if p.fpErr != nil {
		return "", p.fpErr
	}
	i := int(p.calls.Add(1)) - 1
	if i >= len(p.fingerprints) {
		i = len(p.fingerprints) - 1
	}
	return p.fingerprints[i], nil
}

func covCSleeperArgs() []string {
	return []string{os.Args[0], "-test.run=^TestCovCWatchSleeperHelper$"}
}

func covCSleeperEnv() []string {
	return append(os.Environ(), "COVC_WATCH_SLEEP=1")
}

// covCRunWatch drives runWatch with a long-running first child; the provider
// reports a changed fingerprint on the first tick so the loop restarts.
func covCRunWatch(t *testing.T, p *covCWatchProvider, noResolve bool) (string, error) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)
	// interval 0 is clamped up to the 1s floor.
	err := runWatch(cmd, p, &config.ResolvedConfig{}, covCSleeperArgs(), nil, covCSleeperEnv(), 0, noResolve)
	return stderr.String(), err
}

func covCDumpSecrets(dump string, extra ...*provider.Secret) []*provider.Secret {
	return append([]*provider.Secret{
		{Key: "SKRET_RUN_ENV_DUMP", Value: dump},
		{Key: "SKRET_RUN_ENV_NAME", Value: "COVC_REF"},
	}, extra...)
}

func TestCovCRunWatch_RestartReinjectsResolvedSecrets(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "dump.txt")
	p := &covCWatchProvider{fingerprints: []string{"fp-1", "fp-2"}}
	p.listFunc = func(context.Context, string) ([]*provider.Secret, error) {
		p.listCalls.Add(1)
		return covCDumpSecrets(dump,
			&provider.Secret{Key: "COVC_BASE", Value: "rotated"},
			&provider.Secret{Key: "COVC_REF", Value: "${COVC_BASE}/v2"},
		), nil
	}

	stderr, err := covCRunWatch(t, p, false)
	require.NoError(t, err)
	assert.Contains(t, stderr, "[skret] secrets changed - restarting")
	assert.Equal(t, int32(1), p.listCalls.Load())
	got, rerr := os.ReadFile(dump)
	require.NoError(t, rerr, "the restarted child must run with the fresh env")
	assert.Equal(t, "rotated/v2", string(got), "restart must re-resolve references")
}

func TestCovCRunWatch_RestartNoResolveKeepsRawValue(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "dump.txt")
	p := &covCWatchProvider{fingerprints: []string{"fp-1", "fp-2"}}
	p.listFunc = func(context.Context, string) ([]*provider.Secret, error) {
		return covCDumpSecrets(dump,
			&provider.Secret{Key: "COVC_BASE", Value: "rotated"},
			&provider.Secret{Key: "COVC_REF", Value: "${COVC_BASE}/v2"},
		), nil
	}

	_, err := covCRunWatch(t, p, true)
	require.NoError(t, err)
	got, rerr := os.ReadFile(dump)
	require.NoError(t, rerr)
	assert.Equal(t, "${COVC_BASE}/v2", string(got))
}

func TestCovCRunWatch_RestartListFailure(t *testing.T) {
	boom := errors.New("covc list exploded")
	p := &covCWatchProvider{fingerprints: []string{"fp-1", "fp-2"}}
	p.listFunc = func(context.Context, string) ([]*provider.Secret, error) { return nil, boom }

	_, err := covCRunWatch(t, p, false)
	require.Error(t, err)
	assert.Equal(t, skret.ExitExecError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "runtime error")
	assert.ErrorIs(t, err, boom)
}

func TestCovCRunWatch_RestartReferenceCycleKeepsExitCode(t *testing.T) {
	p := &covCWatchProvider{fingerprints: []string{"fp-1", "fp-2"}}
	p.listFunc = func(context.Context, string) ([]*provider.Secret, error) {
		return []*provider.Secret{{Key: "A", Value: "${B}"}, {Key: "B", Value: "${A}"}}, nil
	}

	_, err := covCRunWatch(t, p, false)
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err), "a structured restart error keeps its own exit code")
	assert.Contains(t, err.Error(), "reference cycle")
}

func TestCovCRunWatch_SetupErrors(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetErr(&bytes.Buffer{})
	resolved := &config.ResolvedConfig{}

	t.Run("command not found", func(t *testing.T) {
		p := &covCWatchProvider{fingerprints: []string{"x"}}
		err := runWatch(cmd, p, resolved, []string{"covc-no-such-command-4711"}, nil, os.Environ(), time.Second, false)
		require.Error(t, err)
		assert.Equal(t, skret.ExitExecError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "command not found: covc-no-such-command-4711")
		assert.Equal(t, int32(0), p.calls.Load(), "no fingerprint before the binary resolves")
	})

	t.Run("fingerprint failure", func(t *testing.T) {
		p := &covCWatchProvider{fpErr: errors.New("covc fp down")}
		err := runWatch(cmd, p, resolved, covCSleeperArgs(), nil, covCSleeperEnv(), time.Second, false)
		require.Error(t, err)
		assert.Equal(t, skret.ExitProviderError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "run: fingerprint failed")
	})

	t.Run("start failure", func(t *testing.T) {
		name := "covc-not-a-program"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		bad := filepath.Join(t.TempDir(), name)
		require.NoError(t, os.WriteFile(bad, nil, 0o700)) // executable bit, but no valid image
		p := &covCWatchProvider{fingerprints: []string{"x"}}
		err := runWatch(cmd, p, resolved, []string{bad}, nil, os.Environ(), time.Second, false)
		require.Error(t, err)
		assert.Equal(t, skret.ExitExecError, skret.ExitCode(err))
		assert.Contains(t, err.Error(), "run: failed to start command")
	})
}

// TestCovCWatchLoop_PollWithoutChangeKeepsChild pins the two "keep the child"
// poll outcomes (fingerprint unchanged, fingerprint error) deterministically:
// the tick channel is unbuffered, so the child's exit is only delivered after
// the loop has consumed the tick and evaluated the poll. The older
// TestWatchLoop_NoChangeNoRestart / _FingerprintErrorContinues buffer both
// stimuli, so select may legally take the exit first and skip the poll.
func TestCovCWatchLoop_PollWithoutChangeKeepsChild(t *testing.T) {
	cases := []struct {
		name string
		fp   string
		err  error
	}{
		{"unchanged", "same", nil},
		{"transient error", "", errors.New("transient backend error")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tick := make(chan time.Time)
			polled := make(chan struct{}, 1)
			var out bytes.Buffer
			spawned := 0
			deps := watchDeps{
				fingerprint: func(context.Context) (string, error) {
					polled <- struct{}{}
					return tc.fp, tc.err
				},
				list:     func(context.Context) ([]*provider.Secret, error) { return nil, nil },
				buildEnv: func([]*provider.Secret) []string { return nil },
				spawn: func([]string) (supervisor, error) {
					spawned++
					return nil, nil
				},
				tick: tick,
				out:  &out,
			}
			child := &fakeChild{done: make(chan error, 1)}
			res := runLoop(context.Background(), deps, child, "same")

			tick <- time.Now()
			<-polled
			child.done <- nil

			got := awaitResult(t, res)
			assert.Equal(t, 0, got.code)
			require.NoError(t, got.err)
			assert.Equal(t, 0, child.terminated, "a poll without change must not touch the child")
			assert.Equal(t, 0, spawned)
			assert.Empty(t, out.String())
		})
	}
}
