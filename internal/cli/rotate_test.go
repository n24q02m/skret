package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// rotateStore mirrors the local provider file shape for assertions.
type rotateStore struct {
	Version string            `yaml:"version"`
	Secrets map[string]string `yaml:"secrets"`
	Meta    map[string]string `yaml:"meta"`
}

// rotateSetupRepo creates a local-provider repo seeded with two known
// secrets, chdirs into it, and registers cleanup restore.
func rotateSetupRepo(t *testing.T) string {
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
	rotateSeedFile(t, dir)

	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return dir
}

// rotateSeedFile rewrites the two-secret local store so each subtest starts
// from the same known values (API_KEY="secret123", DB_PASS="old-db-value").
func rotateSeedFile(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".secrets.dev.yaml"), []byte(`
version: "1"
secrets:
  API_KEY: "secret123"
  DB_PASS: "old-db-value"
`), 0o600))
}

// rotateRand reseeds the generate engine's randomness source with real
// crypto/rand and restores the original after the test.
func rotateRand(t *testing.T) {
	t.Helper()
	orig := genRandReader
	genRandReader = rand.Reader
	t.Cleanup(func() { genRandReader = orig })
}

// readRotateStore unmarshals the local secrets file for assertions.
func readRotateStore(t *testing.T, dir string) rotateStore {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".secrets.dev.yaml"))
	require.NoError(t, err)
	var store rotateStore
	require.NoError(t, yaml.Unmarshal(data, &store))
	return store
}

// runRotate executes `skret rotate <args...>` in dir with captured streams.
func runRotate(t *testing.T, dir string, args ...string) (string, string, error) {
	t.Helper()
	require.NoError(t, os.Chdir(dir))
	cmd := newRotateCmd(&GlobalOpts{})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestRotateCmd_GeneratesNewValue(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	stdout, stderr, err := runRotate(t, dir, "API_KEY")
	require.NoError(t, err)

	newValue := readRotateStore(t, dir).Secrets["API_KEY"]
	assert.NotEqual(t, "secret123", newValue, "rotate must replace the value")
	assert.Len(t, newValue, 32, "default generation is password/32/alnum")
	for _, r := range newValue {
		assert.True(t, strings.ContainsRune(generateAlnum, r), "alnum charset by default")
	}

	assert.Empty(t, stdout, "default output must not print values on stdout")
	assert.Contains(t, stderr, "Rotated API_KEY")
}

func TestRotateCmd_NonInteractiveRotatesWithoutPrompt(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	// No --yes and stdin is not a TTY (tests never are): rotation must
	// proceed with no prompt and no "Cancelled." — the CI path.
	stdout, stderr, err := runRotate(t, dir, "API_KEY")
	require.NoError(t, err)
	assert.NotContains(t, stderr, "Rotate 1 secret(s)?")
	assert.NotContains(t, stderr, "Cancelled")
	assert.Contains(t, stderr, "Rotated API_KEY")
	assert.NotEqual(t, "secret123", readRotateStore(t, dir).Secrets["API_KEY"])
	assert.Empty(t, stdout)
}

func TestRotateCmd_ValueNeverLeaksOnStdout(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	stdout, _, err := runRotate(t, dir, "API_KEY", "DB_PASS")
	require.NoError(t, err)
	store := readRotateStore(t, dir)
	assert.NotContains(t, stdout, store.Secrets["API_KEY"], "new value must not leak")
	assert.NotContains(t, stdout, store.Secrets["DB_PASS"], "new value must not leak")
	assert.NotContains(t, stdout, "secret123", "old value must not leak")
	assert.Empty(t, stdout, "stdout must stay empty without --show")
}

func TestRotateCmd_ShowPrintsValueOnce(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	stdout, stderr, err := runRotate(t, dir, "API_KEY", "--show")
	require.NoError(t, err)
	newValue := readRotateStore(t, dir).Secrets["API_KEY"]
	assert.Equal(t, newValue+"\n", stdout, "--show prints exactly the value")
	assert.NotContains(t, stderr, newValue, "value stays off stderr")
}

func TestRotateCmd_ExplicitValue(t *testing.T) {
	dir := rotateSetupRepo(t)

	_, _, err := runRotate(t, dir, "API_KEY", "--value", "manually-set-token", "--generate=false")
	require.NoError(t, err)
	assert.Equal(t, "manually-set-token", readRotateStore(t, dir).Secrets["API_KEY"])
}

func TestRotateCmd_TTLRecordedAndPreserved(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	before := time.Now()
	_, _, err := runRotate(t, dir, "API_KEY", "--ttl", "30d")
	require.NoError(t, err)

	raw, ok := readRotateStore(t, dir).Meta["API_KEY"]
	require.True(t, ok, "local file must record expiry metadata")
	expiry, perr := time.Parse(time.RFC3339, raw)
	require.NoError(t, perr)
	assert.True(t, expiry.After(before.Add(29*24*time.Hour)), "expiry ≈ now+30d: %v", expiry)
	assert.True(t, expiry.Before(before.Add(31*24*time.Hour)), "expiry ≈ now+30d: %v", expiry)

	// Rotate again WITHOUT --ttl: the recorded expiry must survive.
	_, _, err = runRotate(t, dir, "API_KEY")
	require.NoError(t, err)
	assert.Equal(t, raw, readRotateStore(t, dir).Meta["API_KEY"],
		"rotation without --ttl continues the existing cadence")
}

func TestRotateCmd_MultipleKeys(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	stdout, stderr, err := runRotate(t, dir, "API_KEY", "DB_PASS")
	require.NoError(t, err)
	store := readRotateStore(t, dir)
	assert.NotEqual(t, "secret123", store.Secrets["API_KEY"])
	assert.NotEqual(t, "old-db-value", store.Secrets["DB_PASS"])
	assert.Contains(t, stderr, "Rotated API_KEY")
	assert.Contains(t, stderr, "Rotated DB_PASS")
	assert.Empty(t, stdout)
}

func TestRotateCmd_JSONFormat(t *testing.T) {
	dir := rotateSetupRepo(t)
	rotateRand(t)

	stdout, _, err := runRotate(t, dir, "API_KEY", "--format", "json")
	require.NoError(t, err)
	assert.NotContains(t, stdout, "secret123", "old value never appears")

	var got RotateResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, "API_KEY", got.Key)
	assert.True(t, got.Rotated)
	assert.Empty(t, got.Value, "JSON payload must omit the value without --show")
	assert.Empty(t, got.ExpiresAt, "no expiry recorded without --ttl")

	// Multi-key: array payload with expiry.
	stdout, _, err = runRotate(t, dir, "API_KEY", "DB_PASS", "--format", "json", "--ttl", "48h")
	require.NoError(t, err)
	var many []RotateResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &many))
	require.Len(t, many, 2)
	assert.Equal(t, "API_KEY", many[0].Key)
	assert.Equal(t, "DB_PASS", many[1].Key)
	for _, res := range many {
		assert.True(t, res.Rotated)
		assert.NotEmpty(t, res.ExpiresAt)
		expiry, perr := time.Parse(time.RFC3339, res.ExpiresAt)
		require.NoError(t, perr)
		assert.InDelta(t, 48, time.Until(expiry).Hours(), 1.0)
	}

	// --show rides inside the JSON payload.
	stdout, _, err = runRotate(t, dir, "API_KEY", "--format", "json", "--show")
	require.NoError(t, err)
	var shown RotateResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &shown))
	assert.Equal(t, readRotateStore(t, dir).Secrets["API_KEY"], shown.Value)
}

func TestRotateCmd_NotFound(t *testing.T) {
	dir := rotateSetupRepo(t)

	_, _, err := runRotate(t, dir, "MISSING_KEY")
	require.Error(t, err)
	assert.Equal(t, skret.ExitNotFoundError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "Nothing to rotate")

	// Preflight: a missing key in a multi-key batch rotates nothing.
	_, _, err = runRotate(t, dir, "API_KEY", "MISSING_KEY")
	require.Error(t, err)
	assert.Equal(t, skret.ExitNotFoundError, skret.ExitCode(err))
	assert.Equal(t, "secret123", readRotateStore(t, dir).Secrets["API_KEY"],
		"no key may rotate when the batch preflight fails")
}

func TestRotateCmd_FlagValidation(t *testing.T) {
	dir := rotateSetupRepo(t)

	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"unknown type", []string{"API_KEY", "--type", "base58"}, "unknown --type"},
		{"length zero", []string{"API_KEY", "--length", "0"}, "--length must be between"},
		{"uuid with length", []string{"API_KEY", "--type", "uuid", "--length", "10"}, "--length does not apply to uuid"},
		{"unknown charset", []string{"API_KEY", "--charset", "emoji"}, "unknown --charset"},
		{"charset without password type", []string{"API_KEY", "--type", "hex", "--charset", "alnum"}, "--charset only applies"},
		{"generate=false without value", []string{"API_KEY", "--generate=false"}, "--generate=false requires --value"},
		{"value with explicit generate", []string{"API_KEY", "--value", "x", "--generate"}, "mutually exclusive"},
		{"value with type flags", []string{"API_KEY", "--value", "x", "--length", "8"}, "--type/--length/--charset only apply"},
		{"bad ttl", []string{"API_KEY", "--ttl", "soon"}, "invalid duration"},
		{"negative ttl", []string{"API_KEY", "--ttl", "-1h"}, "must be positive"},
		{"bad format", []string{"API_KEY", "--format", "yaml"}, "unknown --format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rotateSeedFile(t, dir)
			_, _, err := runRotate(t, dir, tc.args...)
			require.Error(t, err)
			assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
			assert.Contains(t, err.Error(), tc.wantMsg)
			assert.Equal(t, "secret123", readRotateStore(t, dir).Secrets["API_KEY"],
				"validation failure must not mutate anything")
		})
	}
}

func TestRotateCmd_TTLOnSetRoundTrips(t *testing.T) {
	dir := rotateSetupRepo(t)

	cmd := newSetCmd(&GlobalOpts{})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"API_KEY", "fresh-value", "--ttl", "12h"})
	require.NoError(t, cmd.Execute())

	raw, ok := readRotateStore(t, dir).Meta["API_KEY"]
	require.True(t, ok, "set --ttl must record expiry metadata")
	expiry, perr := time.Parse(time.RFC3339, raw)
	require.NoError(t, perr)
	assert.InDelta(t, 12, time.Until(expiry).Hours(), 1.0)

	// set WITHOUT --ttl leaves the recorded expiry in place.
	cmd = newSetCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"API_KEY", "another-value"})
	require.NoError(t, cmd.Execute())
	assert.Equal(t, raw, readRotateStore(t, dir).Meta["API_KEY"])
}

func TestRotateCmd_ListSurfacesExpiry(t *testing.T) {
	rotateSetupRepo(t)

	cmd := newSetCmd(&GlobalOpts{})
	cmd.SetArgs([]string{"API_KEY", "fresh-value", "--ttl", "1h"})
	require.NoError(t, cmd.Execute())

	listCmd := newListCmd(&GlobalOpts{})
	var stdout bytes.Buffer
	listCmd.SetOut(&stdout)
	listCmd.SetArgs([]string{"list", "--values", "--format", "json"})
	require.NoError(t, listCmd.Execute())

	var items []map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &items))
	byKey := map[string]map[string]any{}
	for _, item := range items {
		byKey[item["key"].(string)] = item
	}
	require.Contains(t, byKey["API_KEY"], "expires_at", "expiring key surfaces expires_at")
	assert.NotContains(t, byKey["DB_PASS"], "expires_at", "keys without ttl stay clean")

	// Near-expiry (< 7d) warns on stderr without touching stdout.
	warnCmd := newListCmd(&GlobalOpts{})
	var out, errOut bytes.Buffer
	warnCmd.SetOut(&out)
	warnCmd.SetErr(&errOut)
	warnCmd.SetArgs([]string{"list", "--values"})
	require.NoError(t, warnCmd.Execute())
	assert.Contains(t, errOut.String(), "warning: API_KEY expires in")
	assert.Contains(t, out.String(), "EXPIRES")
}
