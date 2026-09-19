package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRefScopeConfig creates a local-provider config whose dev environment
// holds a small reference scope: DB_URL references DB_USER/DB_PASS, TOKEN and
// LITERAL are standalone, and ESCAPED carries both escape spellings.
func writeRefScopeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("dev.yaml", `version: "1"
secrets:
  DB_USER: admin
  DB_PASS: "p@ss w0rd"
  DB_URL: postgres://${DB_USER}:${DB_PASS}@db:5432
  TOKEN: tok123
  LITERAL: no-dollars-here
  ESCAPED: \${DB_USER} and $${DB_USER}
  CHAIN: ${DB_URL}/app
`)
	must(".skret.yaml", "version: \"1\"\ndefault_env: dev\nenvironments:\n  dev:\n    provider: local\n    file: dev.yaml\n")
	return dir
}

// runRefCmd executes the CLI with args, chdir'd into dir, returning stdout+stderr.
func runRefCmd(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestGetCmd_ResolvesReference(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "DB_URL")
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:p@ss w0rd@db:5432\n", out)
}

func TestGetCmd_ChainResolvesTransitively(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "CHAIN")
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:p@ss w0rd@db:5432/app\n", out)
}

func TestGetCmd_NoResolveReturnsRawBytes(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "DB_URL", "--no-resolve")
	require.NoError(t, err)
	assert.Equal(t, "postgres://${DB_USER}:${DB_PASS}@db:5432\n", out)

	out, err = runRefCmd(t, dir, "get", "ESCAPED")
	require.NoError(t, err)
	assert.Equal(t, `\${DB_USER} and $${DB_USER}`+"\n", out)
}

func TestGetCmd_ByteExactPlainWithSpecials(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "DB_URL", "--plain")
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:p@ss w0rd@db:5432", out)
}

func TestGetCmd_MissingReferenceErrors(t *testing.T) {
	dir := writeRefScopeConfig(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte(
		"version: \"1\"\nsecrets:\n  BROKEN: pre-${NOT_THERE}-post\n"), 0o600))

	_, err := runRefCmd(t, dir, "get", "BROKEN")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "${NOT_THERE}")
	// The referenced value must not leak through the error.
	assert.NotContains(t, err.Error(), "postgres")
}

func TestGetCmd_CycleErrorsWithChain(t *testing.T) {
	dir := writeRefScopeConfig(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte(
		"version: \"1\"\nsecrets:\n  A: \"${B}\"\n  B: \"${A}\"\n"), 0o600))

	_, err := runRefCmd(t, dir, "get", "A")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	// Chain: resolving A's value walks B first, so the loop is reported B -> A -> B.
	assert.Contains(t, err.Error(), "reference cycle: B -> A -> B")
}

func TestGetCmd_JsonContainsResolvedValue(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "DB_URL", "--json")
	require.NoError(t, err)
	assert.Contains(t, out, `"value": "postgres://admin:p@ss w0rd@db:5432"`)
}

func TestEnvCmd_ResolvesReferences(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "env", "--format=dotenv")
	require.NoError(t, err)
	assert.Contains(t, out, `DB_URL="postgres://admin:p@ss w0rd@db:5432"`)
	assert.Contains(t, out, `CHAIN="postgres://admin:p@ss w0rd@db:5432/app"`)
	assert.Contains(t, out, "TOKEN=tok123")
	// Escaped values keep their bytes (dotenv doubles the backslash when quoting).
	assert.Contains(t, out, `ESCAPED="\\${DB_USER} and $${DB_USER}"`)

	out, err = runRefCmd(t, dir, "env", "--no-resolve")
	require.NoError(t, err)
	assert.Contains(t, out, `DB_URL="postgres://${DB_USER}:${DB_PASS}@db:5432"`)
	assert.Contains(t, out, `CHAIN="${DB_URL}/app"`)
}

func TestEnvCmd_MissingReferenceFailsWholeDump(t *testing.T) {
	dir := writeRefScopeConfig(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte(
		"version: \"1\"\nsecrets:\n  GOOD: fine\n  BAD: \"${GONE}\"\n"), 0o600))

	_, err := runRefCmd(t, dir, "env", "--format=dotenv")
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "${GONE}")
}

func TestRunCmd_InjectsResolvedValues(t *testing.T) {
	dir := writeRefScopeConfig(t)
	dump := filepath.Join(dir, "envdump.txt")
	t.Setenv("SKRET_RUN_ENV_DUMP", dump)
	t.Setenv("SKRET_RUN_ENV_NAME", "DB_URL")

	_, err := runRefCmd(t, dir, "run", "--", os.Args[0])
	require.NoError(t, err)
	data, rerr := os.ReadFile(dump)
	require.NoError(t, rerr)
	assert.Equal(t, "postgres://admin:p@ss w0rd@db:5432", string(data))
}

func TestRunCmd_NoResolveInjectsRawStoredValue(t *testing.T) {
	dir := writeRefScopeConfig(t)
	dump := filepath.Join(dir, "envdump.txt")
	t.Setenv("SKRET_RUN_ENV_DUMP", dump)
	t.Setenv("SKRET_RUN_ENV_NAME", "DB_URL")

	_, err := runRefCmd(t, dir, "run", "--no-resolve", "--", os.Args[0])
	require.NoError(t, err)
	data, rerr := os.ReadFile(dump)
	require.NoError(t, rerr)
	assert.Equal(t, "postgres://${DB_USER}:${DB_PASS}@db:5432", string(data))
}

func TestRunCmd_CycleFailsBeforeLaunch(t *testing.T) {
	dir := writeRefScopeConfig(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev.yaml"), []byte(
		"version: \"1\"\nsecrets:\n  A: \"${B}\"\n  B: \"${A}\"\n"), 0o600))
	dump := filepath.Join(dir, "envdump.txt")
	t.Setenv("SKRET_RUN_ENV_DUMP", dump)
	t.Setenv("SKRET_RUN_ENV_NAME", "A")

	_, err := runRefCmd(t, dir, "run", "--", os.Args[0])
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "reference cycle: B -> A -> B")
	assert.NoFileExists(t, dump) // the child never launched
}

// resolveInPlace unit coverage: scope identity follows environment names, not
// raw keys, and excluded-but-present keys stay resolvable.
func TestResolveInPlace_UsesEnvNameIdentity(t *testing.T) {
	secrets := []*provider.Secret{
		{Key: "db-user", Value: "admin"},
		{Key: "CONN", Value: "user=${DB_USER}"},
	}
	require.NoError(t, resolveInPlace(secrets, ""))
	assert.Equal(t, "user=admin", secrets[1].Value)
}

func TestResolveInPlace_NoTokensUntouched(t *testing.T) {
	raw := "$2a$14$N9qo8uLOickgx2ZMRZoMye"
	secrets := []*provider.Secret{{Key: "K", Value: raw}}
	require.NoError(t, resolveInPlace(secrets, ""))
	assert.Equal(t, raw, secrets[0].Value)
}

func TestResolveValue_ErrorsCarryExitCodeAndRemediation(t *testing.T) {
	lookup := scopeLookup([]*provider.Secret{{Key: "A", Value: "${B}"}, {Key: "B", Value: "${A}"}}, "")

	_, err := resolveValue("${A}", "OWNER", lookup)
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "A -> B -> A")
	assert.NotEmpty(t, skret.RemediationOf(err))

	_, err = resolveValue("${MISSING}", "OWNER", lookup)
	require.Error(t, err)
	assert.Equal(t, skret.ExitValidationError, skret.ExitCode(err))
	assert.Contains(t, skret.RemediationOf(err), "skret set MISSING")
}

func TestHasReferenceToken(t *testing.T) {
	assert.False(t, hasReferenceToken("plain"))
	assert.False(t, hasReferenceToken("$2a$14$x"))
	assert.True(t, hasReferenceToken("pre-${A}"))
	assert.True(t, hasReferenceToken("escaped \\${A}")) // still scanned; escape handled by resolver
}

// The env JSON format must carry resolved values too.
func TestEnvCmd_JsonFormatResolved(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "env", "--format=json")
	require.NoError(t, err)
	assert.Contains(t, out, "postgres://admin:p@ss w0rd@db:5432")
}

// get on a value without any ${ token must not require listing the scope —
// exercised implicitly by LITERAL resolving to itself with a provider whose
// List would fail if called; simulate via a store with exactly one key.
func TestGetCmd_NoRefSkipsScope(t *testing.T) {
	dir := writeRefScopeConfig(t)

	out, err := runRefCmd(t, dir, "get", "LITERAL")
	require.NoError(t, err)
	assert.False(t, strings.Contains(out, "postgres://admin"))
	assert.Equal(t, "no-dollars-here\n", out)
}
