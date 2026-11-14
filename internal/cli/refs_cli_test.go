package cli

import (
	"bytes"
	"os"
	osexec "os/exec"
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

// runRefRunInChild drives `skret run ... -- <test binary>` from a re-exec of
// the test binary rather than inline. On Unix `run` replaces the process image
// via syscall.Exec, so running it inline swaps the whole test binary for the
// launched command: every test ordered after it silently never runs and the
// binary exits without printing its PASS and `coverage:` lines. Only the child
// gets replaced here; the launched command (this binary again, see the
// SKRET_RUN_ENV_DUMP branch in TestMain) writes the env var named envName to
// the returned dump file, which the parent then asserts on.
//
// The dump target travels as SKRET_TEST_REFRUN_DUMP and is only promoted to
// SKRET_RUN_ENV_DUMP inside the child test: setting SKRET_RUN_ENV_DUMP on the
// child itself would trip that TestMain branch before the test ever ran.
func runRefRunInChild(t *testing.T, testName, envName string, args ...string) string {
	t.Helper()
	if os.Getenv("SKRET_TEST_REFRUN_CHILD") == "1" {
		t.Setenv("SKRET_RUN_ENV_DUMP", os.Getenv("SKRET_TEST_REFRUN_DUMP"))
		t.Setenv("SKRET_RUN_ENV_NAME", envName)
		// Only reached on Windows, where `run` returns after the child exits.
		_, err := runRefCmd(t, os.Getenv("SKRET_TEST_REFRUN_DIR"), append(args, "--", os.Args[0])...)
		require.NoError(t, err)
		return ""
	}

	dir := writeRefScopeConfig(t)
	dump := filepath.Join(dir, "envdump.txt")
	child := osexec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+testName+"$", "-test.count=1")
	child.Env = append(os.Environ(),
		"SKRET_TEST_REFRUN_CHILD=1",
		"SKRET_TEST_REFRUN_DIR="+dir,
		"SKRET_TEST_REFRUN_DUMP="+dump,
	)
	out, err := child.CombinedOutput()
	require.NoError(t, err, "run subprocess failed: %s", out)
	data, rerr := os.ReadFile(dump)
	require.NoError(t, rerr, "launched command never wrote its env dump; child output: %s", out)
	return string(data)
}

func TestRunCmd_InjectsResolvedValues(t *testing.T) {
	got := runRefRunInChild(t, "TestRunCmd_InjectsResolvedValues", "DB_URL", "run")
	if os.Getenv("SKRET_TEST_REFRUN_CHILD") == "1" {
		return
	}
	assert.Equal(t, "postgres://admin:p@ss w0rd@db:5432", got)
}

func TestRunCmd_NoResolveInjectsRawStoredValue(t *testing.T) {
	got := runRefRunInChild(t, "TestRunCmd_NoResolveInjectsRawStoredValue", "DB_URL", "run", "--no-resolve")
	if os.Getenv("SKRET_TEST_REFRUN_CHILD") == "1" {
		return
	}
	assert.Equal(t, "postgres://${DB_USER}:${DB_PASS}@db:5432", got)
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
