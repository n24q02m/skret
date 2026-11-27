package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// protectToken is a fabricated value in the GitHub personal access token
// format, assembled at run time so this file contains no token itself.
func protectToken() string { return "ghp_" + strings.Repeat("Fx7q", 9) }

const protectEnvValue = "fixture-env-value-0001"

// protectRepo creates an empty git repository (no commit yet), switches into
// it, and returns its path.
func protectRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	chdirTmp(t, dir)
	runGitCLI(t, dir, "init", "-q")
	return dir
}

func writeProtectFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

// requireNoSecret asserts that no output channel carries a fixture secret.
func requireNoSecret(t *testing.T, stdout, stderr string, err error) {
	t.Helper()
	all := stdout + stderr
	if err != nil {
		all += err.Error() + skret.RemediationOf(err)
	}
	assert.NotContains(t, all, protectToken())
	assert.NotContains(t, all, protectEnvValue)
}

func TestProtect_StagedEnvFile(t *testing.T) {
	dir := protectRepo(t)
	writeProtectFile(t, dir, ".env", "API_KEY="+protectEnvValue+"\n")
	writeProtectFile(t, dir, ".env.example", "API_KEY=\n")
	runGitCLI(t, dir, "add", ".env", ".env.example")

	stdout, stderr, err := runRootCmd(t, "protect")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, err.Error(), "1 finding(s) in staged files")
	assert.Equal(t, "FILE  LINE  RULE\n.env  -     env-file\n", stdout)
	requireNoSecret(t, stdout, stderr, err)
}

func TestProtect_StagedPlaintextToken(t *testing.T) {
	dir := protectRepo(t)
	writeProtectFile(t, dir, "src/config.yaml", "name: app\ntoken: "+protectToken()+"\n")
	runGitCLI(t, dir, "add", "src/config.yaml")
	// What is staged is what gets committed: removing the token from the
	// working tree afterwards does not hide it.
	writeProtectFile(t, dir, "src/config.yaml", "name: app\n")

	stdout, stderr, err := runRootCmd(t, "protect")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, stdout, "src/config.yaml  2     github-pat")
	requireNoSecret(t, stdout, stderr, err)
}

func TestProtect_CleanStagedTreePasses(t *testing.T) {
	dir := protectRepo(t)
	writeProtectFile(t, dir, "main.go", "package main\n")
	writeProtectFile(t, dir, ".env.example", "API_KEY=\n")
	// An unstaged .env is not part of the commit.
	writeProtectFile(t, dir, ".env", "API_KEY="+protectEnvValue+"\n")
	runGitCLI(t, dir, "add", "main.go", ".env.example")

	stdout, stderr, err := runRootCmd(t, "protect")
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "No plaintext secrets found.")
}

// From a subdirectory the whole index is still checked; paths stay
// repo-relative, as git reports them.
func TestProtect_StagedFromSubdirectory(t *testing.T) {
	dir := protectRepo(t)
	writeProtectFile(t, dir, "config/.env.local", "A=1\n")
	writeProtectFile(t, dir, "sub/readme.md", "hi\n")
	runGitCLI(t, dir, "add", "-A")
	chdirTmp(t, filepath.Join(dir, "sub"))

	stdout, _, err := runRootCmd(t, "protect")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, stdout, "config/.env.local")
}

func TestProtect_StagedOutsideGitRepo(t *testing.T) {
	chdirTmp(t, t.TempDir())
	_, _, err := runRootCmd(t, "protect")
	requireExit(t, err, skret.ExitGenericError)
	assert.Contains(t, err.Error(), "reading staged files failed")
	assert.Contains(t, skret.RemediationOf(err), "pass the paths to check")
}

func TestProtect_PathArguments(t *testing.T) {
	dir := t.TempDir() // not a git repository: paths still work
	chdirTmp(t, dir)
	writeProtectFile(t, dir, "clean.txt", "nothing here\n")
	writeProtectFile(t, dir, "leaky.txt", "x\n"+protectToken()+"\n")
	writeProtectFile(t, dir, "deploy/prod.env", "A="+protectEnvValue+"\n")
	writeProtectFile(t, dir, "deploy/notes.md", "fine\n")

	_, stderr, err := runRootCmd(t, "protect", "clean.txt")
	require.NoError(t, err)
	assert.Contains(t, stderr, "No plaintext secrets found.")

	stdout, stderr, err := runRootCmd(t, "protect", "clean.txt", "leaky.txt", "deploy")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, err.Error(), "2 finding(s) in the given paths")
	assert.Contains(t, stdout, filepath.Join("deploy", "prod.env")+"  -     env-file")
	assert.Contains(t, stdout, "leaky.txt")
	assert.NotContains(t, stdout, "clean.txt")
	requireNoSecret(t, stdout, stderr, err)
}

// A directory argument inside a repository covers tracked and untracked
// files but not ignored ones.
func TestProtect_DirectoryArgumentHonoursGitignore(t *testing.T) {
	dir := protectRepo(t)
	writeProtectFile(t, dir, ".gitignore", "ignored.txt\n")
	writeProtectFile(t, dir, "ignored.txt", protectToken()+"\n")
	writeProtectFile(t, dir, "untracked.txt", protectToken()+"\n")

	stdout, _, err := runRootCmd(t, "protect", ".")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, stdout, "untracked.txt")
	assert.NotContains(t, stdout, "ignored.txt")
}

func TestProtect_MissingPath(t *testing.T) {
	chdirTmp(t, t.TempDir())
	_, _, err := runRootCmd(t, "protect", "no-such-file")
	requireExit(t, err, skret.ExitValidationError)
	assert.Contains(t, err.Error(), `"no-such-file"`)
}

func TestProtect_AllowAndInlineMarker(t *testing.T) {
	dir := t.TempDir()
	chdirTmp(t, dir)
	writeProtectFile(t, dir, "testdata/fixture.txt", protectToken()+"\n")
	writeProtectFile(t, dir, ".env.ci", "A=1\n")
	writeProtectFile(t, dir, "doc.md", "example: "+protectToken()+" <!-- skret:allow -->\n")

	_, stderr, err := runRootCmd(t, "protect", "--allow", "testdata/", "--allow", ".env.ci", "testdata", ".env.ci", "doc.md")
	require.NoError(t, err)
	assert.Contains(t, stderr, "No plaintext secrets found.")
}

func TestProtect_BadAllowPattern(t *testing.T) {
	chdirTmp(t, t.TempDir())
	_, _, err := runRootCmd(t, "protect", "--allow", "[", ".")
	requireExit(t, err, skret.ExitValidationError)
}

func TestProtect_Strict(t *testing.T) {
	dir := t.TempDir()
	chdirTmp(t, dir)
	writeProtectFile(t, dir, "app.conf", "password=hunter2-fixture\n")

	_, _, err := runRootCmd(t, "protect", "app.conf")
	require.NoError(t, err)

	stdout, _, err := runRootCmd(t, "protect", "--strict", "app.conf")
	requireExit(t, err, skret.ExitLeakFound)
	assert.Contains(t, stdout, "secret-assignment")
	assert.NotContains(t, stdout, "hunter2-fixture")
}

func TestProtect_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	chdirTmp(t, dir)
	writeProtectFile(t, dir, "leaky.txt", protectToken()+"\n")
	writeProtectFile(t, dir, "clean.txt", "ok\n")

	stdout, stderr, err := runRootCmd(t, "protect", "--format", "json", "leaky.txt")
	requireExit(t, err, skret.ExitLeakFound)
	var findings []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &findings))
	assert.Equal(t, []map[string]any{{"file": "leaky.txt", "line": float64(1), "rule": "github-pat"}}, findings)
	requireNoSecret(t, stdout, stderr, err)

	stdout, _, err = runRootCmd(t, "protect", "--format", "json", "clean.txt")
	require.NoError(t, err)
	assert.JSONEq(t, "[]", stdout, "a clean run still prints a JSON document")
}

func TestProtect_BadFormat(t *testing.T) {
	chdirTmp(t, t.TempDir())
	_, _, err := runRootCmd(t, "protect", "--format", "yaml", ".")
	requireExit(t, err, skret.ExitValidationError)
}

type protectFailWriter struct{}

func (protectFailWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestProtect_OutputWriteFailure(t *testing.T) {
	dir := t.TempDir()
	chdirTmp(t, dir)
	writeProtectFile(t, dir, "leaky.txt", protectToken()+"\n")
	for _, format := range []string{"table", "json"} {
		cmd := NewRootCmd()
		cmd.SetOut(protectFailWriter{})
		cmd.SetErr(&strings.Builder{})
		cmd.SetArgs([]string{"protect", "--format", format, "leaky.txt"})
		require.ErrorIs(t, cmd.Execute(), os.ErrClosed, format)
	}
}

// protect never reads .skret.yaml or a provider, so it runs in any repo.
func TestProtect_NeedsNoConfig(t *testing.T) {
	dir := t.TempDir()
	chdirTmp(t, dir)
	writeProtectFile(t, dir, ".skret.yaml", "not: [valid")
	writeProtectFile(t, dir, "a.txt", "ok\n")
	_, _, err := runRootCmd(t, "protect", "a.txt")
	require.NoError(t, err)
}
