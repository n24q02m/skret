package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initHistoryRepo creates a local-provider config dir plus a git repo whose
// history can be committed to safely: the provider's dev.yaml (which holds the
// managed values) is gitignored, since committing a secrets store would make
// every history scan legitimately flag it.
func initHistoryRepo(t *testing.T) string {
	t.Helper()
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("dev.yaml\n"), 0o600))
	runGitCLI(t, dir, "init")
	return dir
}

// chdirTmp switches the process into dir for the test's duration.
func chdirTmp(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// historyCommitCLI writes files, commits everything, returns the new sha.
func historyCommitCLI(t *testing.T, dir, msg string, files map[string]string) string {
	t.Helper()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	runGitCLI(t, dir, "add", "-A")
	runGitCLI(t, dir, "-c", "user.email=skret-test@example.com", "-c", "user.name=skret-test", "commit", "-m", msg)
	return runGitCLIOut(t, dir, "rev-parse", "HEAD")
}

func runGitCLI(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := osexec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=", "GIT_CONFIG_SYSTEM=")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v: %s", args, out)
}

func runGitCLIOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := osexec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=", "GIT_CONFIG_SYSTEM=")
	out, err := cmd.Output()
	require.NoErrorf(t, err, "git %v: %s", args, err)
	return strings.TrimSpace(string(out))
}

func runScan(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(append([]string{"scan"}, args...))
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func requireLeakErr(t *testing.T, err error) *skret.Error {
	t.Helper()
	require.Error(t, err)
	var se *skret.Error
	require.True(t, errors.As(err, &se))
	return se
}

func TestScanCmd_History_FindsLeak(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := initHistoryRepo(t)
	historyCommitCLI(t, dir, "c1: clean", map[string]string{"app.env": "API=benign\n"})
	sha2 := historyCommitCLI(t, dir, "c2: leak", map[string]string{"leaked.env": "API=tok123\n"})

	stdout, stderr, err := runScan(t, "--history")
	se := requireLeakErr(t, err)
	require.Equal(t, skret.ExitLeakFound, se.Code)
	assert.Contains(t, se.Message, "git history")
	assert.NotEmpty(t, skret.RemediationOf(err), "leak-found error carries a remediation hint")

	s := stdout
	assert.Contains(t, s, "TOKEN")
	assert.Contains(t, s, "leaked.env")
	assert.Contains(t, s, sha2)
	assert.Contains(t, s, "COMMIT")
	assert.NotContains(t, s, "tok123") // value never shown in output
	assert.NotContains(t, s, err.Error())
	assert.NotContains(t, stderr, "tok123") // value never shown on stderr
	assert.NotContains(t, err.Error(), "tok123")
}

func TestScanCmd_History_JSON(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := initHistoryRepo(t)
	historyCommitCLI(t, dir, "c1: leak", map[string]string{"leaked.env": "API=tok123\n"})

	stdout, _, err := runScan(t, "--history", "--format", "json")
	requireLeakErr(t, err)

	s := stdout
	assert.NotContains(t, s, "tok123")

	var findings []map[string]any
	require.NoError(t, json.Unmarshal([]byte(s), &findings))
	require.Len(t, findings, 1)
	assert.Equal(t, "TOKEN", findings[0]["key"])
	assert.Equal(t, "leaked.env", findings[0]["file"])
	assert.Equal(t, float64(1), findings[0]["line"])
	assert.Equal(t, runGitCLIOut(t, dir, "rev-parse", "HEAD"), findings[0]["commit"])
}

func TestScanCmd_History_Clean(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := initHistoryRepo(t)
	historyCommitCLI(t, dir, "c1", map[string]string{"app.env": "API=benign\n"})

	_, stderr, err := runScan(t, "--history")
	require.NoError(t, err)
	assert.Contains(t, stderr, "No leaks found.")
}

func TestScanCmd_History_CleanJSON(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := initHistoryRepo(t)
	historyCommitCLI(t, dir, "c1", map[string]string{"app.env": "API=benign\n"})

	stdout, stderr, err := runScan(t, "--history", "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, "[]\n", stdout, "clean history renders an empty findings array on stdout")
	assert.Contains(t, stderr, "No leaks found.", "status line stays on stderr")
}

func TestScanCmd_History_MaxCountBounds(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := initHistoryRepo(t)
	historyCommitCLI(t, dir, "c1: leak", map[string]string{"leaked.env": "API=tok123\n"})
	historyCommitCLI(t, dir, "c2", map[string]string{"app.env": "API=benign\n"})

	// The leak commit falls outside a 1-commit window.
	_, stderr, err := runScan(t, "--history", "--max-count=1")
	require.NoError(t, err)
	assert.Contains(t, stderr, "No leaks found.")
}

func TestScanCmd_History_NotARepo(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runScan(t, "--history")
	se := requireLeakErr(t, err)
	assert.Equal(t, skret.ExitGenericError, se.Code)
	assert.Contains(t, se.Message, "history scan failed")
	assert.NotEmpty(t, skret.RemediationOf(err))
}

func TestScanCmd_History_StagedConflict(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runScan(t, "--staged", "--history")
	se := requireLeakErr(t, err)
	assert.Equal(t, skret.ExitGenericError, se.Code)
	assert.Contains(t, se.Message, "mutually exclusive")
}

func TestScanCmd_History_SinceWithoutHistory(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runScan(t, "--since=2 weeks ago")
	se := requireLeakErr(t, err)
	assert.Equal(t, skret.ExitGenericError, se.Code)
	assert.Contains(t, se.Message, "--since only applies to --history")
}

func TestScanCmd_History_BadMaxCount(t *testing.T) {
	dir := writeLocalTemplateConfig(t)
	chdirTmp(t, dir)

	_, _, err := runScan(t, "--history", "--max-count=0")
	se := requireLeakErr(t, err)
	assert.Equal(t, skret.ExitGenericError, se.Code)
	assert.Contains(t, se.Message, "--max-count must be at least 1")
}
