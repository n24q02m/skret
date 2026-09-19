package scanner

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runGitOut runs git in dir and returns trimmed stdout (for rev-parse etc.).
func runGitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := osexec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(
		os.Environ(),
		"GIT_CONFIG_GLOBAL=",
		"GIT_CONFIG_SYSTEM=",
	)
	out, err := cmd.Output()
	require.NoErrorf(t, err, "git %v: %s", args, err)
	return strings.TrimSpace(string(out))
}

// historyCommit writes files (name -> content), commits everything staged,
// and returns the new HEAD sha.
func historyCommit(t *testing.T, dir, msg string, files map[string]string) string {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "-c", "user.email=skret-test@example.com", "-c", "user.name=skret-test", "commit", "-m", msg)
	return runGitOut(t, dir, "rev-parse", "HEAD")
}

func historyTargets() []Target {
	return []Target{{Key: "TOKEN", Value: "tok123"}}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
}

func TestHistoryScan_FindsIntroducingCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")

	sha1 := historyCommit(t, dir, "c1: clean", map[string]string{"readme.md": "hello\n"})
	sha2 := historyCommit(t, dir, "c2: leak", map[string]string{"leaked.env": "API=tok123\n"})
	historyCommit(t, dir, "c3: clean", map[string]string{"readme.md": "hello\nworld\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, Finding{Key: "TOKEN", File: "leaked.env", Line: 1, Commit: sha2}, findings[0])
	assert.NotEqual(t, sha1, findings[0].Commit)
}

func TestHistoryScan_CleanHistory(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"app.env": "API=not-the-secret\n"})
	historyCommit(t, dir, "c2", map[string]string{"app.env": "API=still-not-the-secret\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestHistoryScan_RootCommitSecret(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	sha1 := historyCommit(t, dir, "c1: leak in root", map[string]string{"leaked.env": "API=tok123\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, sha1, findings[0].Commit)
}

func TestHistoryScan_LineContext(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"conf.yml": "a: 1\nb: 2\ntoken: tok123\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, 3, findings[0].Line)
}

func TestHistoryScan_ModifiedBlobReportedAtItsCommit(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1: clean", map[string]string{"readme.md": "hi\n"})
	sha2 := historyCommit(t, dir, "c2: leak", map[string]string{"leaked.env": "API=tok123\n"})
	sha3 := historyCommit(t, dir, "c3: edit around leak", map[string]string{"leaked.env": "# edited\nAPI=tok123\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	commits := []string{findings[0].Commit, findings[1].Commit}
	assert.ElementsMatch(t, []string{sha2, sha3}, commits)
}

func TestHistoryScan_RenameNotRereported(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	sha2 := historyCommit(t, dir, "c2: leak", map[string]string{"leaked.env": "API=tok123\n"})
	runGit(t, dir, "mv", "leaked.env", "moved.env")
	runGit(t, dir, "-c", "user.email=skret-test@example.com", "-c", "user.name=skret-test", "commit", "-m", "c3: rename")

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 1) // identical blob: not re-reported after rename
	assert.Equal(t, sha2, findings[0].Commit)
	assert.Equal(t, "leaked.env", findings[0].File)
}

func TestHistoryScan_DeletedFile(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	sha2 := historyCommit(t, dir, "c2: leak", map[string]string{"leaked.env": "API=tok123\n"})
	require.NoError(t, os.Remove(filepath.Join(dir, "leaked.env")))
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "-c", "user.email=skret-test@example.com", "-c", "user.name=skret-test", "commit", "-m", "c3: delete")

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, sha2, findings[0].Commit)
}

func TestHistoryScan_BinarySkipped(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"blob.bin": "\x00\x01tok123\x00"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestHistoryScan_MaxCountBoundsWalk(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1: leak", map[string]string{"leaked.env": "API=tok123\n"})
	historyCommit(t, dir, "c2", map[string]string{"readme.md": "hi\n"})
	historyCommit(t, dir, "c3", map[string]string{"readme.md": "hi\nthere\n"})

	bounded, err := HistoryScan(historyTargets(), dir, HistoryOpts{MaxCount: 1})
	require.NoError(t, err)
	assert.Empty(t, bounded, "secret predates the 1-commit window")

	full, err := HistoryScan(historyTargets(), dir, HistoryOpts{MaxCount: 3})
	require.NoError(t, err)
	assert.Len(t, full, 1)
}

func TestHistoryScan_SinceBoundsWalk(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1: leak", map[string]string{"leaked.env": "API=tok123\n"})

	future, err := HistoryScan(historyTargets(), dir, HistoryOpts{Since: "2030-01-01"})
	require.NoError(t, err)
	assert.Empty(t, future, "no commits after 2030")

	past, err := HistoryScan(historyTargets(), dir, HistoryOpts{Since: "2000-01-01"})
	require.NoError(t, err)
	assert.Len(t, past, 1)
}

func TestHistoryScan_MinLengthFiltersTargets(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"leaked.env": "API=tok123\n"})

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{Opts: Opts{MinLength: 100}})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestHistoryScan_EmptyRepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init") // no commits yet

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestHistoryScan_NotARepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()

	_, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git rev-parse")
}
