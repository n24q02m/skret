package scanner

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWalkFilesNonGitDir(t *testing.T) {
	dir := t.TempDir()
	keep := writeFile(t, dir, "keep.txt", "data\n")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	gitCfg := filepath.Join(dir, ".git", "config")
	require.NoError(t, os.WriteFile(gitCfg, []byte("[core]\n"), 0o600))

	files, err := TrackedFiles(dir)
	require.NoError(t, err)
	require.Contains(t, files, keep)
	require.NotContains(t, files, gitCfg)
}

func TestTrackedAndStagedFilesGit(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	keep := writeFile(t, dir, "keep.txt", "keep\n")
	ignored := writeFile(t, dir, "ignored.txt", "ignored\n")
	gitignore := writeFile(t, dir, ".gitignore", "ignored.txt\n")

	runGit(t, dir, "init")
	runGit(t, dir, "add", "-A")

	tracked, err := TrackedFiles(dir)
	require.NoError(t, err)
	require.Contains(t, tracked, keep)
	require.Contains(t, tracked, gitignore)
	require.NotContains(t, tracked, ignored)

	staged, err := StagedFiles(dir)
	require.NoError(t, err)
	require.Contains(t, staged, keep)
	require.Contains(t, staged, gitignore)
	require.NotContains(t, staged, ignored)
}

func TestStagedFilesNonGitDir(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	_, err := StagedFiles(dir)
	require.Error(t, err)
}

func TestWalkFilesMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	files, err := walkFiles(missing)
	require.NoError(t, err)
	require.Empty(t, files)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := osexec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(
		os.Environ(),
		"GIT_CONFIG_GLOBAL=",
		"GIT_CONFIG_SYSTEM=",
	)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v: %s", args, out)
}

func TestTrackedFiles(t *testing.T) {
	t.Run("git repository", func(t *testing.T) {
		if _, err := osexec.LookPath("git"); err != nil {
			t.Skip("git not available")
		}
		dir := t.TempDir()
		keep := writeFile(t, dir, "keep.txt", "keep\n")
		writeFile(t, dir, "ignored.txt", "ignored\n")
		writeFile(t, dir, ".gitignore", "ignored.txt\n")

		runGit(t, dir, "init")
		runGit(t, dir, "add", "-A")

		tracked, err := TrackedFiles(dir)
		require.NoError(t, err)
		require.Contains(t, tracked, keep)
		require.NotContains(t, tracked, filepath.Join(dir, "ignored.txt"))
	})

	t.Run("non-git directory", func(t *testing.T) {
		dir := t.TempDir()
		f1 := writeFile(t, dir, "f1.txt", "1")
		f2 := writeFile(t, dir, "f2.txt", "2")

		files, err := TrackedFiles(dir)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{f1, f2}, files)
	})

	t.Run("empty git repository", func(t *testing.T) {
		if _, err := osexec.LookPath("git"); err != nil {
			t.Skip("git not available")
		}
		dir := t.TempDir()
		runGit(t, dir, "init")

		tracked, err := TrackedFiles(dir)
		require.NoError(t, err)
		require.Empty(t, tracked)
	})

	t.Run("non-existent directory", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "ghost")
		files, err := TrackedFiles(missing)
		// walkFiles (fallback) uses filepath.WalkDir which does not error
		// if the root doesn't exist, it just returns nil.
		require.NoError(t, err)
		require.Empty(t, files)
	})
}

// force-commit: update PR title
