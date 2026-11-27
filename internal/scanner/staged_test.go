package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stagedByPath(blobs []StagedBlob) map[string]StagedBlob {
	out := make(map[string]StagedBlob, len(blobs))
	for _, b := range blobs {
		out[b.Path] = b
	}
	return out
}

// On a fresh repository (no commit yet) every staged file is returned with
// its staged content.
func TestStagedBlobs_UnbornHead(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o700))
	writeFile(t, dir, "a.txt", "alpha\n")
	writeFile(t, dir, filepath.Join("sub", "b.txt"), "beta\n")
	writeFile(t, dir, "untracked.txt", "not staged\n")
	runGit(t, dir, "add", "a.txt", "sub/b.txt")

	blobs, err := StagedBlobs(dir, 0)
	require.NoError(t, err)
	byPath := stagedByPath(blobs)
	require.Len(t, byPath, 2)
	assert.Equal(t, "alpha\n", string(byPath["a.txt"].Content))
	assert.Equal(t, "beta\n", string(byPath["sub/b.txt"].Content), "paths are repo-relative with forward slashes")
}

// The index, not the working tree, is what gets committed: a staged secret
// edited away afterwards is still reported, deletions are not, and files
// unchanged since HEAD are not returned.
func TestStagedBlobs_ReadsTheIndex(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"keep.txt": "same\n", "gone.txt": "bye\n", "edit.txt": "v1\n"})

	writeFile(t, dir, "edit.txt", "v2 staged\n")
	runGit(t, dir, "add", "edit.txt")
	writeFile(t, dir, "edit.txt", "v3 unstaged\n")
	runGit(t, dir, "rm", "-q", "gone.txt")

	blobs, err := StagedBlobs(dir, 0)
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Equal(t, "edit.txt", blobs[0].Path)
	assert.Equal(t, "v2 staged\n", string(blobs[0].Content))
}

// Binary, oversize and non-regular entries are still listed (so file-name
// rules apply) but carry no content.
func TestStagedBlobs_ContentlessEntries(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "bin.dat", "a\x00b")
	writeFile(t, dir, "big.txt", strings.Repeat("x", 64))
	writeFile(t, dir, "ok.txt", "fine\n")
	runGit(t, dir, "add", "bin.dat", "big.txt", "ok.txt")
	// A symlink entry, staged straight into the index so the test does not
	// depend on the platform's symlink support.
	runGit(t, dir, "update-index", "--add", "--cacheinfo", "120000,"+runGitOut(t, dir, "hash-object", "-w", "ok.txt")+",link")

	blobs, err := StagedBlobs(dir, 32)
	require.NoError(t, err)
	byPath := stagedByPath(blobs)
	require.Len(t, byPath, 4)
	assert.Nil(t, byPath["bin.dat"].Content, "binary content is not returned")
	assert.Nil(t, byPath["big.txt"].Content, "oversize content is not returned")
	assert.Nil(t, byPath["link"].Content, "symlink targets are not file content")
	assert.Equal(t, "fine\n", string(byPath["ok.txt"].Content))
}

func TestStagedBlobs_NothingStaged(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	blobs, err := StagedBlobs(dir, 0)
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestStagedBlobs_NotARepo(t *testing.T) {
	requireGit(t)
	_, err := StagedBlobs(t.TempDir(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git diff --cached")
}

func TestStagedBlobs_CatFileStartFailure(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "a.txt", "alpha\n")
	runGit(t, dir, "add", "a.txt")

	restore := newCatFileBatchFunc
	t.Cleanup(func() { newCatFileBatchFunc = restore })
	newCatFileBatchFunc = func(string) (*catFileBatch, error) { return nil, os.ErrPermission }

	_, err := StagedBlobs(dir, 0)
	require.ErrorIs(t, err, os.ErrPermission)
}

// A cat-file stream that breaks mid-read is an error, never a clean result.
func TestStagedBlobs_CatFileStreamFailure(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "a.txt", "alpha\n")
	runGit(t, dir, "add", "a.txt")

	restore := newCatFileBatchFunc
	t.Cleanup(func() { newCatFileBatchFunc = restore })
	newCatFileBatchFunc = func(d string) (*catFileBatch, error) {
		b, err := newCatFileBatch(d)
		if err == nil {
			b.stdin = bufio.NewWriter(brokenPipe{})
		}
		return b, err
	}

	blobs, err := StagedBlobs(dir, 0)
	require.Error(t, err)
	assert.Nil(t, blobs)
	assert.Contains(t, err.Error(), "git cat-file:")
}

func TestParseRawDiff(t *testing.T) {
	sha := strings.Repeat("b", 40)
	zero := strings.Repeat("0", 40)
	raw := ":000000 100644 " + zero + " " + sha + " A\x00new.txt\x00" +
		":100644 100755 " + sha + " " + sha + " M\x00tool.sh\x00" +
		"garbage\x00" +
		":short\x00ignored\x00"
	entries := parseRawDiff([]byte(raw))
	require.Len(t, entries, 2)
	assert.Equal(t, rawEntry{mode: "100644", sha: sha, path: "new.txt"}, entries[0])
	assert.Equal(t, rawEntry{mode: "100755", sha: sha, path: "tool.sh"}, entries[1])
}

func TestCandidateFiles(t *testing.T) {
	t.Run("git repository", func(t *testing.T) {
		requireGit(t)
		dir := t.TempDir()
		runGit(t, dir, "init")
		tracked := writeFile(t, dir, "tracked.txt", "t\n")
		untracked := writeFile(t, dir, "new.txt", "n\n")
		ignored := writeFile(t, dir, "ignored.txt", "i\n")
		writeFile(t, dir, ".gitignore", "ignored.txt\n")
		runGit(t, dir, "add", "tracked.txt")

		files, err := CandidateFiles(dir)
		require.NoError(t, err)
		assert.Contains(t, files, tracked)
		assert.Contains(t, files, untracked, "untracked files can still be committed")
		assert.NotContains(t, files, ignored)
	})
	t.Run("plain directory", func(t *testing.T) {
		dir := t.TempDir()
		keep := writeFile(t, dir, "keep.txt", "k\n")
		files, err := CandidateFiles(dir)
		require.NoError(t, err)
		assert.Equal(t, []string{keep}, files)
	})
}

func TestLoadText(t *testing.T) {
	dir := t.TempDir()
	text := writeFile(t, dir, "text.txt", "hello\n")
	bin := writeFile(t, dir, "bin.dat", "a\x00b")
	big := writeFile(t, dir, "big.txt", strings.Repeat("x", 64))

	content, err := LoadText(text, 0)
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(content))

	content, err = LoadText(bin, 0)
	require.NoError(t, err)
	assert.Nil(t, content)

	content, err = LoadText(big, 32)
	require.NoError(t, err)
	assert.Nil(t, content)

	content, err = LoadText(dir, 0)
	require.NoError(t, err)
	assert.Nil(t, content, "a directory has no content")

	_, err = LoadText(filepath.Join(dir, "missing"), 0)
	require.Error(t, err)

	t.Run("unreadable file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file mode bits do not restrict reads on Windows")
		}
		unreadable := writeFile(t, dir, "locked.txt", "x\n")
		require.NoError(t, os.Chmod(unreadable, 0o000))
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
		if _, err := os.ReadFile(unreadable); err == nil {
			t.Skip("running with privileges that bypass file permissions")
		}
		_, err := LoadText(unreadable, 0)
		require.Error(t, err)
	})
}
