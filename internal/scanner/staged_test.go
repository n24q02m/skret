package scanner

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

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

// utf16File encodes s as UTF-16 in the given byte order, with a byte order
// mark, as Windows tools commonly save text.
func utf16File(s string, order binary.ByteOrder) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2+2*len(units))
	order.PutUint16(out, 0xFEFF)
	for i, u := range units {
		order.PutUint16(out[2+2*i:], u)
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
// rules apply) but carry no content, and say why it was not read.
func TestStagedBlobs_SkippedEntries(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	writeFile(t, dir, "bin.dat", "a\x00b")
	writeFile(t, dir, "big.txt", strings.Repeat("x", 64))
	writeFile(t, dir, "ok.txt", "fine\n")
	runGit(t, dir, "add", "bin.dat", "big.txt", "ok.txt")
	// A symlink and a submodule entry, staged straight into the index so the
	// test does not depend on the platform's symlink support or on a second
	// repository.
	okSha := runGitOut(t, dir, "hash-object", "-w", "ok.txt")
	runGit(t, dir, "update-index", "--add", "--cacheinfo", "120000,"+okSha+",link")
	runGit(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("c", 40)+",vendor/lib")

	blobs, err := StagedBlobs(dir, 32)
	require.NoError(t, err)
	byPath := stagedByPath(blobs)
	require.Len(t, byPath, 5)
	for path, want := range map[string]SkipReason{
		"bin.dat":    SkipBinary,
		"big.txt":    SkipOversize,
		"link":       SkipNotRegular,
		"vendor/lib": SkipNotRegular,
	} {
		assert.Nil(t, byPath[path].Content, path)
		assert.Equal(t, want, byPath[path].Skipped, path)
	}
	assert.Equal(t, "fine\n", string(byPath["ok.txt"].Content))
	assert.Empty(t, byPath["ok.txt"].Skipped)
}

// UTF-16 with a byte order mark is text, not binary: it is decoded to UTF-8
// so the line rules can match it.
func TestStagedBlobs_DecodesUTF16(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	text := "line one\nline two\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "le.txt"), utf16File(text, binary.LittleEndian), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "be.txt"), utf16File(text, binary.BigEndian), 0o600))
	runGit(t, dir, "add", "le.txt", "be.txt")

	blobs, err := StagedBlobs(dir, 0)
	require.NoError(t, err)
	byPath := stagedByPath(blobs)
	for _, path := range []string{"le.txt", "be.txt"} {
		assert.Equal(t, text, string(byPath[path].Content), path)
		assert.Empty(t, byPath[path].Skipped, path)
	}
}

// A regular index entry whose object is missing cannot be checked, and git
// could not commit it either: that is an error, not a silently empty file.
func TestStagedBlobs_MissingObject(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "update-index", "--add", "--info-only", "--cacheinfo", "100644,"+strings.Repeat("d", 40)+",ghost.txt")

	blobs, err := StagedBlobs(dir, 0)
	require.Error(t, err)
	assert.Nil(t, blobs)
	assert.Contains(t, err.Error(), "ghost.txt")
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

	content, skipped, err := LoadText(text, 0)
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(content))
	assert.Empty(t, skipped)

	content, skipped, err = LoadText(bin, 0)
	require.NoError(t, err)
	assert.Nil(t, content)
	assert.Equal(t, SkipBinary, skipped)

	content, skipped, err = LoadText(big, 32)
	require.NoError(t, err)
	assert.Nil(t, content)
	assert.Equal(t, SkipOversize, skipped)

	content, skipped, err = LoadText(dir, 0)
	require.NoError(t, err)
	assert.Nil(t, content, "a directory has no content")
	assert.Equal(t, SkipNotRegular, skipped)

	_, _, err = LoadText(filepath.Join(dir, "missing"), 0)
	require.Error(t, err)

	t.Run("UTF-16 with a byte order mark", func(t *testing.T) {
		for name, order := range map[string]binary.ByteOrder{"le.txt": binary.LittleEndian, "be.txt": binary.BigEndian} {
			p := filepath.Join(dir, name)
			// A trailing odd byte is not a whole code unit and is dropped.
			require.NoError(t, os.WriteFile(p, append(utf16File("café\nok\n", order), 'x'), 0o600))
			content, skipped, err := LoadText(p, 0)
			require.NoError(t, err)
			assert.Equal(t, "café\nok\n", string(content), name)
			assert.Empty(t, skipped, name)
		}
		// A byte order mark in front of NUL code units (UTF-32, or binary
		// data that happens to start with one) is still binary.
		p := filepath.Join(dir, "utf32.txt")
		require.NoError(t, os.WriteFile(p, []byte{0xFF, 0xFE, 0, 0, 'A', 0, 0, 0}, 0o600))
		content, skipped, err := LoadText(p, 0)
		require.NoError(t, err)
		assert.Nil(t, content)
		assert.Equal(t, SkipBinary, skipped)
	})

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
		_, _, err := LoadText(unreadable, 0)
		require.Error(t, err)
	})
}
