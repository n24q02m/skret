package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLessFinding_Ordering(t *testing.T) {
	base := Finding{Key: "TOKEN", File: "a.env", Line: 1, Commit: "c1"}
	tests := []struct {
		name string
		a, b Finding
		want bool
	}{
		{"commit ascending", Finding{Commit: "a"}, Finding{Commit: "b"}, true},
		{"commit descending", Finding{Commit: "b"}, Finding{Commit: "a"}, false},
		{"file tiebreak", Finding{Commit: "c", File: "a"}, Finding{Commit: "c", File: "b"}, true},
		{"line tiebreak", Finding{Commit: "c", File: "f", Line: 1}, Finding{Commit: "c", File: "f", Line: 2}, true},
		{"key tiebreak", Finding{Commit: "c", File: "f", Line: 1, Key: "A"}, Finding{Commit: "c", File: "f", Line: 1, Key: "B"}, true},
		{"equal", base, Finding{Key: "TOKEN", File: "a.env", Line: 1, Commit: "c1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, lessFinding(tt.a, tt.b))
		})
	}
}

func TestSortFindings_Deterministic(t *testing.T) {
	findings := []Finding{
		{Key: "B", File: "z", Line: 1, Commit: "c2"},
		{Key: "A", File: "z", Line: 1, Commit: "c2"},
		{Key: "A", File: "a", Line: 9, Commit: "c1"},
	}
	sortFindings(findings)
	assert.Equal(t, []Finding{
		{Key: "A", File: "a", Line: 9, Commit: "c1"},
		{Key: "A", File: "z", Line: 1, Commit: "c2"},
		{Key: "B", File: "z", Line: 1, Commit: "c2"},
	}, findings)
}

func TestIsBinaryContent(t *testing.T) {
	assert.True(t, isBinaryContent([]byte{0x00, 0x01}), "NUL in sniff window")
	assert.False(t, isBinaryContent([]byte("plain text")), "text")
	// NUL beyond the sniff window does not mark the content binary.
	big := bytes.Repeat([]byte("a"), binarySniff+16)
	big[binarySniff+8] = 0
	assert.False(t, isBinaryContent(big))
	big[binarySniff-1] = 0
	assert.True(t, isBinaryContent(big), "NUL at sniff-window edge")
}

func TestRenderTable_WithAndWithoutCommit(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, RenderTable(&out, []Finding{{Key: "TOKEN", File: "a.env", Line: 3}}))
	assert.Equal(t, "KEY    FILE   LINE\nTOKEN  a.env  3\n", out.String())

	out.Reset()
	require.NoError(t, RenderTable(&out, []Finding{{Key: "TOKEN", File: "a.env", Line: 3, Commit: "abc"}}))
	assert.Equal(t, "KEY    FILE   LINE  COMMIT\nTOKEN  a.env  3     abc\n", out.String())
}

func TestRenderJSON_CommitField(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, RenderJSON(&out, []Finding{{Key: "TOKEN", File: "a.env", Line: 1, Commit: "abc"}}))
	assert.JSONEq(t, `[{"key":"TOKEN","file":"a.env","line":1,"commit":"abc"}]`, out.String())
}

// TestCatFileBatch_Kinds exercises the batch reader's response kinds directly:
// a real blob, a missing object, a non-blob object (drained, not served), and
// an oversize blob (drained, not served), then verifies the stream stays
// aligned afterwards.
func TestCatFileBatch_Kinds(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{
		"real.txt": "hello\n",
		"big.txt":  strings.Repeat("x", 128) + "\n",
	})

	blobSha := runGitOut(t, dir, "rev-parse", "HEAD:real.txt")
	bigSha := runGitOut(t, dir, "rev-parse", "HEAD:big.txt")
	headSha := runGitOut(t, dir, "rev-parse", "HEAD") // a commit object, not a blob
	missingSha := strings.Repeat("f", 40)

	batch, err := newCatFileBatch(dir)
	require.NoError(t, err)
	defer func() { _ = batch.close() }()

	content, ok, err := batch.blob(blobSha, 8<<20)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "hello\n", string(content))

	// Missing object: not served, no body.
	_, ok, err = batch.blob(missingSha, 8<<20)
	require.NoError(t, err)
	assert.False(t, ok)

	// Non-blob object: drained so the stream stays aligned.
	_, ok, err = batch.blob(headSha, 8<<20)
	require.NoError(t, err)
	assert.False(t, ok)

	// Oversize blob beyond maxBytes: drained, not served.
	_, ok, err = batch.blob(bigSha, 64)
	require.NoError(t, err)
	assert.False(t, ok)

	// Stream still aligned: the real blob reads correctly again.
	content, ok, err = batch.blob(blobSha, 8<<20)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "hello\n", string(content))
}

func TestCommitBlobs_RenamesAndDeletes(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	historyCommit(t, dir, "c1", map[string]string{"old.env": "value\n"})

	// Rename with content change: R entry whose dst blob must be parsed.
	require.NoError(t, os.Remove(filepath.Join(dir, "old.env")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new.env"), []byte("changed value\n"), 0o600))
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "-c", "user.email=skret-test@example.com", "-c", "user.name=skret-test", "commit", "-m", "c2: rename+edit")

	blobs, err := commitBlobs(dir, runGitOut(t, dir, "rev-parse", "HEAD"))
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Equal(t, "new.env", blobs[0].path)
	dstSha := blobs[0].sha
	assert.NotEqual(t, strings.Repeat("0", 40), dstSha)

	// The dst blob resolves through the batch reader.
	batch, err := newCatFileBatch(dir)
	require.NoError(t, err)
	defer func() { _ = batch.close() }()
	content, ok, err := batch.blob(dstSha, 8<<20)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "changed value\n", string(content))
}
