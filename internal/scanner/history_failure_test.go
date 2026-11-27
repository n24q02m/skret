package scanner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// removeObject deletes the loose object file for oid from the repository in
// dir, simulating a corrupt or partially copied clone.
func removeObject(t *testing.T, dir, oid string) {
	t.Helper()
	path := filepath.Join(dir, ".git", "objects", oid[:2], oid[2:])
	require.FileExists(t, path, "precondition: %s must be a loose object", oid)
	require.NoError(t, os.Chmod(path, 0o600)) // git writes objects read-only
	require.NoError(t, os.Remove(path))
}

// A history whose commit chain is broken (a parent commit object is gone)
// fails the scan with the rev-list error instead of reporting a clean,
// shortened history.
func TestHistoryScan_BrokenCommitChainIsAnError(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	first := historyCommit(t, dir, "c1", map[string]string{"a.env": "TOKEN=tok123\n"})
	historyCommit(t, dir, "c2", map[string]string{"b.txt": "clean\n"})
	removeObject(t, dir, first)

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "git rev-list")
}

// A commit whose tree object is gone fails the scan with the diff-tree
// error instead of skipping the commit and its blobs.
func TestHistoryScan_MissingTreeIsAnError(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	head := historyCommit(t, dir, "c1", map[string]string{"a.env": "TOKEN=tok123\n"})
	removeObject(t, dir, runGitOut(t, dir, "rev-parse", "HEAD^{tree}"))

	findings, err := HistoryScan(historyTargets(), dir, HistoryOpts{})
	require.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "git diff-tree "+head)
}

// The cat-file batch reports a process that cannot start (here: its working
// directory does not exist) instead of returning a batch that never answers.
func TestNewCatFileBatch_StartFailure(t *testing.T) {
	batch, err := newCatFileBatch(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	assert.Nil(t, batch)
}

// brokenPipe is a cat-file stdin whose reader has gone away.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A cat-file process that dies mid-stream surfaces an error on every step
// of the exchange; the caller never gets a truncated or empty blob as if it
// were the real content.
func TestCatFileBatch_StreamFailures(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tests := []struct {
		name   string
		stdin  *bufio.Writer
		stdout string
	}{
		// The request does not fit the buffer, so the write itself flushes
		// into the broken pipe.
		{"request write fails", bufio.NewWriterSize(brokenPipe{}, 16), ""},
		{"request flush fails", bufio.NewWriter(brokenPipe{}), ""},
		{"no header", bufio.NewWriter(io.Discard), ""},
		{"truncated body", bufio.NewWriter(io.Discard), sha + " blob 10\nabc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &catFileBatch{stdin: tt.stdin, stdout: bufio.NewReader(strings.NewReader(tt.stdout))}
			content, status, err := b.blob(sha, 8<<20)
			require.Error(t, err)
			assert.Equal(t, blobAbsent, status)
			assert.Nil(t, content)
			assert.Contains(t, err.Error(), "git cat-file:")
		})
	}
}
