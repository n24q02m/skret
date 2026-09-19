package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultHistoryMaxCount bounds the history walk when --max-count is not set,
// so scanning a large repository cannot turn into an unbounded job.
const DefaultHistoryMaxCount = 1000

// HistoryOpts controls HistoryScan.
type HistoryOpts struct {
	Opts // MinLength, MaxBytes

	MaxCount int    // cap on commits walked (<=0 -> DefaultHistoryMaxCount)
	Since    string // optional git --since expression (e.g. "2 weeks ago")
}

// HistoryScan scans committed blob content across the git history of dir,
// oldest commit first, reporting each managed value once — at the commit that
// introduced the blob containing it. Findings reuse the Finding shape, with
// Commit set and File holding the repo-relative path as git reports it.
//
// Efficiency and memory bounds:
//   - the walk is capped at opts.MaxCount commits (default DefaultHistoryMaxCount);
//   - each unique blob is scanned exactly once (deduped by object id), so a
//     secret carried forward through later commits is attributed to its
//     introducing commit instead of re-reported;
//   - blob content streams through one `git cat-file --batch` process, one
//     blob in memory at a time; binary and oversize blobs are skipped.
func HistoryScan(targets []Target, dir string, opts HistoryOpts) ([]Finding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	maxCount := opts.MaxCount
	if maxCount <= 0 {
		maxCount = DefaultHistoryMaxCount
	}
	active := make([]Target, 0, len(targets))
	for _, t := range targets {
		if len(t.Value) >= opts.MinLength {
			active = append(active, t)
		}
	}
	if len(active) == 0 {
		return nil, nil
	}

	commits, err := historyCommits(dir, maxCount, opts.Since)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	// Walk oldest -> newest so the first sighting of a blob is the commit
	// that introduced it (rev-list output is newest first).
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}

	batch, err := newCatFileBatch(dir)
	if err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	defer batch.close() //nolint:errcheck // best-effort teardown; read errors already surfaced

	seen := make(map[string]struct{})
	var findings []Finding
	for _, commit := range commits {
		blobs, err := commitBlobs(dir, commit)
		if err != nil {
			return nil, err
		}
		for _, b := range blobs {
			if _, done := seen[b.sha]; done {
				continue
			}
			seen[b.sha] = struct{}{}
			content, ok, err := batch.blob(b.sha, maxBytes)
			if err != nil {
				return nil, err
			}
			if !ok || isBinaryContent(content) {
				continue
			}
			for _, f := range scanContent(b.path, content, active) {
				f.Commit = commit
				findings = append(findings, f)
			}
		}
	}

	sortFindings(findings)
	return findings, nil
}

// historyCommits lists HEAD-reachable commit shas, newest first, capped at
// maxCount and optionally filtered by a git --since expression.
func historyCommits(dir string, maxCount int, since string) ([]string, error) {
	args := []string{"rev-list", "--max-count=" + strconv.Itoa(maxCount)}
	if since != "" {
		args = append(args, "--since="+since)
	}
	args = append(args, "HEAD")
	raw, err := gitOutput(dir, args...)
	if err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// blobRef is a blob reachable from one commit's tree delta: its object id and
// the repo-relative path it is reachable under.
type blobRef struct {
	sha  string
	path string
}

// commitBlobs returns the blobs added or changed by commit (vs its first
// parent; the root commit counts every file via --root). Merge commits yield
// nothing, which is correct here: every blob they carry was introduced by some
// non-merge commit that the walk also visits.
func commitBlobs(dir, commit string) ([]blobRef, error) {
	raw, err := gitOutput(dir, "diff-tree", "--root", "-r", "--no-commit-id", "-z", commit)
	if err != nil {
		return nil, fmt.Errorf("git diff-tree %s: %w", commit, err)
	}
	parts := strings.Split(string(raw), "\x00")
	out := make([]blobRef, 0, len(parts)/2)
	for i := 0; i < len(parts)-1; i++ {
		meta := parts[i]
		if !strings.HasPrefix(meta, ":") {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) < 5 {
			continue
		}
		sha, status, newMode := fields[3], fields[4], fields[2]
		path := parts[i+1]
		i++
		if status[0] == 'R' || status[0] == 'C' {
			// -z rename/copy entries carry old and new path; the finding
			// belongs under the path the blob is reachable as now.
			path = parts[i+1]
			i++
		}
		if isZeroOID(sha) || newMode == "160000" {
			continue // deleted entry or submodule gitlink: no blob content
		}
		out = append(out, blobRef{sha: sha, path: path})
	}
	return out, nil
}

func isZeroOID(oid string) bool { return strings.Trim(oid, "0") == "" }

func isBinaryContent(content []byte) bool {
	if len(content) > binarySniff {
		content = content[:binarySniff]
	}
	return bytes.IndexByte(content, 0) >= 0
}

// sortFindings orders findings deterministically: commit, then file, line, key.
func sortFindings(findings []Finding) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && lessFinding(findings[j], findings[j-1]); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

func lessFinding(a, b Finding) bool {
	if a.Commit != b.Commit {
		return a.Commit < b.Commit
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Key < b.Key
}

// gitOutput runs git in dir and returns stdout; on failure the error carries
// git's stderr so misconfiguration (not a repo, bad --since) is diagnosable.
func gitOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	return raw, nil
}

// catFileBatch streams blob content through one long-lived
// `git cat-file --batch` process instead of one process per blob.
type catFileBatch struct {
	cmd      *exec.Cmd
	stdin    *bufio.Writer
	inCloser io.WriteCloser
	stdout   *bufio.Reader
}

func newCatFileBatch(dir string) (*catFileBatch, error) {
	cmd := exec.CommandContext(context.Background(), "git", "cat-file", "--batch")
	cmd.Dir = dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	return &catFileBatch{
		cmd:      cmd,
		stdin:    bufio.NewWriter(stdin),
		inCloser: stdin,
		stdout:   bufio.NewReader(stdout),
	}, nil
}

// blob fetches one object. ok is false when git reports the object missing,
// the object is not a blob (e.g. a submodule commit id that happens to be
// present), or the blob exceeds maxBytes — the stream stays aligned in every
// case, so the batch can keep serving requests.
func (b *catFileBatch) blob(sha string, maxBytes int64) ([]byte, bool, error) {
	if _, err := b.stdin.WriteString(sha + "\n"); err != nil {
		return nil, false, fmt.Errorf("git cat-file: %w", err)
	}
	if err := b.stdin.Flush(); err != nil {
		return nil, false, fmt.Errorf("git cat-file: %w", err)
	}
	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, false, fmt.Errorf("git cat-file: %w", err)
	}
	fields := strings.Fields(strings.TrimSuffix(header, "\n"))
	if len(fields) < 3 {
		// "<sha> missing" / "<sha> ambiguous": no body follows.
		return nil, false, nil
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("git cat-file: bad header %q", strings.TrimSpace(header))
	}
	if fields[1] != "blob" || (maxBytes > 0 && size > maxBytes) {
		_, _ = io.CopyN(io.Discard, b.stdout, size+1) // trailing LF keeps the stream aligned
		return nil, false, nil
	}
	body := make([]byte, size+1)
	if _, err := io.ReadFull(b.stdout, body); err != nil {
		return nil, false, fmt.Errorf("git cat-file: read %s: %w", sha, err)
	}
	return body[:size], true, nil
}

// close ends the batch: closing stdin makes git cat-file exit.
func (b *catFileBatch) close() error {
	_ = b.stdin.Flush()
	_ = b.inCloser.Close()
	return b.cmd.Wait()
}
