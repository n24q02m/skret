package scanner

import (
	"fmt"
	"strings"
)

// StagedBlob is one path staged for the next commit, with the content read
// from the index rather than the working tree, so an edit made after
// `git add` cannot hide what is about to be committed.
type StagedBlob struct {
	Path    string     // repo-relative, forward slashes, as git reports it
	Content []byte     // the staged text; nil when Skipped is set
	Skipped SkipReason // why Content was not read (binary, oversize, symlink or submodule), or empty
}

// newCatFileBatchFunc is newCatFileBatch, swappable in tests.
var newCatFileBatchFunc = newCatFileBatch

// StagedBlobs returns every path added, copied, modified or changed in type
// in the index of the repository containing dir, with its staged content.
// Deleted paths are not returned. Before the first commit the index is
// compared with the empty tree, so every staged file is returned. Content is
// read as LoadText reads a file. maxBytes <= 0 uses the 8 MiB default.
func StagedBlobs(dir string, maxBytes int64) ([]StagedBlob, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	raw, err := gitOutput(dir, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", "--diff-filter=ACMT")
	if err != nil {
		return nil, fmt.Errorf("git diff --cached: %w", err)
	}
	entries := parseRawDiff(raw)
	if len(entries) == 0 {
		return nil, nil
	}

	batch, err := newCatFileBatchFunc(dir)
	if err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	defer batch.close() //nolint:errcheck // best-effort teardown; read errors already surfaced

	out := make([]StagedBlob, 0, len(entries))
	for _, e := range entries {
		b := StagedBlob{Path: e.path, Skipped: SkipNotRegular}
		if e.mode == "100644" || e.mode == "100755" {
			raw, status, err := batch.blob(e.sha, maxBytes)
			if err != nil {
				return nil, err
			}
			switch status {
			case blobRead:
				b.Content, b.Skipped = textContent(raw)
			case blobTooLarge:
				b.Skipped = SkipOversize
			default:
				return nil, fmt.Errorf("git cat-file: staged object %s for %q is missing or not a blob", e.sha, e.path)
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// rawEntry is the post-image of one `git diff --raw -z` record.
type rawEntry struct {
	mode string
	sha  string
	path string
}

// parseRawDiff reads `git diff --raw -z --no-renames` output: each record is
// ":<old mode> <new mode> <old sha> <new sha> <status>" NUL "<path>" NUL.
func parseRawDiff(raw []byte) []rawEntry {
	parts := strings.Split(string(raw), "\x00")
	var out []rawEntry
	for i := 0; i+1 < len(parts); i++ {
		meta := parts[i]
		if !strings.HasPrefix(meta, ":") {
			continue
		}
		path := parts[i+1]
		i++
		fields := strings.Fields(meta)
		if len(fields) < 5 {
			continue
		}
		out = append(out, rawEntry{mode: fields[1], sha: fields[3], path: path})
	}
	return out
}
