package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// TrackedFiles lists git-tracked files under dir (respects .gitignore). If dir
// is not a git repo or git is unavailable, it walks dir, skipping .git/.
func TrackedFiles(dir string) ([]string, error) {
	if out, err := gitLines(dir, "ls-files", "-z"); err == nil {
		return out, nil
	}
	return walkFiles(dir)
}

// CandidateFiles lists the files under dir that could be committed: tracked
// files plus untracked files that .gitignore does not exclude. If dir is not
// a git repo or git is unavailable, it walks dir, skipping .git/.
func CandidateFiles(dir string) ([]string, error) {
	if out, err := gitLines(dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard"); err == nil {
		return out, nil
	}
	return walkFiles(dir)
}

// SkipReason says why the content of a file was not read. The empty value
// means it was read.
type SkipReason string

const (
	// SkipOversize: the file is larger than the size limit.
	SkipOversize SkipReason = "oversize"
	// SkipBinary: a NUL byte in the first 8 KiB, after UTF-16 decoding.
	SkipBinary SkipReason = "binary"
	// SkipNotRegular: a directory, symlink, submodule, pipe or device.
	SkipNotRegular SkipReason = "not-regular"
)

// LoadText returns the text content of the file at path. Content that is not
// read is nil, with the reason: path is not a regular file (symlinks are
// followed), is larger than maxBytes, or is binary. UTF-16 with a byte order
// mark is decoded to UTF-8 before the binary check. maxBytes <= 0 uses the
// 8 MiB default.
func LoadText(path string, maxBytes int64) ([]byte, SkipReason, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, SkipNotRegular, nil
	}
	if info.Size() > maxBytes {
		return nil, SkipOversize, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	content, skipped := textContent(raw)
	return content, skipped, nil
}

// textContent returns raw as text: UTF-16 with a byte order mark is decoded
// to UTF-8, and content with a NUL byte in its first 8 KiB is binary.
func textContent(raw []byte) ([]byte, SkipReason) {
	if decoded, ok := decodeUTF16(raw); ok {
		raw = decoded
	}
	if isBinaryContent(raw) {
		return nil, SkipBinary
	}
	return raw, ""
}

// decodeUTF16 decodes raw to UTF-8 when it starts with a UTF-16 byte order
// mark. A trailing odd byte is not a whole code unit and is dropped.
func decodeUTF16(raw []byte) ([]byte, bool) {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}):
		order = binary.LittleEndian
	case bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		order = binary.BigEndian
	default:
		return nil, false
	}
	units := make([]uint16, (len(raw)-2)/2)
	for i := range units {
		units[i] = order.Uint16(raw[2+2*i:])
	}
	return []byte(string(utf16.Decode(units))), true
}

// StagedFiles lists added/copied/modified staged files under dir.
func StagedFiles(dir string) ([]string, error) {
	return gitLines(dir, "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
}

func gitLines(dir string, args ...string) ([]string, error) {
	cmd := osexec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, filepath.Join(dir, p))
	}
	return out, nil
}

func walkFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entry: skip it, keep walking
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out, err
}
