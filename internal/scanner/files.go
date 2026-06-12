package scanner

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
)

// TrackedFiles lists git-tracked files under dir (respects .gitignore). If dir
// is not a git repo or git is unavailable, it walks dir, skipping .git/.
func TrackedFiles(dir string) ([]string, error) {
	if out, err := gitLines(dir, "ls-files", "-z"); err == nil {
		return out, nil
	}
	return walkFiles(dir)
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
