//go:build !windows

package syncer

import (
	"os"
	"path/filepath"
	"sort"
)

func scanStateManifestRoot(root string) ([]StateManifestFile, error) {
	files := make([]StateManifestFile, 0)
	directories := make(map[string]os.FileInfo)
	err := filepath.WalkDir(root, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil {
			return stateManifestError("source root scan failed")
		}
		info, err := entry.Info()
		if err != nil {
			return stateManifestError("source root scan failed")
		}
		if unsafeStateManifestMode(entry.Type()) || unsafeStateManifestMode(info.Mode()) {
			return stateManifestError("unsafe source entries are not allowed")
		}
		if currentPath == root {
			if !info.IsDir() {
				return stateManifestError("invalid source root")
			}
			directories[currentPath] = info
			return nil
		}
		if info.IsDir() {
			directories[currentPath] = info
			return nil
		}
		if !info.Mode().IsRegular() {
			return stateManifestError("non-regular entries are not allowed")
		}
		relative, err := filepath.Rel(root, currentPath)
		if err != nil {
			return stateManifestError("source path resolution failed")
		}
		normalized := filepath.ToSlash(relative)
		if !validStateManifestPath(normalized) {
			return stateManifestError("invalid file path")
		}
		size, digest, err := hashStateManifestFile(currentPath, info)
		if err != nil {
			return err
		}
		files = append(files, StateManifestFile{Path: normalized, Size: size, SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := revalidateStateManifestDirectories(directories); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, stateManifestError("source root is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}
