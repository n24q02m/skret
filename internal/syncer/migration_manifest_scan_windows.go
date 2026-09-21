//go:build windows

package syncer

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	windowsStateManifestFinalPathInitialSize = 256
	windowsStateManifestFinalPathMaxSize     = 32768
)

func canonicalStateManifestRootPath(root string) (string, error) {
	return filepath.Clean(root), nil
}

func scanStateManifestRoot(root string) ([]StateManifestFile, error) {
	expectedRoot, err := os.Lstat(root)
	if err != nil || expectedRoot == nil || unsafeStateManifestMode(expectedRoot.Mode()) || !expectedRoot.IsDir() {
		return nil, stateManifestError("invalid source root")
	}

	stableRoot, err := openWindowsStateManifestRoot(root, expectedRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stableRoot.Close() }()

	files := make([]StateManifestFile, 0)
	if err := scanWindowsStateManifestDirectory(stableRoot.root, stableRoot.finalPath, "", stableRoot.finalPath, &files); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, stateManifestError("source root is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

type windowsStateManifestRoot struct {
	root      *os.File
	finalPath string
	handles   []*os.File
}

func (root *windowsStateManifestRoot) Close() error {
	if root == nil {
		return nil
	}
	var firstErr error
	for index := len(root.handles) - 1; index >= 0; index-- {
		if err := root.handles[index].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	root.handles = nil
	root.root = nil
	return firstErr
}

func openWindowsStateManifestRoot(root string, expectedRoot os.FileInfo) (stable *windowsStateManifestRoot, err error) {
	if expectedRoot == nil || unsafeStateManifestMode(expectedRoot.Mode()) || !expectedRoot.IsDir() {
		return nil, stateManifestError("invalid source root")
	}
	volumeRoot, components, err := windowsStateManifestPathComponents(root)
	if err != nil {
		return nil, stateManifestError("invalid source root")
	}

	stable = &windowsStateManifestRoot{}
	defer func() {
		if err != nil {
			_ = stable.Close()
		}
	}()

	volumeHandle, err := openWindowsStateManifestHandle(volumeRoot)
	if err != nil {
		return nil, stateManifestError("source root scan failed")
	}
	stable.handles = append(stable.handles, volumeHandle)
	volumeInfo, err := volumeHandle.Stat()
	if err != nil || volumeInfo == nil || unsafeStateManifestMode(volumeInfo.Mode()) || !volumeInfo.IsDir() {
		return nil, stateManifestError("invalid source root")
	}
	parent := volumeHandle
	parentFinalPath, err := windowsStateManifestFinalPath(parent)
	if err != nil || parentFinalPath == "" {
		return nil, stateManifestError("source root scan failed")
	}

	for _, component := range components {
		childPath := filepath.Join(parentFinalPath, component)
		child, childErr := openWindowsStateManifestHandle(childPath)
		if childErr != nil {
			return nil, stateManifestError("source root scan failed")
		}
		childInfo, statErr := child.Stat()
		if statErr != nil || childInfo == nil || unsafeStateManifestMode(childInfo.Mode()) {
			_ = child.Close()
			return nil, stateManifestError("unsafe source roots are not allowed")
		}
		expectedChild, lstatErr := os.Lstat(childPath)
		if lstatErr != nil || expectedChild == nil || unsafeStateManifestMode(expectedChild.Mode()) ||
			!os.SameFile(expectedChild, childInfo) {
			_ = child.Close()
			return nil, stateManifestError("source root changed during scan")
		}
		childFinalPath, finalPathErr := windowsStateManifestFinalPath(child)
		if finalPathErr != nil || !windowsStateManifestPathWithinRoot(parentFinalPath, childFinalPath) {
			_ = child.Close()
			return nil, stateManifestError("source root changed during scan")
		}
		stable.handles = append(stable.handles, child)
		parent = child
		parentFinalPath = childFinalPath
	}

	openedRoot, err := parent.Stat()
	if err != nil || openedRoot == nil || unsafeStateManifestMode(openedRoot.Mode()) ||
		!openedRoot.IsDir() || !os.SameFile(expectedRoot, openedRoot) {
		return nil, stateManifestError("source root changed during scan")
	}
	stable.root = parent
	stable.finalPath = parentFinalPath
	return stable, nil
}

func windowsStateManifestPathComponents(root string) (string, []string, error) {
	cleaned := filepath.Clean(strings.ReplaceAll(root, "/", "\\"))
	for _, prefix := range []string{`\\?\UNC\`, `\\.\UNC\`} {
		if len(cleaned) < len(prefix) || !strings.EqualFold(cleaned[:len(prefix)], prefix) {
			continue
		}
		parts := strings.Split(strings.TrimLeft(cleaned[len(prefix):], "\\"), "\\")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", nil, os.ErrInvalid
		}
		volumeRoot := prefix + parts[0] + "\\" + parts[1] + "\\"
		components := parts[2:]
		for _, part := range components {
			if part == "" || part == "." || part == ".." {
				return "", nil, os.ErrInvalid
			}
		}
		return volumeRoot, components, nil
	}

	volume := filepath.VolumeName(cleaned)
	if volume == "" {
		return "", nil, os.ErrInvalid
	}
	volumeRoot := strings.TrimRight(volume, "\\") + "\\"
	remainder := strings.TrimLeft(cleaned[len(volume):], "\\")
	if remainder == "" {
		return volumeRoot, nil, nil
	}
	parts := strings.Split(remainder, "\\")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", nil, os.ErrInvalid
		}
	}
	return volumeRoot, parts, nil
}

func openWindowsStateManifestHandle(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, os.ErrInvalid
	}
	return file, nil
}

func scanWindowsStateManifestDirectory(dir *os.File, dirFinalPath, relativeRoot, rootFinalPath string, files *[]StateManifestFile) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return stateManifestError("source root scan failed")
	}
	for _, entry := range entries {
		if entry == nil {
			return stateManifestError("source root scan failed")
		}
		entryInfo, err := entry.Info()
		if err != nil || entryInfo == nil {
			return stateManifestError("source root scan failed")
		}
		if unsafeStateManifestMode(entry.Type()) || unsafeStateManifestMode(entryInfo.Mode()) {
			return stateManifestError("unsafe source entries are not allowed")
		}

		relative, err := filepath.Rel(rootFinalPath, filepath.Join(dirFinalPath, entry.Name()))
		if err != nil {
			return stateManifestError("source path resolution failed")
		}
		if relativeRoot != "" {
			relative = filepath.Join(relativeRoot, entry.Name())
		}
		normalized := filepath.ToSlash(relative)
		if !validStateManifestPath(normalized) {
			return stateManifestError("invalid file path")
		}
		if isReservedStateManifestName(normalized) {
			continue
		}

		childPath := filepath.Join(dirFinalPath, entry.Name())
		child, err := openWindowsStateManifestHandle(childPath)
		if err != nil {
			return stateManifestError("source root scan failed")
		}
		childInfo, statErr := child.Stat()
		if statErr != nil || childInfo == nil || unsafeStateManifestMode(childInfo.Mode()) || !os.SameFile(entryInfo, childInfo) {
			_ = child.Close()
			return stateManifestError("source entries changed during scan")
		}
		childFinalPath, finalPathErr := windowsStateManifestFinalPath(child)
		if finalPathErr != nil || !windowsStateManifestPathWithinRoot(rootFinalPath, childFinalPath) {
			_ = child.Close()
			return stateManifestError("source entry escaped root")
		}

		var scanErr error
		switch {
		case childInfo.IsDir():
			scanErr = scanWindowsStateManifestDirectory(child, childFinalPath, normalized, rootFinalPath, files)
		case childInfo.Mode().IsRegular():
			var file StateManifestFile
			file.Path = normalized
			file.Size, file.SHA256, scanErr = hashWindowsStateManifestFile(child, childInfo)
			if scanErr == nil {
				*files = append(*files, file)
			}
		default:
			scanErr = stateManifestError("non-regular entries are not allowed")
		}
		closeErr := child.Close()
		if scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return stateManifestError("source root scan failed")
		}
	}
	return nil
}

func hashWindowsStateManifestFile(file *os.File, expected os.FileInfo) (int64, string, error) {
	if file == nil || expected == nil || unsafeStateManifestMode(expected.Mode()) || !expected.Mode().IsRegular() {
		return 0, "", stateManifestError("file changed during scan")
	}
	opened, err := file.Stat()
	if err != nil || opened == nil || unsafeStateManifestMode(opened.Mode()) || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return 0, "", stateManifestError("file changed during scan")
	}
	digest := sha256.New()
	size, copyErr := io.Copy(digest, file)
	if copyErr != nil || size < 0 {
		return 0, "", stateManifestError("file read failed")
	}
	after, statErr := file.Stat()
	if statErr != nil || after == nil || unsafeStateManifestMode(after.Mode()) || !after.Mode().IsRegular() || !os.SameFile(opened, after) || size != after.Size() {
		return 0, "", stateManifestError("file changed during scan")
	}
	return size, hex.EncodeToString(digest.Sum(nil)), nil
}

func windowsStateManifestFinalPath(file *os.File) (string, error) {
	if file == nil {
		return "", os.ErrInvalid
	}
	size := uint32(windowsStateManifestFinalPathInitialSize)
	for {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		if length >= windowsStateManifestFinalPathMaxSize {
			return "", os.ErrInvalid
		}
		size = length + 1
	}
}

func windowsStateManifestPathWithinRoot(rootFinalPath, candidateFinalPath string) bool {
	rootFinalPath = strings.TrimRight(strings.ReplaceAll(rootFinalPath, "/", "\\"), "\\")
	candidateFinalPath = strings.TrimRight(strings.ReplaceAll(candidateFinalPath, "/", "\\"), "\\")
	if rootFinalPath == "" || candidateFinalPath == "" {
		return false
	}
	rootLower := strings.ToLower(rootFinalPath)
	candidateLower := strings.ToLower(candidateFinalPath)
	return candidateLower == rootLower || strings.HasPrefix(candidateLower, rootLower+"\\")
}
