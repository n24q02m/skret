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

func scanStateManifestRoot(root string) ([]StateManifestFile, error) {
	expectedRoot, err := os.Lstat(root)
	if err != nil || expectedRoot == nil || unsafeStateManifestMode(expectedRoot.Mode()) || !expectedRoot.IsDir() {
		return nil, stateManifestError("invalid source root")
	}

	rootFile, err := openWindowsStateManifestHandle(root)
	if err != nil {
		return nil, stateManifestError("source root scan failed")
	}
	defer rootFile.Close()

	openedRoot, err := rootFile.Stat()
	if err != nil || openedRoot == nil || unsafeStateManifestMode(openedRoot.Mode()) || !openedRoot.IsDir() || !os.SameFile(expectedRoot, openedRoot) {
		return nil, stateManifestError("source root changed during scan")
	}
	rootFinalPath, err := windowsStateManifestFinalPath(rootFile)
	if err != nil || rootFinalPath == "" {
		return nil, stateManifestError("source root scan failed")
	}

	files := make([]StateManifestFile, 0)
	if err := scanWindowsStateManifestDirectory(rootFile, rootFinalPath, "", rootFinalPath, &files); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, stateManifestError("source root is empty")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
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
